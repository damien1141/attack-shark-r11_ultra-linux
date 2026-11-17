#include "attackshark_device.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QThread>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/hidraw.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace attackshark {

namespace {

constexpr int kInterReportDelayMs = 150;
constexpr int kHotplugCheckIntervalMs = 2000;

const uint8_t kPollingRatePayloads[4][2] = {
    {0x08, 0xF7}, // 125 Hz
    {0x04, 0xFB}, // 250 Hz
    {0x02, 0xFD}, // 500 Hz
    {0x01, 0xFE}, // 1000 Hz
};

// --- Attack Shark R11 Ultra vendor protocol ---
// Recovered from HIDUsb.dll (UsbServer_* packet builders and the checksum
// routine at 0x180010890) and the interface-1 report descriptor:
//   Output report ID 0x08, 16 data bytes; Input report ID 0x08, 16 data bytes.
// Wire layout (17 bytes including the report ID):
//   [0]      report ID (0x08)
//   [1]      sub-command
//   [2]      reserved (0x00)
//   [3..4]   big-endian config address
//   [5]      payload length (0x00 for queries; the 0x80 bit is rejected)
//   [6..15]  payload
//   [16]     0x55 - sum(bytes[0..15])
// Responses echo [1..4], put status in [2] (0 = ok), the returned length in [5]
// and the data in [6..].
constexpr uint8_t kR11ReportId = 0x08;

uint8_t r11Checksum(const uint8_t *data, size_t length)
{
    uint8_t sum = 0;
    for (size_t i = 0; i < length; ++i)
        sum = static_cast<uint8_t>(sum + data[i]);
    return static_cast<uint8_t>(0x55 - sum);
}

void buildR11Report(uint8_t out[17], uint8_t subcommand, uint8_t address,
                    uint8_t flags, const uint8_t *payload, size_t payloadLength)
{
    std::memset(out, 0, 17);
    out[0] = kR11ReportId;
    out[1] = subcommand;
    out[2] = 0x00;
    out[3] = 0x00; // address high byte (all known settings live below 0x100)
    out[4] = address;
    out[5] = flags;
    const size_t copyLen = std::min(payloadLength, size_t(10));
    if (payload && copyLen > 0)
        std::memcpy(out + 6, payload, copyLen);
    out[16] = r11Checksum(out, 16);
}

uint8_t r11PollingRateCode(PollingRate rate)
{
    // usersetting/Config.ini "ReportRates": 125=8, 250=4, 500=2, 1000=1,
    // 2000=16, 4000=32, 8000=64.
    switch (rate) {
    case PollingRate::Hz125:  return 8;
    case PollingRate::Hz250:  return 4;
    case PollingRate::Hz500:  return 2;
    case PollingRate::Hz1000: return 1;
    case PollingRate::Hz2000: return 16;
    case PollingRate::Hz4000: return 32;
    case PollingRate::Hz8000: return 64;
    }
    return 1;
}

// DPI stage encoding. The vendor app decodes a stored stage as
//   dpi = (code + 1) * 50;  *2 if (flag & 0x11);  *100 if (flag & 0x22)
// (see 0x140011290 in ATTACK  SHARK MOUSE HUB.exe). The inverse picks the
// smallest multiplier that keeps the code within one byte.
void r11EncodeDpi(int dpi, uint8_t &code, uint8_t &flag)
{
    const int clamped = std::clamp(dpi, kR11MinDpi, kR11MaxDpi);
    int mult = 50;
    if (clamped <= 12800) {
        mult = 50;
        flag = 0x00;
    } else if (clamped <= 25600) {
        mult = 100;
        flag = 0x11;
    } else {
        mult = 200;
        flag = 0x33;
    }
    const int value = (clamped + mult / 2) / mult - 1;
    code = static_cast<uint8_t>(std::clamp(value, 0, 255));
}

QString readSysfsLine(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return {};
    return QString::fromUtf8(f.readLine()).trimmed();
}

struct SysfsHidrawEntry {
    QString hidrawNode; // e.g. /dev/hidraw7
    QString usbDirPath; // canonical USB device sysfs dir (e.g. /sys/devices/.../usb7/7-1)
    QString productName;
    uint16_t vid = 0;
    uint16_t pid = 0;
    int interfaceNumber = -1;
};

QList<SysfsHidrawEntry> scanSysfsHidraw()
{
    QList<SysfsHidrawEntry> entries;
    QDir hidrawClassDir(QStringLiteral("/sys/class/hidraw"));
    const QStringList names = hidrawClassDir.entryList(
        QStringList{QStringLiteral("hidraw*")},
        QDir::Dirs | QDir::NoDotAndDotDot,
        QDir::Name);

    for (const QString &name : names) {
        const QString devSysPath = hidrawClassDir.absoluteFilePath(name + QStringLiteral("/device"));
        const QFileInfo devInfo(devSysPath);
        if (!devInfo.exists())
            continue;

        const QString canonicalDev = devInfo.canonicalFilePath();
        const QString ifaceDir = QFileInfo(canonicalDev + QStringLiteral("/..")).canonicalFilePath();
        const QString usbDir   = QFileInfo(canonicalDev + QStringLiteral("/../..")).canonicalFilePath();

        bool okVid = false, okPid = false, okIface = false;
        const uint16_t vid = static_cast<uint16_t>(readSysfsLine(usbDir + QStringLiteral("/idVendor")).toUInt(&okVid, 16));
        const uint16_t pid = static_cast<uint16_t>(readSysfsLine(usbDir + QStringLiteral("/idProduct")).toUInt(&okPid, 16));
        const int ifaceNum = static_cast<int>(readSysfsLine(ifaceDir + QStringLiteral("/bInterfaceNumber")).toInt(&okIface, 16));

        if (!okVid || !okPid)
            continue;

        QString prod = readSysfsLine(usbDir + QStringLiteral("/product"));
        const QString mfg = readSysfsLine(usbDir + QStringLiteral("/manufacturer"));
        if (prod.isEmpty())
            prod = QStringLiteral("USB HID Device");
        if (!mfg.isEmpty() && !prod.startsWith(mfg, Qt::CaseInsensitive))
            prod = mfg + QStringLiteral(" ") + prod;

        SysfsHidrawEntry entry;
        entry.hidrawNode      = QStringLiteral("/dev/") + name;
        entry.usbDirPath      = usbDir;
        entry.productName     = prod;
        entry.vid             = vid;
        entry.pid             = pid;
        entry.interfaceNumber = okIface ? ifaceNum : -1;
        entries.append(entry);
    }

    return entries;
}

} // namespace

AttackSharkDevice::AttackSharkDevice(QObject *parent)
    : QObject(parent)
{
    m_hotplugTimer = new QTimer(this);
    m_hotplugTimer->setInterval(kHotplugCheckIntervalMs);
    connect(m_hotplugTimer, &QTimer::timeout,
            this, &AttackSharkDevice::checkHotplugTransition);
    m_hotplugTimer->start();
}

AttackSharkDevice::~AttackSharkDevice()
{
    closeDevice();
}

QList<DeviceInfo> AttackSharkDevice::enumerateDevices(bool allHidDevices)
{
    QList<DeviceInfo> result;
    const QList<SysfsHidrawEntry> sysEntries = scanSysfsHidraw();

    for (const SysfsHidrawEntry &e : sysEntries) {
        const bool isX11 = isAttackSharkDevice(e.vid, e.pid);
        const bool isR11 = isR11UltraDevice(e.vid, e.pid);
        const bool isSupported = isX11 || isR11;

        if (isSupported) {
            const int configInterface = isR11 ? kR11ConfigInterface : kConfigInterface;
            if (e.interfaceNumber != configInterface)
                continue;
        } else if (!allHidDevices) {
            continue;
        }

        DeviceInfo info;
        info.path       = e.hidrawNode;
        info.hidrawPath = e.hidrawNode;
        info.vid        = e.vid;
        info.pid        = e.pid;
        info.model      = isR11 ? DeviceModel::R11Ultra : DeviceModel::X11;
        info.isWired    = isR11 ? isR11WiredPid(e.pid)
                                : (e.vid == kVendorId && isWiredPid(e.pid));

        if (isR11) {
            info.name = info.isWired
                ? QStringLiteral("Attack Shark R11 Ultra (Wired / Charging)")
                : QStringLiteral("Attack Shark R11 Ultra (2.4G Wireless)");
        } else if (isX11) {
            info.name = info.isWired
                ? QStringLiteral("Attack Shark X11 (Wired / Charging)")
                : QStringLiteral("Attack Shark X11 (2.4G Wireless)");
        } else {
            info.name = e.productName;
        }

        result.append(info);
    }

    return result;
}

QString AttackSharkDevice::findDefaultDevicePath()
{
    const QList<DeviceInfo> devices = enumerateDevices(false);
    // Prioritize Wired mode if plugged in (since the mouse turns off its 2.4G radio when charging via USB)
    for (const DeviceInfo &d : devices) {
        if (d.isWired)
            return d.hidrawPath;
    }
    for (const DeviceInfo &d : devices) {
        if (!d.isWired)
            return d.hidrawPath;
    }
    return {};
}

QString AttackSharkDevice::resolveConfigHidrawPath(const QString &devicePath, bool *isWiredOut)
{
    const QList<SysfsHidrawEntry> sysEntries = scanSysfsHidraw();

    // Track the currently active wired/wireless config node for each supported model.
    // When the USB charging cable is plugged in, both mice switch to Wired USB mode and
    // stop talking to the 2.4G wireless dongle, even if the dongle stays plugged in.
    QString x11Wired, x11Wireless, r11Wired, r11Wireless;
    for (const SysfsHidrawEntry &e : sysEntries) {
        if (isAttackSharkDevice(e.vid, e.pid) && e.interfaceNumber == kConfigInterface) {
            if (isWiredPid(e.pid)) {
                if (x11Wired.isEmpty())
                    x11Wired = e.hidrawNode;
            } else if (e.pid == kProductIdWireless && x11Wireless.isEmpty()) {
                x11Wireless = e.hidrawNode;
            }
        } else if (isR11UltraDevice(e.vid, e.pid) && e.interfaceNumber == kR11ConfigInterface) {
            if (isR11WiredPid(e.pid)) {
                if (r11Wired.isEmpty())
                    r11Wired = e.hidrawNode;
            } else if (r11Wireless.isEmpty()) {
                r11Wireless = e.hidrawNode;
            }
        }
    }

    // 1. If devicePath is a specific /dev/hidraw* node, inspect what device it belongs to
    if (devicePath.startsWith(QStringLiteral("/dev/hidraw"))) {
        for (const SysfsHidrawEntry &e : sysEntries) {
            if (e.hidrawNode != devicePath)
                continue;

            const bool isR11 = isR11UltraDevice(e.vid, e.pid);
            const bool isX11 = isAttackSharkDevice(e.vid, e.pid);
            const int configInterface = isR11 ? kR11ConfigInterface : kConfigInterface;
            const QString &activeWired = isR11 ? r11Wired : x11Wired;

            // If the user selected a wireless node but the mouse is plugged in via USB
            // cable, prioritize the active wired node for the same model.
            if ((isR11 || isX11) && !activeWired.isEmpty()) {
                if (isWiredOut)
                    *isWiredOut = true;
                return activeWired;
            }

            if (e.interfaceNumber == configInterface) {
                if (isWiredOut)
                    *isWiredOut = isR11 ? isR11WiredPid(e.pid)
                                        : (e.vid == kVendorId && isWiredPid(e.pid));
                return e.hidrawNode;
            }

            // Find the config interface on the same USB device
            for (const SysfsHidrawEntry &sibling : sysEntries) {
                if (sibling.usbDirPath == e.usbDirPath && sibling.interfaceNumber == configInterface) {
                    if (isWiredOut)
                        *isWiredOut = isR11 ? isR11WiredPid(sibling.pid)
                                            : (sibling.vid == kVendorId && isWiredPid(sibling.pid));
                    return sibling.hidrawNode;
                }
            }
            break;
        }
    }

    // 2. Fallback / auto-priority: R11 Ultra first, then X11; wired before wireless.
    if (!r11Wired.isEmpty()) {
        if (isWiredOut)
            *isWiredOut = true;
        return r11Wired;
    }
    if (!x11Wired.isEmpty()) {
        if (isWiredOut)
            *isWiredOut = true;
        return x11Wired;
    }
    if (!r11Wireless.isEmpty()) {
        if (isWiredOut)
            *isWiredOut = false;
        return r11Wireless;
    }
    if (!x11Wireless.isEmpty()) {
        if (isWiredOut)
            *isWiredOut = false;
        return x11Wireless;
    }

    return {};
}

bool AttackSharkDevice::openDevice(const QString &devicePath)
{
    closeDevice();
    m_lastError.clear();

    bool wired = false;
    const QString hidraw = resolveConfigHidrawPath(devicePath, &wired);
    if (hidraw.isEmpty()) {
        m_lastError = QStringLiteral("No supported Attack Shark interface found.");
        return false;
    }

    int fd = ::open(hidraw.toUtf8().constData(), O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        const int savedErrno = errno;
        fd = ::open(hidraw.toUtf8().constData(), O_RDONLY | O_NONBLOCK);
        if (fd < 0) {
            m_lastError = QStringLiteral("Cannot open %1: %2. Install packaging/70-attackshark.rules "
                                         "into /etc/udev/rules.d, then replug the device.")
                              .arg(hidraw, QString::fromLocal8Bit(std::strerror(savedErrno)));
            return false;
        }
    }

    m_devicePath = devicePath;
    m_hidrawPath = hidraw;
    m_fd         = fd;
    m_isWired    = wired;

    m_model = DeviceModel::X11;
    for (const SysfsHidrawEntry &e : scanSysfsHidraw()) {
        if (e.hidrawNode == hidraw) {
            m_model = detectDeviceModel(e.vid, e.pid);
            break;
        }
    }

    m_readNotifier = new QSocketNotifier(m_fd, QSocketNotifier::Read, this);
    connect(m_readNotifier, &QSocketNotifier::activated,
            this, &AttackSharkDevice::onHidrawReadyRead);

    if (m_isWired) {
        // In Wired USB mode, the mouse is charging via cable
        m_lastBattery.isCharging = true;
        emit batteryStatusChanged(m_lastBattery);
    } else {
        m_lastBattery.isCharging = false;
        emit batteryStatusChanged(m_lastBattery);
    }

    emit connectionModeChanged(m_isWired, m_hidrawPath);

    // Drain any buffered reports immediately
    onHidrawReadyRead();
    return true;
}

void AttackSharkDevice::closeDevice()
{
    if (m_readNotifier) {
        m_readNotifier->setEnabled(false);
        m_readNotifier->deleteLater();
        m_readNotifier = nullptr;
    }
    if (m_fd >= 0) {
        ::close(m_fd);
        m_fd = -1;
    }
    m_hidrawPath.clear();
    m_isWired = false;
}

void AttackSharkDevice::checkHotplugTransition()
{
    bool preferredWired = false;
    const QString preferredHidraw = resolveConfigHidrawPath(m_devicePath, &preferredWired);

    if (preferredHidraw.isEmpty()) {
        if (m_fd >= 0) {
            closeDevice();
            emit deviceDisconnected();
        }
        return;
    }

    // Automatically switch between Wired Charging mode (1d57:fa61) and 2.4G Wireless mode (1d57:fa60)
    // when the user plugs in or unplugs the USB cable
    if (m_fd < 0 || preferredHidraw != m_hidrawPath || preferredWired != m_isWired) {
        const QString savedPath = m_devicePath;
        openDevice(savedPath);
    }
}

void AttackSharkDevice::onHidrawReadyRead()
{
    if (m_fd < 0)
        return;

    uint8_t buf[64];
    while (true) {
        const ssize_t n = ::read(m_fd, buf, sizeof(buf));
        if (n > 0) {
            parseIncomingReport(buf, n);
        } else {
            if (n < 0 && (errno == ENODEV || errno == EIO || errno == EBADF)) {
                closeDevice();
                emit deviceDisconnected();
            }
            break;
        }
    }
}

void AttackSharkDevice::parseIncomingReport(const uint8_t *buf, ssize_t length)
{
    if (m_model == DeviceModel::R11Ultra) {
        // R11 Ultra telemetry arrives as 17-byte reports (report ID 0x08 + 16 bytes).
        // Keep the last checksum-valid report so pollBatteryR11() can consume it even
        // when the QSocketNotifier already drained the fd.
        if (length >= 17 && buf[0] == kR11ReportId && r11Checksum(buf, 16) == buf[16]) {
            std::memcpy(m_r11LastReport.data(), buf, 17);
            m_r11HasReport = true;
            if (qEnvironmentVariableIsSet("ATTACKSHARK_DEBUG")) {
                qInfo().noquote() << "RX R11 report"
                                  << QByteArray(reinterpret_cast<const char *>(buf), 17).toHex(' ');
            }
        }
        return;
    }

    // Attack Shark X11 wireless packet handling on Interface 2:
    // 1. DPI Stage Switch Notification from physical mouse button:
    // Signature: [0x03, 0x10, 0x10, <stage 1-based>, 0x00]
    if (length >= 4 && buf[0] == 0x03 && buf[1] == 0x10 && buf[2] == 0x10) {
        int stage1Based = static_cast<int>(buf[3]);
        if (stage1Based == 0 && length >= 5) {
            stage1Based = static_cast<int>(buf[4]);
        }
        if (stage1Based >= 1 && stage1Based <= kDpiStagesCount) {
            emit activeDpiStageChanged(stage1Based - 1);
        }
    }

    // 1b. Command acknowledgement from the firmware:
    // Signature: [0x03, 0x10, 0x50, <status 0=ok>, <reportId>]
    if (length >= 5 && buf[0] == 0x03 && buf[1] == 0x10 && buf[2] == 0x50) {
        emit commandAcknowledged(static_cast<int>(buf[4]), buf[3] == 0x00);
    }

    // 2. Battery & Charging status telemetry report:
    // - Beken 10-step firmware:  [0x03, 0x10, 0x40, <state>, <level 1..10 (0x01..0x0a = 10%..100%)>]
    // - Standard 100-step fw:    [0x03, 0x55, 0x40, <state>, <percentage 0..100 (0x00..0x64)>]
    if (length >= 5 && buf[0] == 0x03 && buf[2] == 0x40 && (buf[1] == 0x10 || buf[1] == 0x55)) {
        const uint8_t state = buf[3];
        const int raw = static_cast<int>(buf[4]);
        int pct = raw;
        if (buf[1] == 0x10 && raw <= 10) {
            pct = raw * 10;
        }
        pct = std::clamp(pct, 0, 100);

        // State: 0x02 = Charging, 0x03 = Fully charged, 0x01 = Discharging
        const bool charging = m_isWired || (state == 0x02);

        if (m_lastBattery.percentage != pct || m_lastBattery.isCharging != charging) {
            m_lastBattery.percentage = pct;
            m_lastBattery.isCharging = charging;
            emit batteryStatusChanged(m_lastBattery);
        }
    }
}

BatteryStatus AttackSharkDevice::pollBatteryOnce(int timeoutMs)
{
    // Check if wired/wireless mode changed first
    checkHotplugTransition();

    if (m_fd < 0)
        return m_lastBattery;

    if (m_model == DeviceModel::R11Ultra)
        return pollBatteryR11(timeoutMs);

    onHidrawReadyRead();
    if (m_isWired) {
        m_lastBattery.isCharging = true;
        return m_lastBattery;
    }

    if (m_lastBattery.percentage >= 0)
        return m_lastBattery;

    struct pollfd pfd {};
    pfd.fd     = m_fd;
    pfd.events = POLLIN;

    const int rc = ::poll(&pfd, 1, timeoutMs);
    if (rc > 0 && (pfd.revents & POLLIN)) {
        onHidrawReadyRead();
    }

    return m_lastBattery;
}

bool AttackSharkDevice::sendFeatureReport(const uint8_t *data, size_t length, QString *errorMessage)
{
    // Ensure we are targeting the active interface (e.g. Wired if plugged in via USB)
    checkHotplugTransition();

    int targetFd = m_fd;
    bool tempOpened = false;

    if (targetFd < 0) {
        const QString hidraw = m_hidrawPath.isEmpty()
            ? resolveConfigHidrawPath(m_devicePath)
            : m_hidrawPath;
        if (hidraw.isEmpty()) {
            if (errorMessage)
                *errorMessage = QStringLiteral("Attack Shark X11 configuration interface not found.");
            return false;
        }
        targetFd = ::open(hidraw.toUtf8().constData(), O_RDWR | O_NONBLOCK);
        if (targetFd < 0) {
            if (errorMessage)
                *errorMessage = QStringLiteral("Cannot open %1: %2").arg(hidraw, QString::fromLocal8Bit(std::strerror(errno)));
            return false;
        }
        tempOpened = true;
    }

    std::array<uint8_t, 64> buffer {};
    const size_t copyLen = std::min(length, buffer.size());
    std::memcpy(buffer.data(), data, copyLen);

    const int rc = ::ioctl(targetFd, HIDIOCSFEATURE(copyLen), buffer.data());
    const int savedErrno = errno;

    if (qEnvironmentVariableIsSet("ATTACKSHARK_DEBUG")) {
        qInfo().noquote() << "TX report" << QByteArray(reinterpret_cast<const char *>(data), static_cast<int>(copyLen)).toHex(' ')
                          << "rc=" << rc;
    }

    if (tempOpened)
        ::close(targetFd);

    if (rc < 0) {
        if (errorMessage)
            *errorMessage = QStringLiteral("HIDIOCSFEATURE failed: %1").arg(QString::fromLocal8Bit(std::strerror(savedErrno)));
        return false;
    }

    return true;
}

void AttackSharkDevice::buildPollingReport(PollingRate rate, uint8_t out[9])
{
    const int idx = std::clamp(static_cast<int>(rate), 0, 3);
    const uint8_t report[9] = {
        0x06, 0x09, 0x01,
        kPollingRatePayloads[idx][0],
        kPollingRatePayloads[idx][1],
        0x00, 0x00, 0x00, 0x00
    };
    std::memcpy(out, report, sizeof(report));
}

void AttackSharkDevice::buildDefaultButtonMappingReport(uint8_t out[59])
{
    constexpr int kSlotsStart = 3;
    constexpr int kSlotsEnd = 55;
    constexpr int kSlotSize = 3;
    constexpr uint8_t kDisabledButton = 0x01;

    std::memset(out, 0, 59);
    out[0] = 0x08;
    out[1] = 0x3B;
    out[2] = 0x01;
    for (int i = kSlotsStart; i < kSlotsEnd; i += kSlotSize)
        out[i] = kDisabledButton;

    out[3]  = 0x02; // Left click
    out[6]  = 0x03; // Right click
    out[9]  = 0x04; // Middle click
    out[18] = 0x0D; // DPI cycle
    out[21] = 0x06; // Forward
    out[24] = 0x05; // Backward
    out[51] = 0x09; // Scroll up
    out[54] = 0x0A; // Scroll down

    int sum = 0;
    for (int i = 2; i < 58; ++i)
        sum += out[i];
    out[58] = static_cast<uint8_t>((sum - 1) & 0xFF);
}

void AttackSharkDevice::buildColorAndPowerReport(const MouseConfig &config, uint8_t out[15])
{
    std::memset(out, 0, 15);
    out[0] = 0x05;
    out[1] = 0x0F;
    out[2] = 0x01;

    // Byte 3: Mode opcode (0x00=Off, 0x10=Static, 0x20=Breathing, 0x30=Neon, 0x40=Color Breathing, 0x50=Static DPI, 0x60=Breathing DPI)
    const int mode = std::clamp(static_cast<int>(config.colorMode), 0, 6);
    out[3] = static_cast<uint8_t>(mode << 4);

    const int sleepTime     = std::clamp(config.sleepTimeMin, 1, 30);
    const int deepSleepTime = std::clamp(config.deepSleepTimeMin, 1, 60);
    const int keyRespTime   = std::clamp(config.keyResponseTimeMs, 4, 50);

    const int speed      = std::clamp(static_cast<int>(config.ledSpeed), 1, 8);
    const int brightness = std::clamp(static_cast<int>(config.ledBrightness), 1, 8);

    const int bucket = (deepSleepTime - 1) / 16;
    out[4] = static_cast<uint8_t>((bucket << 4) | (speed & 0x0F));
    out[5] = static_cast<uint8_t>(((0x08 + (deepSleepTime * 0x10)) & 0xF0) | (brightness & 0x0F));

    // Bytes 6..8: RGB color for Static / Breathing
    if (config.colorMode == ColorMode::Disabled) {
        out[6] = 0x00;
        out[7] = 0x00;
        out[8] = 0x00;
    } else {
        out[6] = config.ledRed;
        out[7] = config.ledGreen;
        out[8] = config.ledBlue;
    }

    out[9]  = static_cast<uint8_t>(sleepTime * 2);
    out[10] = static_cast<uint8_t>(((keyRespTime - 4) / 2) + 2);

    // Bytes 11..12: 16-bit Big-Endian sum of bytes 3..10 inclusive
    uint16_t checksum = 0;
    for (int i = 3; i <= 10; ++i) {
        checksum = static_cast<uint16_t>(checksum + out[i]);
    }
    out[11] = static_cast<uint8_t>((checksum >> 8) & 0xFF);
    out[12] = static_cast<uint8_t>(checksum & 0xFF);
    out[13] = 0x00;
    out[14] = 0x00;
}

void AttackSharkDevice::buildDpiAndSensorReport(const MouseConfig &config, uint8_t out[56])
{
    const uint8_t activeStage1Based = static_cast<uint8_t>(
        std::clamp(config.activeDpiStage + 1, 1, kDpiStagesCount));

    // Compute Stage Mask (> 12000 DPI) for stages 1..5 + stage 6 (default 22000 DPI = bit 5)
    uint8_t stageMask = 0x20; // bit 5 set for stage 6 (22000 DPI)
    for (int i = 0; i < kDpiStagesCount; ++i) {
        if (config.dpiStages[i].needsStageMask()) {
            stageMask |= static_cast<uint8_t>(1u << i);
        }
    }

    uint8_t report[56] = {
        0x04, 0x38, 0x01,                                                     // Bytes 0..2: Header
        config.angleSnap ? uint8_t(0x01) : uint8_t(0x00),                     // Byte 3: Angle Snap
        config.rippleControl ? uint8_t(0x01) : uint8_t(0x00),                 // Byte 4: Ripple Control
        0x1f,                                                                 // Byte 5: Enable bitmask for 5 stages (0b00011111)
        stageMask,                                                            // Byte 6: Stage Mask A (DPI > 12000)
        stageMask,                                                            // Byte 7: Stage Mask B (duplicate)
        config.dpiStages[0].toHardwareIndex(),                                // Byte 8:  Stage 1 encoded DPI
        config.dpiStages[1].toHardwareIndex(),                                // Byte 9:  Stage 2 encoded DPI
        config.dpiStages[2].toHardwareIndex(),                                // Byte 10: Stage 3 encoded DPI
        config.dpiStages[3].toHardwareIndex(),                                // Byte 11: Stage 4 encoded DPI
        config.dpiStages[4].toHardwareIndex(),                                // Byte 12: Stage 5 encoded DPI
        0x81,                                                                 // Byte 13: Stage 6 encoded DPI (22000 default)
        0x00, 0x00,                                                           // Bytes 14..15: Fixed
        config.dpiStages[0].needsHighStageFlag() ? uint8_t(0x01) : uint8_t(0x00), // Byte 16: High Flag 1
        config.dpiStages[1].needsHighStageFlag() ? uint8_t(0x01) : uint8_t(0x00), // Byte 17: High Flag 2
        config.dpiStages[2].needsHighStageFlag() ? uint8_t(0x01) : uint8_t(0x00), // Byte 18: High Flag 3
        config.dpiStages[3].needsHighStageFlag() ? uint8_t(0x01) : uint8_t(0x00), // Byte 19: High Flag 4
        config.dpiStages[4].needsHighStageFlag() ? uint8_t(0x01) : uint8_t(0x00), // Byte 20: High Flag 5
        0x01,                                                                 // Byte 21: High Flag 6 (22000 DPI)
        0x00, 0x00,                                                           // Bytes 22..23: Fixed
        activeStage1Based,                                                    // Byte 24: Active DPI Stage (1..5)
        // Bytes 25..48: Stage indicator colors (8 stages * 3 bytes RGB)
        0xFF, 0x00, 0x00, // Stage 1: Red
        0x00, 0xFF, 0x00, // Stage 2: Green
        0x00, 0x00, 0xFF, // Stage 3: Blue
        0xFF, 0xFF, 0x00, // Stage 4: Yellow
        0x00, 0xFF, 0xFF, // Stage 5: Cyan
        0xFF, 0x00, 0xFF, // Stage 6: Purple (default)
        0xFF, 0x80, 0x00, // Stage 7: Orange (default)
        0xFF, 0xFF, 0xFF, // Stage 8: White (default)
        0x02,             // Byte 49: LOD = 2mm
        0x00, 0x00,       // Bytes 50..51: Checksum placeholder
        0x00, 0x00, 0x00, 0x00 // Bytes 52..55: Padding
    };

    // Calculate 16-bit Big-Endian checksum over bytes 3..49 inclusive
    uint16_t checksum = 0;
    for (int i = 3; i <= 49; ++i) {
        checksum = static_cast<uint16_t>(checksum + report[i]);
    }
    report[50] = static_cast<uint8_t>((checksum >> 8) & 0xFF);
    report[51] = static_cast<uint8_t>(checksum & 0xFF);

    std::memcpy(out, report, sizeof(report));
}

bool AttackSharkDevice::applyConfiguration(const MouseConfig &config, QString *errorMessage)
{
    if (!config.isValid()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Invalid mouse configuration parameters.");
        return false;
    }

    if (m_model == DeviceModel::R11Ultra)
        return applyConfigurationR11(config, errorMessage);

    // 1. Send DPI & Sensor Report first (Report 0x04)
    uint8_t dpiReport[56];
    buildDpiAndSensorReport(config, dpiReport);
    if (!sendFeatureReport(dpiReport, sizeof(dpiReport), errorMessage))
        return false;

    QThread::msleep(kInterReportDelayMs);

    // 2. Send LED, Sleep & Debounce Report second (Report 0x05)
    // Sending this after Report 0x04 ensures the mouse applies the user's chosen lighting mode
    // rather than staying stuck on the DPI stage indicator.
    uint8_t colorReport[15];
    buildColorAndPowerReport(config, colorReport);
    if (!sendFeatureReport(colorReport, sizeof(colorReport), errorMessage))
        return false;

    QThread::msleep(kInterReportDelayMs);

    // 3. Send Polling Rate Report third (Report 0x06)
    uint8_t pollingReport[9];
    buildPollingReport(config.pollingRate, pollingReport);
    if (!sendFeatureReport(pollingReport, sizeof(pollingReport), errorMessage))
        return false;

    QThread::msleep(kInterReportDelayMs);

    // 4. Restore the default button mapping (Report 0x08); the firmware can lose it after the reports above
    uint8_t buttonReport[59];
    buildDefaultButtonMappingReport(buttonReport);
    if (!sendFeatureReport(buttonReport, sizeof(buttonReport), errorMessage))
        return false;

    // Drain ACK reports
    onHidrawReadyRead();
    return true;
}

bool AttackSharkDevice::sendColorReport(const MouseConfig &config, QString *errorMessage)
{
    uint8_t colorReport[15];
    buildColorAndPowerReport(config, colorReport);
    const bool ok = sendFeatureReport(colorReport, sizeof(colorReport), errorMessage);
    onHidrawReadyRead();
    return ok;
}

// ---------------------------------------------------------------------------
// Attack Shark R11 Ultra
// ---------------------------------------------------------------------------

bool AttackSharkDevice::sendR11Report(const uint8_t report[17], QString *errorMessage)
{
    checkHotplugTransition();

    int targetFd = m_fd;
    bool tempOpened = false;

    if (targetFd < 0) {
        const QString hidraw = m_hidrawPath.isEmpty()
            ? resolveConfigHidrawPath(m_devicePath)
            : m_hidrawPath;
        if (hidraw.isEmpty()) {
            if (errorMessage)
                *errorMessage = QStringLiteral("Attack Shark R11 Ultra configuration interface not found.");
            return false;
        }
        targetFd = ::open(hidraw.toUtf8().constData(), O_RDWR | O_NONBLOCK);
        if (targetFd < 0) {
            if (errorMessage)
                *errorMessage = QStringLiteral("Cannot open %1: %2")
                                    .arg(hidraw, QString::fromLocal8Bit(std::strerror(errno)));
            return false;
        }
        tempOpened = true;
    }

    const ssize_t written = ::write(targetFd, report, 17);
    const int savedErrno = errno;

    if (qEnvironmentVariableIsSet("ATTACKSHARK_DEBUG")) {
        qInfo().noquote() << "TX R11 report"
                          << QByteArray(reinterpret_cast<const char *>(report), 17).toHex(' ')
                          << "rc=" << written;
    }

    if (tempOpened)
        ::close(targetFd);

    if (written != 17) {
        if (errorMessage) {
            if (written < 0)
                *errorMessage = QStringLiteral("HID output report failed: %1")
                                    .arg(QString::fromLocal8Bit(std::strerror(savedErrno)));
            else
                *errorMessage = QStringLiteral("HID output report truncated (%1/17 bytes)").arg(written);
        }
        return false;
    }

    return true;
}

bool AttackSharkDevice::r11WriteByte(uint8_t address, uint8_t value, QString *errorMessage)
{
    // Sub-command 0x07 writes a value + its 0x55-complement at a config address.
    const uint8_t payload[2] = { value, static_cast<uint8_t>(0x55 - value) };
    uint8_t report[17];
    buildR11Report(report, 0x07, address, 2, payload, 2);
    return sendR11Report(report, errorMessage);
}

bool AttackSharkDevice::r11WriteDpiStage(int stageIndex, int dpi, QString *errorMessage)
{
    if (stageIndex < 0 || stageIndex >= kR11DpiStages)
        return false;

    uint8_t code = 0;
    uint8_t flag = 0;
    r11EncodeDpi(dpi, code, flag);
    const uint8_t payload[4] = {
        code, code, flag,
        static_cast<uint8_t>(0x55 - (code + code + flag))
    };

    uint8_t report[17];
    buildR11Report(report, 0x07, static_cast<uint8_t>(0x0C + 4 * stageIndex),
                   4, payload, 4);
    return sendR11Report(report, errorMessage);
}

bool AttackSharkDevice::r11ReadResponse(uint8_t out[17], int timeoutMs)
{
    // Prefer a report already captured by the socket notifier.
    if (m_r11HasReport) {
        std::memcpy(out, m_r11LastReport.data(), 17);
        m_r11HasReport = false;
        return true;
    }

    if (m_fd < 0)
        return false;

    struct pollfd pfd {};
    pfd.fd     = m_fd;
    pfd.events = POLLIN;

    const int rc = ::poll(&pfd, 1, timeoutMs);
    if (rc <= 0 || !(pfd.revents & POLLIN))
        return false;

    uint8_t buf[64];
    const ssize_t n = ::read(m_fd, buf, sizeof(buf));
    if (n < 17)
        return false;
    if (buf[0] != kR11ReportId)
        return false;
    if (r11Checksum(buf, 16) != buf[16])
        return false;

    std::memcpy(out, buf, 17);
    return true;
}

bool AttackSharkDevice::applyConfigurationR11(const MouseConfig &config, QString *errorMessage)
{
    // 1. Polling rate (config address 0x00)
    if (!r11WriteByte(0x00, r11PollingRateCode(config.pollingRate), errorMessage))
        return false;
    QThread::msleep(kInterReportDelayMs);

    // 2. DPI stages (config addresses 0x0C, 0x10, ... — 3-byte groups)
    for (int i = 0; i < kDpiStagesCount; ++i) {
        if (!r11WriteDpiStage(i, config.dpiStages[i].dpi, errorMessage))
            return false;
        QThread::msleep(kInterReportDelayMs);
    }

    // 3. Active DPI stage (config address 0x04)
    const uint8_t activeStage = static_cast<uint8_t>(
        std::clamp(config.activeDpiStage, 0, kDpiStagesCount - 1));
    if (!r11WriteByte(0x04, activeStage, errorMessage))
        return false;

    onHidrawReadyRead();
    return true;
}

BatteryStatus AttackSharkDevice::pollBatteryR11(int timeoutMs)
{
    if (m_isWired) {
        m_lastBattery.isCharging = true;
        return m_lastBattery;
    }

    m_r11HasReport = false;

    // Sub-command 0x04 = read battery level.
    uint8_t report[17];
    buildR11Report(report, 0x04, 0x00, 0, nullptr, 0);
    if (!sendR11Report(report, nullptr))
        return m_lastBattery;

    // Give the socket notifier a chance to capture the reply, then fall back to a
    // direct timed read.
    onHidrawReadyRead();

    uint8_t response[17];
    if (r11ReadResponse(response, timeoutMs) && response[1] == 0x04 && response[2] == 0x00) {
        // Verified on hardware: [6] = percentage, [7] = charging flag.
        const int pct = static_cast<int>(response[6]);
        const bool charging = response[7] != 0;
        if (pct >= 0 && pct <= 100 &&
            (m_lastBattery.percentage != pct || m_lastBattery.isCharging != charging)) {
            m_lastBattery.percentage = pct;
            m_lastBattery.isCharging = charging;
            emit batteryStatusChanged(m_lastBattery);
        }
    }

    return m_lastBattery;
}

} // namespace attackshark
