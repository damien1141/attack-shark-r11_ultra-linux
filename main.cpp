#include "atsx11.h"
#include "core/profile_store.h"

#include <QApplication>
#include <QColor>
#include <QPalette>
#include <QSettings>
#include <QStyleFactory>
#include <QTextStream>

namespace {

void applyDarkTheme(QApplication &app)
{
    app.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));

    QPalette palette;
    const QColor window(30, 30, 30);
    const QColor text(242, 242, 242);
    const QColor base(37, 37, 37);
    const QColor button(45, 45, 45);
    const QColor disabled(127, 127, 127);
    const QColor highlight(42, 130, 218);

    palette.setColor(QPalette::Window, window);
    palette.setColor(QPalette::WindowText, text);
    palette.setColor(QPalette::Base, base);
    palette.setColor(QPalette::AlternateBase, button);
    palette.setColor(QPalette::ToolTipBase, text);
    palette.setColor(QPalette::ToolTipText, window);
    palette.setColor(QPalette::Text, text);
    palette.setColor(QPalette::Button, button);
    palette.setColor(QPalette::ButtonText, text);
    palette.setColor(QPalette::BrightText, Qt::red);
    palette.setColor(QPalette::Link, highlight);
    palette.setColor(QPalette::Highlight, highlight);
    palette.setColor(QPalette::HighlightedText, Qt::white);
    palette.setColor(QPalette::Disabled, QPalette::Text, disabled);
    palette.setColor(QPalette::Disabled, QPalette::ButtonText, disabled);

    app.setPalette(palette);
}

} // namespace

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    if (app.arguments().contains(QStringLiteral("--list-devices"))) {
        QTextStream out(stdout);
        const QList<attackshark::DeviceInfo> devices =
            attackshark::AttackSharkDevice::enumerateDevices(true);
        if (devices.isEmpty()) {
            out << "No supported devices found.\n";
            return 1;
        }
        for (const attackshark::DeviceInfo &d : devices) {
            out << d.hidrawPath << "  "
                << QStringLiteral("%1:%2").arg(d.vid, 4, 16, QLatin1Char('0'))
                                           .arg(d.pid, 4, 16, QLatin1Char('0'))
                << "  " << (d.isWired ? "wired" : "wireless")
                << "  " << d.name << "\n";
        }
        return 0;
    }

    if (app.arguments().contains(QStringLiteral("--apply"))) {
        QTextStream out(stdout);
        QSettings qSettings(QStringLiteral("AttackShark"), QStringLiteral("X11"));
        const attackshark::MouseConfig cfg = attackshark::profiles::readConfig(qSettings);

        attackshark::AttackSharkDevice device;
        const QString path = attackshark::AttackSharkDevice::findDefaultDevicePath();
        if (path.isEmpty()) {
            out << "No supported device found.\n";
            return 1;
        }
        if (!device.openDevice(path)) {
            out << "Open failed: " << device.lastError() << "\n";
            return 1;
        }
        QString err;
        const bool ok = device.applyConfiguration(cfg, &err);
        out << (ok ? "Applied" : "Apply failed: " + err) << "\n";
        return ok ? 0 : 1;
    }

    applyDarkTheme(app);
    app.setQuitOnLastWindowClosed(false);

    atsx11 window;
    const bool startMinimized = app.arguments().contains(QStringLiteral("--minimized"));
    if (!(startMinimized && window.isMinimizeToTrayEnabled()))
        window.show();
    return app.exec();
}
