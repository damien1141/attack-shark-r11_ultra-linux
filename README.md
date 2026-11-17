<img height="400" alt="Screenshot demo of the user interface (UI)" src="./assets/ui_demo.png" />
    
## Attack Shark X11 for Linux

This software provides configuration support for the [Attack Shark X11](https://attackshark.com/products/attack-shark-x11-wireless-gaming-mouse-charging-dock), allowing users to adjust settings such as polling rate and lighting modes on Linux. It serves as an unofficial alternative to the Windows software and is actively being developed to expand feature support.

The **Attack Shark R11 Ultra** (`3554:fb43` wired, `3554:fb44` / `fb35` / `f517` wireless 8K) is also detected and supported for polling rate, DPI stages and battery reporting. See [docs/R11ULTRA.md](docs/R11ULTRA.md) for the recovered protocol and the current feature coverage.

## Disclaimer
This is an independent, community-driven project, not affiliated with or endorsed by Attack Shark, Guangzhou Shijunxingcheng Electronics Technology Co., Ltd., or PixArt Imaging Inc. No original driver source code is used; all communication protocols were independently reverse engineered. All trademarks and product names belong to their respective owners and are used for identification purposes only.

## Install

**Build it yourself (Recommended):**
```sh
git clone https://github.com/iago-fragnan/attack-shark-x11-linux.git
cd attack-shark-x11-linux
cmake -S . -B build
cmake --build build
./build/attackshark-x11
```

**Arch Linux (AUR):**
```sh
paru -S attackshark-x11 # you can also use yay
```

**Debian/Ubuntu:**
```sh
# Install dependencies
sudo dpkg -i attackshark-x11.deb # .deb file from releases
```

### Permissions (udev)

The mice expose a vendor HID interface that is root-only by default. Install the
bundled rule once, then reload it:

```sh
sudo cp packaging/70-attackshark.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=hidraw --action=change
ls -l /dev/hidraw*      # expect crw-rw---- root plugdev
```

The rule covers both the X11 (`1d57:*`) and the R11 Ultra (`3554:*`) and grants
access through `TAG+="uaccess"` with `GROUP="plugdev"` as a fallback. Replug the
device if permissions do not change.

### Diagnostics

```sh
./build/attackshark-x11 --list-devices   # show detected interfaces
./build/attackshark-x11 --apply          # apply the saved profile and exit
ATTACKSHARK_DEBUG=1 ./build/attackshark-x11   # log raw HID reports
```

## Documentation

Detailed technical documentation and reverse engineering reports are available in the [`docs/`](docs/) directory:
- [Reverse Engineering Report](docs/REVERSE_ENGINEERING.md): Comprehensive analysis of the official Windows driver (`AttackShark.exe` / `hiddriver_3.dll`), assembly disassembly snippets, hardware ACK packets, battery ADC steps, and physical button sync.
- [HID Protocol Reference](docs/PROTOCOL.md): Low-level 64-byte Feature Report layouts, 16-bit Big-Endian checksum calculations, PAW3311 step tables, and asynchronous Input Reports.
- [R11 Ultra Protocol](docs/R11ULTRA.md): Vendor `HIDUsb.dll` packet framing, config address map, polling-rate codes and the current implementation status.

## TODO

- [x] Polling Rate
- [x] DPI Configuration
- [x] LED Color Control
- [x] Apply User-Selected Settings
- [x] Battery Percentage Monitoring
- [x] Display Current Applied Settings on Startup
- [x] Battery Charging Indicator
- [x] Power Management & Standby Control
- [x] Key Response Time
- [x] Ripple Control
- [x] Angle Snapping
- [x] Automatic Device Selection
- [x] Custom window for settings
    - [ ] Macro Support
    - [x] Minimize to System Tray
    - [x] Profiles
        - [x] Apply
        - [x] Save
        - [x] Create
    - [x] Device selection
    - [x] Auto Startup
- [x] Low Battery Notification

### R11 Ultra (3554:fb43 / fb44)

- [x] Device detection and interface selection
- [x] Polling rate (125 Hz – 8000 Hz)
- [x] DPI stages (50 – 42000 DPI)
- [x] Battery percentage and charging state
- [ ] LED bar / DPI indicator control
- [ ] Advanced sensor toggles (angle, ripple, motion sync, long range)
- [ ] DPI dynamic-sensitivity curves
- [ ] Button remapping and macros


## Acknowledgements 

- Lightning and Settings icons provided by [Flaticon](https://www.flaticon.com/).
- Additional Reverse engineering references from [HarukaYamamoto0](https://github.com/HarukaYamamoto0/attack-shark-x11-driver/).
- Contributors.
- You, for reading this.
