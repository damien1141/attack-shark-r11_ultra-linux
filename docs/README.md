# Attack Shark X11 Linux Technical Documentation

This directory collects the technical documentation and the results of the reverse engineering activity conducted on the **Attack Shark X11** gaming mouse and its official Windows software, plus the **Attack Shark R11 Ultra** vendor protocol.

---

## Document Index

1. **[REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md)**:
   * Complete report on the analysis of the official binaries (`AttackShark.exe` and `hiddriver_3.dll`).
   * Detailed explanation with assembly code snippets (x86 disassembly) of the command dispatcher.
   * Diagnosis and resolution of historical bugs (ACK error `03 10 50 01 04`, PAW3311 sensor tables, 16-bit checksum).
   * Explanation of the battery ADC with discrete 10% intervals and hardware synchronization of the DPI button.
   * Management of the dual-mode architecture (wired `1d57:fa61` with radio module off vs wireless `1d57:fa60`).

2. **[PROTOCOL.md](PROTOCOL.md)**:
   * Quick reference for developers on the low-level USB HID protocol.
   * Exact layout of the 64-byte Feature Report packets (`Report 0x04` DPI, `Report 0x05` RGB, `Report 0x06` Polling Rate).
   * Format of the asynchronous Interrupt Input Reports (ACK, physical DPI button, battery telemetry).
   * Checksum algorithms and hardware conversion tables.

3. **[R11ULTRA.md](R11ULTRA.md)**:
   * Attack Shark R11 Ultra (`3554:fb43` / `fb44`) vendor protocol recovered from `HIDUsb.dll`.
   * 17-byte report framing, `0x55 - sum` checksum, reply layout and sub-command table.
   * Config address map, polling-rate codes and the verified DPI stage codec.
   * Current feature coverage and the remaining unknowns.

---

## Permissions

Both mice expose a vendor HID interface that is root-only by default. Install the
bundled udev rule and reload it before running the application:

```sh
sudo cp packaging/70-attackshark.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=hidraw --action=change
ls -l /dev/hidraw*      # expect crw-rw---- root plugdev
```

The rule grants access through `TAG+="uaccess"` (active logind seat) and
`GROUP="plugdev"` as a fallback. Replug the device if permissions do not change.
