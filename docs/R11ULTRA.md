# Attack Shark R11 Ultra — recovered vendor protocol

Source artifact: `ATTACK SHARK R11ULTRA SOFT.exe` (InstallShield single-EXE, 32 MB),
installed under Wine to obtain `HIDUsb.dll`, `ATTACK  SHARK MOUSE HUB.exe` and
`usersetting/Config.ini`.

Protocol facts below come from static analysis of `HIDUsb.dll`
(PE32+ x86-64, 251 exports), the vendor app's DPI codec, and live traffic on a
connected `3554:fb43` unit. Items marked *verified* were exercised on hardware.

## 1. Device identity

`usersetting/Config.ini` stores several fields base64-obfuscated. Decoded:

| Field | Value |
| --- | --- |
| `VID` | `0x3554` |
| `USB_PID` (wired) | `0xFB43`, `0xF516`, `0xF515` |
| `Wireless8_PID` | `0xFB44`, `0xFB35`, `0xF517` |
| `InterfaceId` | `1` |
| `Sensor` | `3950` (PixArt PAW3950) |
| `MM` | `NRF52840` |
| `DM` / `D8M` | `CX52660` |
| `D4M` | `CH32V305` |
| `DPIMaxGrade` | `6` |
| `DPIRange` | `50,26000,50,26100,42000,100,0x11` |
| `DPIGrade` | `1200,2400,3200,5600,8000,42000,6000,8000` |
| `BatteryParam` | 20-step ADC→voltage table |

The connected wired unit enumerates as `3554:fb43` with three HID interfaces:

| Interface | Contents |
| --- | --- |
| 0 | Boot keyboard (3 buttons + 8 keys) |
| 1 | **Vendor config channel** (Usage Page `0xFF00`) |
| 2 | Standard mouse (buttons, X/Y, wheel) |

Interface 1 report descriptor:

```
Usage Page 0xFF05 / 0xFF03 : Input  report ID 0x10, 7 bytes
                             Input  report ID 0x02, 7 bytes
Consumer page             : Input  report ID 0x05, 16-bit
Usage Page 0xFF02         : Input  report ID 0x08, 16 bytes
                             Output report ID 0x08, 16 bytes   <-- command channel
Usage Page 0xFF04         : Feature report ID 0x06, 7 bytes
```

## 2. Packet framing (verified)

Commands are written as **Output report ID `0x08`** (17 bytes on the wire,
including the report ID). Replies arrive as **Input report ID `0x08`**.

```
offset  meaning
[0]     0x08                      report ID
[1]     sub-command
[2]     0x00
[3..4]  big-endian config address
[5]     payload length            (0x00 for queries)
[6..15] payload (10 bytes)
[16]    checksum = 0x55 - sum(bytes[0..15])   (mod 256)
```

Important: the `0x80` bit in byte 5 is **rejected** by this device. The vendor
DLL sets it only in "mouse mode" for other products; the R11 Ultra answers with
status `0x01` (error) when it is set. Use `0x00`.

Reply layout:

```
[0]  0x08
[1]  sub-command echo
[2]  status (0x00 = ok, 0x01 = rejected)
[3..4] address echo
[5]  returned length
[6..] data
```

Examples captured on hardware:

```
version  : 08 12 00 00 00 02 03 01 ...   -> 2.3.1
battery  : 08 04 00 00 00 02 5f 01 ...   -> 95 %, charging flag 1
polling  : 08 08 00 00 00 01 40 ...      -> address 0x00 = 0x40 (8000 Hz)
```

### Config values carry their own checksum

Every stored setting is a `value` followed by `0x55 - value`:

* 1-byte setting → payload `[value, 0x55-value]`, length field `2`
* DPI stage → `[x_code, y_code, flags, 0x55-(sum)]`, length field `4`
* 4-byte setting (DPI curve) → `[b0,b1,b2,b3, 0x55-sum]`, length field `5`

## 3. Sub-commands

| Sub-command | Function |
| --- | --- |
| `0x01` | Read all flash data |
| `0x02` | Set PC driver status |
| `0x03` | Read CID/MID |
| `0x04` | Read battery level |
| `0x05` | Enter dongle pairing |
| `0x06` | Read dongle pairing status |
| `0x07` | **Write config value at address** |
| `0x08` | Read one byte at address (payload `[1]`) |
| `0x09` | Set clear setting |
| `0x0B` | Set VID/PID |
| `0x0D` | Enter USB update mode |
| `0x0E` | Read full config blob |
| `0x0F` | Set current config |
| `0x11` | Enter MTK mode |
| `0x12` | Read version |
| `0x14` | Set 4K dongle RGB |
| `0x15` | Get 4K dongle RGB |
| `0x16` | Set long-range mode |
| `0x17` | Get long-range mode |
| `0x18` | Set dongle RGB bar mode |
| `0x19` | Get dongle RGB bar mode |
| `0x1A` | Set dongle ID to mouse |
| `0x1F` | Set mouse serial number |
| `0x20` | Get mouse serial number |
| `0x2B` | Get RSSI |
| `0x2C` | Set dongle indicator LED |
| `0x2D` | Get dongle indicator LED |
| `0xB3` | Get slave version |

## 4. Config address map

| Address | Size | Meaning | Status |
| --- | --- | --- | --- |
| `0x00` | 1 | Polling rate | verified |
| `0x02` | 1 | DPI stage count (6) | verified read |
| `0x04` | 1 | Active DPI stage (0-based) | verified |
| `0x06` | 1 | Sensor mode (LP/HP/Corded) | inferred |
| `0x08` | 1 | LOD | inferred |
| `0x0A` | 1 | Sleep / performance timer | inferred |
| `0x0C + 4*i` | 4 | DPI stage *i*: `x_code, y_code, flags, checksum` | verified |
| `0x2C` | 4 | Extra stage slot | observed |
| `0x4C` | 1 | DPI indicator LED mode | observed |
| `0xA0` | 1 | LED bar mode | observed |
| `0xA7` | 1 | LED bar auxiliary value | observed |
| `0xA9..0xC1` | 1 each | Advanced toggles (angle, ripple, motion sync, long range…) | addresses confirmed, mapping inferred |
| `0xC3/0xC8/0xCD/0xD2` | 4 each | DPI dynamic-sensitivity curves | addresses confirmed |

Polling-rate codes (from `Language/en.json` `ReportRates`):

| Rate | Code |
| --- | --- |
| 125 Hz | `8` |
| 250 Hz | `4` |
| 500 Hz | `2` |
| 1000 Hz | `1` |
| 2000 Hz | `16` |
| 4000 Hz | `32` |
| 8000 Hz | `64` |

### DPI stage codec (verified)

The vendor app decodes a stored stage as (see `0x140011290` in
`ATTACK  SHARK MOUSE HUB.exe`):

```
dpi = (code + 1) * 50
if (flags & 0x22) dpi = (code + 1) * 100
if (flags & 0x11) dpi *= 2
```

The inverse used by this project picks the smallest multiplier that keeps the
code within one byte:

| DPI range | multiplier | flags | code |
| --- | --- | --- | --- |
| 50 – 12800 | ×50 | `0x00` | `dpi/50 - 1` |
| 12900 – 25600 | ×100 | `0x11` | `dpi/100 - 1` |
| 25700 – 42000 | ×200 | `0x33` | `dpi/200 - 1` |

Round-trip checks on hardware: `1600 → code 0x1F, flag 0x00`, `42000 → code
0xD1, flag 0x33`.

Because the code is one byte, values above 25600 use a ×200 multiplier and are
therefore quantised to 200-DPI steps (the UI still offers 100-DPI steps; the
codec rounds to the nearest representable value).

## 5. Implementation status

Implemented in `device/attackshark_device.cpp` (`DeviceModel::R11Ultra`) and
verified on a `3554:fb43` unit:

- Device detection for all wired/wireless PIDs and interface 1 selection.
- Polling rate write (address `0x00`), including 2000/4000/8000 Hz.
- DPI stage writes for five UI stages (addresses `0x0C…0x1C`) with the codec above.
- Active DPI stage write (address `0x04`).
- Battery query (`0x04`): percentage and charging flag.
- udev rule for non-root access (`packaging/70-attackshark.rules`).

Not yet implemented:

- LED bar / DPI indicator writes (addresses known, byte semantics inferred).
- Advanced sensor toggles (`0xA9…0xC1`).
- DPI dynamic-sensitivity curves.
- Button remapping and macros.

## 6. Verifying on hardware

`tools/r11_probe.py` sends read-only queries and prints checksum-validated
responses:

```sh
sudo python3 tools/r11_probe.py --raw
```

The application also exposes two diagnostics:

```sh
./build/attackshark-x11 --list-devices   # enumerate supported interfaces
./build/attackshark-x11 --apply          # apply the saved profile and exit
```
