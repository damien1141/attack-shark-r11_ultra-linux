#!/usr/bin/env python3
"""Read-only probe for the Attack Shark R11 Ultra vendor HID protocol.

This is a development aid used to validate the protocol implemented in
device/attackshark_device.cpp. It only sends read/query commands.

Requires access to /dev/hidraw* (run as root or install packaging/70-attackshark.rules).

Usage:
    sudo python3 tools/r11_probe.py
    sudo python3 tools/r11_probe.py --raw          # dump every response byte
"""

import argparse
import glob
import os
import select
import struct
import sys

REPORT_ID = 0x08
VENDOR_ID = "3554"
CONFIG_INTERFACE = 1


def checksum(data: bytes) -> int:
    return (0x55 - sum(data)) & 0xFF


def build_report(subcmd: int, address: int = 0, flags: int = 0x00,
                 payload: bytes = b"") -> bytes:
    buf = bytearray(17)
    buf[0] = REPORT_ID
    buf[1] = subcmd
    buf[2] = 0x00
    buf[3] = (address >> 8) & 0xFF
    buf[4] = address & 0xFF
    buf[5] = flags | len(payload)
    buf[6:6 + len(payload)] = payload[:10]
    buf[16] = checksum(buf[:16])
    return bytes(buf)


def find_config_node():
    for node in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        dev = os.path.join(node, "device")
        try:
            usb = os.path.realpath(os.path.join(dev, "..", ".."))
            iface = os.path.realpath(os.path.join(dev, ".."))
        except OSError:
            continue
        try:
            vid = open(os.path.join(usb, "idVendor")).read().strip().lower()
            pid = open(os.path.join(usb, "idProduct")).read().strip().lower()
            num = int(open(os.path.join(iface, "bInterfaceNumber")).read().strip(), 16)
        except OSError:
            continue
        if vid == VENDOR_ID and num == CONFIG_INTERFACE:
            return "/dev/" + os.path.basename(node), pid
    return None, None


def transact(fd, report, timeout=0.5):
    os.write(fd, report)
    r, _, _ = select.select([fd], [], [], timeout)
    if not r:
        return None
    data = os.read(fd, 64)
    return data


def describe(data):
    if data is None:
        return "no response"
    ok = len(data) >= 17 and checksum(data[:16]) == data[16]
    return f"len={len(data)} checksum={'ok' if ok else 'BAD'} data={data.hex(' ')}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", action="store_true", help="dump full responses")
    ap.add_argument("--node", help="explicit /dev/hidrawN")
    args = ap.parse_args()

    node, pid = (args.node, "?") if args.node else find_config_node()
    if not node:
        print("R11 Ultra config interface (VID 3554, interface 1) not found.")
        return 1

    print(f"device: {node}  pid={pid}")
    fd = os.open(node, os.O_RDWR | os.O_NONBLOCK)

    tests = [
        ("version        (0x12)", build_report(0x12)),
        ("battery        (0x04)", build_report(0x04)),
        ("polling rate   (0x08 addr 0x00)",
         build_report(0x08, address=0x00, payload=b"\x01")),
        ("active DPI     (0x08 addr 0x04)",
         build_report(0x08, address=0x04, payload=b"\x01")),
        ("DPI stage 0    (0x08 addr 0x0C)",
         build_report(0x08, address=0x0C, payload=b"\x01")),
        ("config blob    (0x0E)", build_report(0x0E)),
    ]

    for name, report in tests:
        try:
            resp = transact(fd, report)
        except OSError as exc:
            print(f"{name}: write failed: {exc}")
            continue
        print(f"{name}: {describe(resp)}")

    os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
