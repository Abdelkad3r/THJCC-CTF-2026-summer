#!/usr/bin/env python3
"""Decode USB HID keyboard reports from the Afterimage2 PCAP."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path


DLT_USB_LINUX_MMAPPED = 220
USBMON_HEADER_SIZE = 64
LEFT_SHIFT = 0x02
RIGHT_SHIFT = 0x20

PCAP_FORMATS = {
    b"\xd4\xc3\xb2\xa1": ("<", "microseconds"),
    b"\xa1\xb2\xc3\xd4": (">", "microseconds"),
    b"\x4d\x3c\xb2\xa1": ("<", "nanoseconds"),
    b"\xa1\xb2\x3c\x4d": (">", "nanoseconds"),
}

UNSHIFTED = {
    0x28: "\n",
    0x2C: " ",
    0x2D: "-",
    0x2E: "=",
    0x2F: "[",
    0x30: "]",
    0x31: "\\",
    0x33: ";",
    0x34: "'",
    0x35: "`",
    0x36: ",",
    0x37: ".",
    0x38: "/",
}

SHIFTED = {
    0x1E: "!",
    0x1F: "@",
    0x20: "#",
    0x21: "$",
    0x22: "%",
    0x23: "^",
    0x24: "&",
    0x25: "*",
    0x26: "(",
    0x27: ")",
    0x2D: "_",
    0x2E: "+",
    0x2F: "{",
    0x30: "}",
    0x31: "|",
    0x33: ":",
    0x34: '"',
    0x35: "~",
    0x36: "<",
    0x37: ">",
    0x38: "?",
}


def decode_usage(usage: int, shifted: bool) -> str:
    if 0x04 <= usage <= 0x1D:
        character = chr(ord("a") + usage - 0x04)
        return character.upper() if shifted else character

    if 0x1E <= usage <= 0x27:
        if shifted:
            return SHIFTED[usage]
        return "1234567890"[usage - 0x1E]

    table = SHIFTED if shifted else UNSHIFTED
    if usage not in table:
        raise ValueError(f"unsupported HID usage: 0x{usage:02x}")
    return table[usage]


def parse_pcap(source: Path):
    with source.open("rb") as handle:
        magic = handle.read(4)
        if magic not in PCAP_FORMATS:
            raise ValueError("unsupported PCAP byte order or timestamp format")
        byte_order, _ = PCAP_FORMATS[magic]

        global_fields = handle.read(20)
        if len(global_fields) != 20:
            raise ValueError("truncated PCAP global header")
        major, minor, _, _, _, link_type = struct.unpack(
            byte_order + "HHiIII", global_fields
        )
        if (major, minor) != (2, 4):
            raise ValueError(f"unsupported PCAP version: {major}.{minor}")
        if link_type != DLT_USB_LINUX_MMAPPED:
            raise ValueError(
                f"expected link type {DLT_USB_LINUX_MMAPPED}, found {link_type}"
            )

        packet_number = 0
        while True:
            record_header = handle.read(16)
            if not record_header:
                return
            if len(record_header) != 16:
                raise ValueError("truncated PCAP packet header")

            _, _, captured_length, _ = struct.unpack(
                byte_order + "IIII", record_header
            )
            packet = handle.read(captured_length)
            if len(packet) != captured_length:
                raise ValueError("truncated PCAP packet data")

            packet_number += 1
            yield packet_number, byte_order, packet


def usb_keyboard_reports(source: Path):
    for packet_number, byte_order, packet in parse_pcap(source):
        if len(packet) < USBMON_HEADER_SIZE:
            continue

        event_type = packet[8]
        transfer_type = packet[9]
        endpoint = packet[10]
        data_flag = packet[15]
        data_length = struct.unpack_from(byte_order + "I", packet, 36)[0]

        # Completed interrupt transfers from an IN endpoint with captured data.
        if event_type != ord("C") or transfer_type != 1 or not endpoint & 0x80:
            continue
        if data_flag != 0 or data_length < 8:
            continue

        report = packet[USBMON_HEADER_SIZE : USBMON_HEADER_SIZE + 8]
        if len(report) == 8:
            yield packet_number, report


def decode_capture(source: Path, verbose: bool = False) -> tuple[str, int, int]:
    output: list[str] = []
    previous_keys: set[int] = set()
    report_count = 0
    press_count = 0

    for packet_number, report in usb_keyboard_reports(source):
        report_count += 1
        modifier = report[0]
        shifted = bool(modifier & (LEFT_SHIFT | RIGHT_SHIFT))
        current_keys = {usage for usage in report[2:] if usage != 0}
        new_keys = [usage for usage in report[2:] if usage and usage not in previous_keys]

        for usage in new_keys:
            character = decode_usage(usage, shifted)
            output.append(character)
            press_count += 1
            if verbose:
                shown = "\\n" if character == "\n" else character
                print(
                    f"packet={packet_number:02d} modifier=0x{modifier:02x} "
                    f"usage=0x{usage:02x} key={shown}"
                )

        previous_keys = current_keys

    return "".join(output), report_count, press_count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "capture",
        nargs="?",
        type=Path,
        default=Path(__file__).parent / "artifacts" / "usb_capture.pcap",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    text, report_count, press_count = decode_capture(args.capture, args.verbose)
    print(f"USB reports: {report_count}")
    print(f"key presses: {press_count}")
    print(f"decoded: {text}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
