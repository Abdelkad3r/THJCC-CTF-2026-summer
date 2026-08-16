#!/usr/bin/env python3
"""Recover the BlackFrost configuration and flag from the PE and PCAP."""

from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path


CONFIG_RVA = 0x3000
CONFIG_CIPHERTEXT_LENGTH = 56
FLAG_RVA = 0x3080
FLAG_LENGTH = 34


def parse_pe_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    if data[:2] != b"MZ" or len(data) < 0x40:
        raise ValueError("expected a PE executable")

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("invalid PE signature")

    coff = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    machine, section_count = coff[0], coff[1]
    optional_size = coff[5]
    if machine != 0x8664:
        raise ValueError("expected an x86-64 PE")

    optional_offset = pe_offset + 24
    if struct.unpack_from("<H", data, optional_offset)[0] != 0x20B:
        raise ValueError("expected a PE32+ optional header")

    section_offset = optional_offset + optional_size
    sections: dict[str, tuple[int, int, int]] = {}
    for index in range(section_count):
        offset = section_offset + 40 * index
        if offset + 40 > len(data):
            raise ValueError("truncated PE section table")
        name = data[offset : offset + 8].split(b"\x00", 1)[0].decode("ascii")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        sections[name] = (virtual_address, raw_offset, min(virtual_size, raw_size))
    return sections


def read_rva(
    data: bytes,
    sections: dict[str, tuple[int, int, int]],
    address: int,
    length: int,
) -> bytes:
    for virtual_address, raw_offset, size in sections.values():
        relative = address - virtual_address
        if 0 <= relative and relative + length <= size:
            return data[raw_offset + relative : raw_offset + relative + length]
    raise ValueError(f"RVA 0x{address:x} is outside the file-backed sections")


def extract_tcp_payloads(data: bytes) -> list[bytes]:
    if len(data) < 24:
        raise ValueError("truncated PCAP header")

    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        byte_order = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        byte_order = ">"
    else:
        raise ValueError("unsupported PCAP byte order")

    link_type = struct.unpack_from(byte_order + "I", data, 20)[0]
    if link_type != 1:
        raise ValueError("expected Ethernet packets")

    payloads: list[bytes] = []
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError("truncated PCAP record header")
        captured_length = struct.unpack_from(byte_order + "I", data, offset + 8)[0]
        offset += 16
        frame = data[offset : offset + captured_length]
        if len(frame) != captured_length:
            raise ValueError("truncated PCAP packet")
        offset += captured_length

        if len(frame) < 14 or struct.unpack_from(">H", frame, 12)[0] != 0x0800:
            continue
        ip_offset = 14
        ip_length = (frame[ip_offset] & 0x0F) * 4
        if ip_length < 20 or len(frame) < ip_offset + ip_length:
            continue
        if frame[ip_offset + 9] != 6:
            continue

        tcp_offset = ip_offset + ip_length
        if len(frame) < tcp_offset + 20:
            continue
        tcp_length = (frame[tcp_offset + 12] >> 4) * 4
        if tcp_length < 20 or len(frame) < tcp_offset + tcp_length:
            continue

        total_length = struct.unpack_from(">H", frame, ip_offset + 2)[0]
        payload_end = min(len(frame), ip_offset + total_length)
        payload = frame[tcp_offset + tcp_length : payload_end]
        if payload:
            payloads.append(payload)

    return payloads


def parse_capture(data: bytes) -> tuple[int, bytes]:
    payloads = extract_tcp_payloads(data)
    hello_pattern = re.compile(rb"^BFHELLO ([0-9a-fA-F]{8})$")
    handshake_key: int | None = None
    ciphertext: bytes | None = None

    for payload in payloads:
        message = payload.strip()
        hello = hello_pattern.fullmatch(message)
        if hello:
            handshake_key = int(hello.group(1), 16)
        elif message.startswith(b"BF2:"):
            ciphertext = bytes.fromhex(message[4:].decode("ascii"))

    if handshake_key is None or ciphertext is None:
        raise ValueError("the PCAP does not contain a complete BlackFrost exchange")
    return handshake_key, ciphertext


def stream_crypt(data: bytes, key: int) -> bytes:
    return bytes(
        value
        ^ ((key >> (8 * (index % 4))) & 0xFF)
        ^ ((0x5A + 0x11 * index) & 0xFF)
        for index, value in enumerate(data)
    )


def recover_embedded_key(ciphertext: bytes, known_prefix: bytes) -> int:
    if len(ciphertext) < 4 or len(known_prefix) < 4:
        raise ValueError("four known plaintext bytes are required")

    key = 0
    for index in range(4):
        key_byte = (
            ciphertext[index]
            ^ known_prefix[index]
            ^ ((0x5A + 0x11 * index) & 0xFF)
        )
        key |= key_byte << (8 * index)
    return key


def decrypt_embedded_config(ciphertext: bytes, key: int) -> bytes:
    plaintext = bytearray(stream_crypt(ciphertext, key))
    plaintext.extend(
        (
            (key & 0xFF) ^ 0x03,
            ((key >> 8) & 0xFF) ^ 0xAB,
            ((key >> 16) & 0xFF) ^ 0x5C,
        )
    )
    return bytes(plaintext)


def decrypt_flag(ciphertext: bytes) -> str:
    plaintext = bytearray()
    rolling = 0x26

    for index in range(0, len(ciphertext), 2):
        plaintext.append(ciphertext[index] ^ ((rolling - 0x0D) & 0xFF))
        if index + 1 < len(ciphertext):
            plaintext.append(ciphertext[index + 1] ^ rolling)
        rolling = (rolling + 0x1A) & 0xFF

    return plaintext.decode("ascii")


def main() -> int:
    challenge_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binary",
        type=Path,
        default=challenge_dir / "artifacts" / "BlackFrost.exe",
    )
    parser.add_argument(
        "--pcap",
        type=Path,
        default=challenge_dir / "artifacts" / "traffic.pcap",
    )
    args = parser.parse_args()

    pe_data = args.binary.read_bytes()
    pcap_data = args.pcap.read_bytes()
    sections = parse_pe_sections(pe_data)

    handshake_key, captured_ciphertext = parse_capture(pcap_data)
    captured_config = stream_crypt(captured_ciphertext, handshake_key)
    if not captured_config.startswith(b"campaign="):
        raise ValueError("captured configuration failed its known marker")

    embedded_ciphertext = read_rva(
        pe_data, sections, CONFIG_RVA, CONFIG_CIPHERTEXT_LENGTH
    )
    embedded_key = recover_embedded_key(embedded_ciphertext, captured_config)
    embedded_config = decrypt_embedded_config(embedded_ciphertext, embedded_key)
    if embedded_config != captured_config:
        raise ValueError("the reconstructed configurations do not agree")

    encrypted_flag = read_rva(pe_data, sections, FLAG_RVA, FLAG_LENGTH)
    flag = decrypt_flag(encrypted_flag)
    if not (flag.startswith("THJCC{") and flag.endswith("}")):
        raise ValueError("decrypted output is not a THJCC flag")

    print(f"handshake key: 0x{handshake_key:08x}")
    print(f"captured config: {captured_config.decode('ascii')}")
    print(f"embedded config key: 0x{embedded_key:08x}")
    print(f"embedded config: {embedded_config.decode('ascii')}")
    print(f"key mismatch: {handshake_key != embedded_key}")
    print(f"flag: {flag}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
