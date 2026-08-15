#!/usr/bin/env python3
"""Recover the unique license and decrypt the License challenge flag."""

from __future__ import annotations

import argparse
import operator
import struct
import sys
from functools import reduce
from pathlib import Path


PERMUTATION_ADDRESS = 0x2001F0
FLAG_TABLE_ADDRESS = 0x200210
FLAG_LENGTH = 31

TARGET = bytes.fromhex("95540c2f5ac7a99fbca49ad296c32d883a578bad1d2f2b46")
ROUND_CONSTANTS = [0x13579BDF, 0x2468ACE0, 0x0BADF00D, 0x55AA55AA]
ROUND_OFFSETS = [0x00, 0x1D, 0x3A, 0x57]
HEX_ALPHABET = frozenset(b"0123456789ABCDEFabcdef")


def parse_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("expected a 64-bit ELF file")

    if data[5] == 1:
        byte_order = "<"
    elif data[5] == 2:
        byte_order = ">"
    else:
        raise ValueError("unsupported ELF byte order")

    header = struct.unpack_from(byte_order + "HHIQQQIHHHHHH", data, 16)
    if header[1] != 62:
        raise ValueError("expected an x86-64 ELF")

    section_offset = header[5]
    section_entry_size = header[10]
    section_count = header[11]
    string_table_index = header[12]
    section_format = byte_order + "IIQQQQIIQQ"
    native_size = struct.calcsize(section_format)
    if section_entry_size < native_size:
        raise ValueError("ELF section headers are too small")

    headers = [
        struct.unpack_from(
            section_format, data, section_offset + index * section_entry_size
        )
        for index in range(section_count)
    ]
    if string_table_index >= len(headers):
        raise ValueError("invalid section-name string table index")

    names_header = headers[string_table_index]
    names = data[names_header[4] : names_header[4] + names_header[5]]

    sections: dict[str, tuple[int, int, int]] = {}
    for section in headers:
        name_offset = section[0]
        name_end = names.find(b"\x00", name_offset)
        if name_end == -1:
            raise ValueError("unterminated ELF section name")
        name = names[name_offset:name_end].decode("ascii")
        sections[name] = (section[3], section[4], section[5])
    return sections


def read_virtual(
    data: bytes,
    section: tuple[int, int, int],
    address: int,
    length: int,
) -> bytes:
    virtual_address, file_offset, size = section
    relative = address - virtual_address
    if relative < 0 or relative + length > size:
        raise ValueError(f"address 0x{address:x} is outside .rodata")
    return data[file_offset + relative : file_offset + relative + length]


def rol8(value: int, count: int) -> int:
    count &= 7
    if count == 0:
        return value & 0xFF
    return ((value << count) | (value >> (8 - count))) & 0xFF


def ror8(value: int, count: int) -> int:
    count &= 7
    if count == 0:
        return value & 0xFF
    return ((value >> count) | (value << (8 - count))) & 0xFF


def round_key_byte(constant: int, index: int) -> int:
    return (constant >> (8 * (index % 4))) & 0xFF


def forward_round(state: bytes, round_index: int) -> bytes:
    constant = ROUND_CONSTANTS[round_index]
    offset = ROUND_OFFSETS[round_index]
    output = bytearray(24)

    for index in range(24):
        mixed = (
            state[index]
            ^ state[(index + 7) % 24]
            ^ ((index + offset) & 0xFF)
            ^ round_key_byte(constant, index)
        )
        output[index] = rol8(mixed, (index + round_index) % 7)
    return bytes(output)


def inverse_round(output: bytes, round_index: int) -> list[bytes]:
    constant = ROUND_CONSTANTS[round_index]
    offset = ROUND_OFFSETS[round_index]
    differences = []

    for index, value in enumerate(output):
        differences.append(
            ror8(value, (index + round_index) % 7)
            ^ ((index + offset) & 0xFF)
            ^ round_key_byte(constant, index)
        )

    # The equations are x[i] XOR x[i+7] = differences[i]. Because 7 and 24
    # are coprime, the indices form one cycle. Its XOR must close to zero.
    if reduce(operator.xor, differences, 0) != 0:
        return []

    candidates = []
    for seed in range(256):
        state: list[int | None] = [None] * 24
        state[0] = seed
        current = 0

        for _ in range(23):
            following = (current + 7) % 24
            assert state[current] is not None
            state[following] = state[current] ^ differences[current]
            current = following

        assert state[current] is not None
        if state[current] ^ differences[current] != seed:
            continue
        candidates.append(bytes(value for value in state if value is not None))
    return candidates


def reverse_rounds(target: bytes, verbose: bool = False) -> list[bytes]:
    states = [target]
    for round_index in range(3, -1, -1):
        states = [
            candidate
            for output in states
            for candidate in inverse_round(output, round_index)
        ]
        if verbose:
            print(f"after inverse round {round_index + 1}: {len(states)} states")
    return states


def forward_preprocess(raw: bytes, permutation: bytes) -> bytes:
    output = bytearray(24)
    for index in range(24):
        value = raw[permutation[index]] ^ ((0x31 + 17 * index) & 0xFF)
        output[index] = (rol8(value, index % 5) + 11 * index) & 0xFF
    return bytes(output)


def inverse_preprocess(state: bytes, permutation: bytes) -> bytes:
    raw = bytearray(24)
    for index in range(24):
        value = (state[index] - 11 * index) & 0xFF
        value = ror8(value, index % 5)
        raw[permutation[index]] = value ^ ((0x31 + 17 * index) & 0xFF)
    return bytes(raw)


def find_hex_licenses(states: list[bytes], permutation: bytes) -> list[bytes]:
    results = []
    for state in states:
        raw = inverse_preprocess(state, permutation)
        if all(value in HEX_ALPHABET for value in raw):
            results.append(raw)
    return results


def format_license(raw: bytes) -> str:
    return "-".join(raw[index : index + 4].decode("ascii") for index in range(0, 24, 4))


def verify(raw: bytes, permutation: bytes) -> bytes:
    state = forward_preprocess(raw, permutation)
    for round_index in range(4):
        state = forward_round(state, round_index)
    return state


def decrypt_flag(data: bytes, rodata: tuple[int, int, int]) -> str:
    encrypted = read_virtual(data, rodata, FLAG_TABLE_ADDRESS, FLAG_LENGTH)
    plaintext = bytearray()
    rolling = 0x7E

    for index in range(0, FLAG_LENGTH, 2):
        plaintext.append(encrypted[index] ^ ((rolling - 0x0D) & 0xFF))
        if index + 1 < FLAG_LENGTH:
            plaintext.append(encrypted[index + 1] ^ rolling)
        rolling = (rolling + 0x1A) & 0xFF
    return plaintext.decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "binary",
        nargs="?",
        type=Path,
        default=Path(__file__).parent / "artifacts" / "license_v2",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    data = args.binary.read_bytes()
    sections = parse_sections(data)
    if ".rodata" not in sections:
        raise ValueError("ELF has no .rodata section")
    rodata = sections[".rodata"]
    permutation = read_virtual(data, rodata, PERMUTATION_ADDRESS, 24)

    states = reverse_rounds(TARGET, args.verbose)
    licenses = find_hex_licenses(states, permutation)
    if len(licenses) != 1:
        raise ValueError(f"expected one hexadecimal license, found {len(licenses)}")

    raw = licenses[0]
    computed_target = verify(raw, permutation)
    if computed_target != TARGET:
        raise ValueError("recovered license failed forward verification")

    flag = decrypt_flag(data, rodata)
    print(f"pre-round candidates: {len(states)}")
    print(f"hex-valid licenses: {len(licenses)}")
    print(f"license: {format_license(raw)}")
    print(f"target verified: {computed_target == TARGET}")
    print(f"flag: {flag}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
