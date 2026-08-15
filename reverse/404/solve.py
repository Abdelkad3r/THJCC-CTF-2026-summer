#!/usr/bin/env python3
"""Rebuild, invert, and emulate the 404 challenge's bytecode verifier."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path


PROGRAM_CHUNKS = [
    0x2001C0,
    0x2001B0,
    0x200160,
    0x200150,
    0x200120,
    0x200130,
    0x200180,
    0x2001E0,
    0x200190,
    0x2001F0,
    0x200210,
    0x200220,
    0x200140,
    0x200200,
    0x200230,
    0x200170,
    0x2001A0,
    0x2001D0,
]

FLAG_TABLE_ADDRESS = 0x200280
FLAG_LENGTH = 32
INPUT_LENGTH = 16


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
    machine = header[1]
    section_offset = header[5]
    section_entry_size = header[10]
    section_count = header[11]
    string_table_index = header[12]

    if machine != 62:
        raise ValueError(f"expected x86-64 ELF machine 62, found {machine}")

    section_format = byte_order + "IIQQQQIIQQ"
    section_size = struct.calcsize(section_format)
    if section_entry_size < section_size:
        raise ValueError("ELF section headers are too small")

    headers = [
        struct.unpack_from(
            section_format, data, section_offset + index * section_entry_size
        )
        for index in range(section_count)
    ]
    if string_table_index >= len(headers):
        raise ValueError("invalid section-name string table index")

    string_header = headers[string_table_index]
    string_data = data[string_header[4] : string_header[4] + string_header[5]]

    sections: dict[str, tuple[int, int, int]] = {}
    for section in headers:
        name_offset = section[0]
        end = string_data.find(b"\x00", name_offset)
        if end == -1:
            raise ValueError("unterminated ELF section name")
        name = string_data[name_offset:end].decode("ascii")
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


def rebuild_program(data: bytes, rodata: tuple[int, int, int]) -> bytes:
    chunks = [read_virtual(data, rodata, address, 16) for address in PROGRAM_CHUNKS]
    program = b"".join(chunks) + b"\x07"
    if len(program) != 0x121:
        raise ValueError("unexpected reconstructed bytecode length")
    return program


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


def recover_input(program: bytes, verbose: bool = False) -> bytes:
    candidate: list[int | None] = [None] * INPUT_LENGTH

    for block_index in range(INPUT_LENGTH):
        base = block_index * 18
        instructions = [program[base + offset : base + offset + 3] for offset in range(0, 18, 3)]
        opcodes = [instruction[0] for instruction in instructions]
        if opcodes != [1, 2, 3, 4, 5, 6]:
            raise ValueError(f"unexpected opcode pattern in block {block_index}")

        load, xor, add, rotate, compare, _ = instructions
        register = load[1]
        if any(instruction[1] != register for instruction in instructions[:5]):
            raise ValueError(f"register mismatch in block {block_index}")

        input_index = load[2]
        xor_key = xor[2]
        add_key = add[2]
        rotate_count = rotate[2]
        target = compare[2]

        value = ror8(target, rotate_count)
        value = (value - add_key) & 0xFF
        value ^= xor_key

        if input_index >= INPUT_LENGTH or candidate[input_index] is not None:
            raise ValueError(f"invalid input index in block {block_index}")
        candidate[input_index] = value

        if verbose:
            print(
                f"i={input_index:02d} xor=0x{xor_key:02x} add=0x{add_key:02x} "
                f"rol={rotate_count} target=0x{target:02x} byte={value:#04x} "
                f"char={chr(value)!r}"
            )

    if any(value is None for value in candidate):
        raise ValueError("not every input byte was recovered")
    return bytes(value for value in candidate if value is not None)


def emulate(program: bytes, candidate: bytes) -> bool:
    registers = [0] * 8
    last_compare = False
    pc = 0

    for _ in range(0x1000):
        opcode = program[pc]

        if opcode == 1:  # LOAD register, input index
            register, index = program[pc + 1 : pc + 3]
            registers[register] = candidate[index]
            pc += 3
        elif opcode == 2:  # XOR register, immediate
            register, immediate = program[pc + 1 : pc + 3]
            registers[register] ^= immediate
            pc += 3
        elif opcode == 3:  # ADD register, immediate
            register, immediate = program[pc + 1 : pc + 3]
            registers[register] = (registers[register] + immediate) & 0xFF
            pc += 3
        elif opcode == 4:  # ROL register, immediate
            register, count = program[pc + 1 : pc + 3]
            registers[register] = rol8(registers[register], count)
            pc += 3
        elif opcode == 5:  # CMP register, immediate
            register, immediate = program[pc + 1 : pc + 3]
            last_compare = registers[register] == immediate
            registers[register] = int(last_compare)
            pc += 3
        elif opcode == 6:  # ASSERT previous comparison
            if not last_compare:
                return False
            pc += 3
        elif opcode == 7:  # SUCCESS
            return True
        elif opcode == 8:  # Relative bytecode jump
            pc = (pc + 1 + program[pc + 1]) % len(program)
        else:
            raise ValueError(f"invalid opcode {opcode} at bytecode offset 0x{pc:x}")

        if pc >= len(program):
            raise ValueError("bytecode program counter escaped the program")

    raise ValueError("VM instruction limit reached")


def decrypt_flag(data: bytes, rodata: tuple[int, int, int]) -> str:
    encrypted = read_virtual(data, rodata, FLAG_TABLE_ADDRESS, FLAG_LENGTH)
    plaintext = bytearray(FLAG_LENGTH)
    rolling = 0x35

    for offset in range(0, FLAG_LENGTH, 2):
        plaintext[offset] = encrypted[offset] ^ ((rolling - 0x0D) & 0xFF)
        plaintext[offset + 1] = encrypted[offset + 1] ^ rolling
        rolling = (rolling + 0x1A) & 0xFF

    return plaintext.decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "binary",
        nargs="?",
        type=Path,
        default=Path(__file__).parent / "artifacts" / "404",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    data = args.binary.read_bytes()
    sections = parse_sections(data)
    if ".rodata" not in sections:
        raise ValueError("ELF has no .rodata section")

    rodata = sections[".rodata"]
    program = rebuild_program(data, rodata)
    candidate = recover_input(program, args.verbose)
    accepted = emulate(program, candidate)
    if not accepted:
        raise ValueError("recovered input was rejected by the VM emulator")

    flag = decrypt_flag(data, rodata)
    print(f"bytecode length: {len(program)}")
    print(f"input: {candidate.decode('ascii')}")
    print(f"VM accepted: {accepted}")
    print(f"flag: {flag}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
