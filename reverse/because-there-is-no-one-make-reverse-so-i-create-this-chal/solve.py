#!/usr/bin/env python3
from pathlib import Path
import struct


BIN = Path(__file__).with_name("artifacts") / "chal"
PAYLOAD_OFFSET = 0xB98
PAYLOAD_SIZE = 0x2C4
DELTA = 0x9E3779B9
EXPECTED_PAYLOAD_FNV = 0x4B9FB9F7


def u32(value):
    return value & 0xFFFFFFFF


def xtea_encrypt(v0, v1, key):
    total = 0
    for _ in range(32):
        mix = u32(((v1 << 4) ^ (v1 >> 5)) + v1)
        v0 = u32(v0 + (mix ^ u32(total + key[total & 3])))
        total = u32(total + DELTA)
        mix = u32(((v0 << 4) ^ (v0 >> 5)) + v0)
        v1 = u32(v1 + (mix ^ u32(total + key[(total >> 11) & 3])))
    return v0, v1


def decrypt_payload(binary):
    key_bytes = bytes(a ^ b for a, b in zip(binary[0xE5C:0xE6C], binary[0xE6C:0xE7C]))
    key = struct.unpack("<4I", key_bytes)
    ciphertext = binary[PAYLOAD_OFFSET:PAYLOAD_OFFSET + PAYLOAD_SIZE]
    payload = bytearray(PAYLOAD_SIZE)

    for offset in range(0, PAYLOAD_SIZE, 8):
        v0, v1 = xtea_encrypt(u32(0xAFD9E340 + offset // 8), 0x1E403058, key)
        stream = struct.pack("<2I", v0, v1)
        for index in range(min(8, PAYLOAD_SIZE - offset)):
            payload[offset + index] = ciphertext[offset + index] ^ stream[index]

    return key, bytes(payload)


def fnv1a32(data):
    value = 0x811C9DC5
    for byte in data:
        value = u32((value ^ byte) * 0x01000193)
    return value


OPS = {
    0x15: "xor",
    0x18: "add",
    0x5A: "halt",
    0x5B: "skip",
    0x74: "rol",
    0x86: "load",
    0x8F: "check",
    0x97: "index",
    0xCD: "length",
    0xE5: "sub",
}


def disassemble(payload):
    pc = 0
    instructions = []
    while pc < len(payload):
        opcode = payload[pc]
        name = OPS.get(opcode, f"invalid_{opcode:02x}")
        if opcode in (0x5A, 0x86):
            instructions.append((pc, name, None))
            pc += 1
            if opcode == 0x5A:
                break
            continue
        if pc + 1 >= len(payload):
            instructions.append((pc, "truncated", None))
            break
        operand = payload[pc + 1]
        instructions.append((pc, name, operand))
        pc += operand + 2 if opcode == 0x5B else 2
    return instructions


def rol8(value, amount):
    value &= 0xFF
    return ((value << amount) | (value >> (8 - amount))) & 0xFF


def run_vm(payload, candidate):
    acc = 0
    failed = 0
    input_index = 0
    pc = 0
    budget = 0x589
    while pc < len(payload) and budget:
        budget -= 1
        opcode = payload[pc]
        pc += 1
        if opcode == 0x5A:
            return failed == 0
        if opcode == 0x86:
            acc = candidate[input_index] if input_index < len(candidate) else 0
            continue
        if pc >= len(payload):
            return False
        operand = payload[pc]
        pc += 1
        if opcode == 0x15:
            acc ^= operand
        elif opcode == 0x18:
            acc += operand
        elif opcode == 0x5B:
            pc += operand
        elif opcode == 0x74:
            if not 1 <= operand <= 7:
                return False
            acc = rol8(acc, operand)
        elif opcode == 0x8F:
            failed |= (acc & 0xFF) ^ operand
        elif opcode == 0x97:
            input_index = operand
        elif opcode == 0xCD:
            failed |= len(candidate) ^ operand
        elif opcode == 0xE5:
            acc -= operand
        else:
            return False
    return False


def recover_flag(payload, instructions):
    expected_length = next(arg for _, op, arg in instructions if op == "length")
    flag = bytearray(b"?" * expected_length)

    # Each input byte is selected with INDEX, loaded, transformed, then checked.
    # Brute forcing one byte at a time keeps the solver independent of the exact
    # arithmetic sequence used for each position.
    blocks = []
    current = []
    for insn in instructions:
        if insn[1] == "index":
            if current:
                blocks.append(current)
            current = [insn]
        elif current:
            current.append(insn)
    if current:
        blocks.append(current)

    for block in blocks:
        index = block[0][2]
        if index >= expected_length or not any(op == "check" for _, op, _ in block):
            continue
        for candidate in range(256):
            acc = 0
            matched = False
            for _, op, arg in block[1:]:
                if op == "load":
                    acc = candidate
                elif op == "xor":
                    acc ^= arg
                elif op == "add":
                    acc += arg
                elif op == "sub":
                    acc -= arg
                elif op == "rol":
                    acc = rol8(acc, arg)
                elif op == "check":
                    matched = (acc & 0xFF) == arg
                    break
            if matched:
                flag[index] = candidate
                break
        else:
            raise RuntimeError(f"No byte satisfies position {index}")
    return bytes(flag)


def main():
    binary = BIN.read_bytes()
    key, payload = decrypt_payload(binary)
    payload_hash = fnv1a32(payload)
    if payload_hash != EXPECTED_PAYLOAD_FNV:
        raise RuntimeError(f"Payload integrity check failed: {payload_hash:08x}")
    instructions = disassemble(payload)
    flag = recover_flag(payload, instructions)

    print("key:", " ".join(f"{word:08x}" for word in key))
    print(f"payload fnv1a32: {payload_hash:08x}")
    print("instructions:", len(instructions))
    print("flag:", flag.decode("ascii"))
    print("verified:", run_vm(payload, flag))


if __name__ == "__main__":
    main()
