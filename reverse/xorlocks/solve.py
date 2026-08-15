#!/usr/bin/env python3
from hashlib import sha256
from pathlib import Path


BINARY = Path(__file__).with_name("artifacts") / "xorlock"
EXPECTED_SHA256 = "99bd67f0782e97865279e4bd2f8613199db96f958f98e2e8c4bbbc493747e48b"

PASSWORD_TABLE_OFFSET = 0x150
PASSWORD_LENGTH = 20
FLAG_TABLE_OFFSET = 0x170
FLAG_LENGTH = 31


def recover_password(binary):
    table = binary[PASSWORD_TABLE_OFFSET:PASSWORD_TABLE_OFFSET + PASSWORD_LENGTH]
    if len(table) != PASSWORD_LENGTH:
        raise ValueError("The password table is truncated")

    return bytes(
        (((encoded - 3 * index) & 0xFF) ^ 0x5A)
        for index, encoded in enumerate(table)
    )


def recover_flag(binary):
    table = binary[FLAG_TABLE_OFFSET:FLAG_TABLE_OFFSET + FLAG_LENGTH]
    if len(table) != FLAG_LENGTH:
        raise ValueError("The flag table is truncated")

    result = bytearray()
    for index, encoded in enumerate(table):
        cl = (0x40 + 0x1A * (index // 2)) & 0xFF
        key = (cl - 0x0D) & 0xFF if index % 2 == 0 else cl
        result.append(encoded ^ key)
    return bytes(result)


def verify_password(binary, password):
    table = binary[PASSWORD_TABLE_OFFSET:PASSWORD_TABLE_OFFSET + PASSWORD_LENGTH]
    if len(password) != PASSWORD_LENGTH:
        return False

    return all(
        (((value ^ 0x5A) + 3 * index) & 0xFF) == table[index]
        for index, value in enumerate(password)
    )


def main():
    binary = BINARY.read_bytes()
    digest = sha256(binary).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"Unexpected artifact SHA-256: {digest}")

    password = recover_password(binary)
    flag = recover_flag(binary)

    print(f"password: {password.decode('ascii')}")
    print(f"password verified: {verify_password(binary, password)}")
    print(f"flag: {flag.decode('ascii')}")


if __name__ == "__main__":
    main()
