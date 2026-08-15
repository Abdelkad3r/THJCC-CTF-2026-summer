#!/usr/bin/env python3
import hashlib
import hmac
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"
RESIDENTS = ["yaniko", "yakuko", "hameko", "kaoruko", "aruko"]

MASK32 = 0xFFFFFFFF
PASSES = 3
K = (21, 20, 24, 108000)


def rotl32(value, amount):
    value &= MASK32
    return ((value << amount) | (value >> (32 - amount))) & MASK32


def yani40(message):
    k1, k2, k3, k4 = K
    a = (k1 ^ 0x9E3779B9) & MASK32
    b = (k2 + 0x85EBCA6B) & MASK32
    c = (k3 ^ 0xC2B2AE35) & MASK32
    d = (k4 + 0x27D4EB2F) & MASK32

    for pass_number in range(PASSES):
        for byte in message:
            a = ((a ^ byte) * 0x01000193) & MASK32
            b = rotl32(b + a, 13) ^ c
            c = (((c * 5 + 0xF00D) & MASK32) ^ b) & MASK32
            d = (rotl32(d ^ a, 7) + b) & MASK32
            a = (a + d) & MASK32
        a = (a ^ (pass_number * 0x7FEB352D)) & MASK32

    for _ in range(4):
        a = ((a ^ (b >> 15)) * 0x2545F491) & MASK32
        b = ((b ^ (c >> 13)) * 0x9E3779B1) & MASK32
        c = ((c ^ (d >> 11)) * 0x85EBCA77) & MASK32
        d = ((d ^ (a >> 16)) * 0xC2B2AE3D) & MASK32

    value = (((a ^ c) << 32) | (b ^ d)) & 0xFFFFFFFFFFFFFFFF
    return value.to_bytes(8, "big")[3:]


def compile_and_run_cracker():
    compiler = next(
        (shutil.which(name) for name in ("clang++", "g++", "c++") if shutil.which(name)),
        None,
    )
    if compiler is None:
        raise RuntimeError("A C++17 compiler is required")

    recovered = {}
    with tempfile.TemporaryDirectory(prefix="saizeriya-") as temporary:
        executable = Path(temporary) / "crack"
        subprocess.run(
            [
                compiler,
                "-O3",
                "-std=c++17",
                "-pthread",
                str(ROOT / "crack.cpp"),
                "-o",
                str(executable),
            ],
            check=True,
        )

        process = subprocess.Popen(
            [executable, ARTIFACTS / "nyan.tbl", ARTIFACTS / "shadow.txt"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        for line in process.stdout:
            print(line, end="", flush=True)
            match = re.match(r"^(\w+):([yaniko]{14}) ", line)
            if match:
                recovered[match.group(1)] = match.group(2)
        if process.wait() != 0:
            raise RuntimeError("The rainbow-table cracker failed")

    missing = [resident for resident in RESIDENTS if resident not in recovered]
    if missing:
        raise RuntimeError(f"Missing resident preimages: {missing}")
    return recovered


def load_shadows():
    shadows = {}
    for line in (ARTIFACTS / "shadow.txt").read_text().splitlines():
        resident, digest = line.split(":", 1)
        shadows[resident] = bytes.fromhex(digest)
    return shadows


def keystream(key, length):
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hashlib.sha256(
                key + b"YANI-CTR" + counter.to_bytes(4, "big")
            ).digest()
        )
        counter += 1
    return bytes(output[:length])


def main():
    recovered = compile_and_run_cracker()
    shadows = load_shadows()

    for resident, password in recovered.items():
        if yani40(password.encode()) != shadows[resident]:
            raise RuntimeError(f"Hash verification failed for {resident}")

    ordered = [recovered[resident] for resident in RESIDENTS]
    key = hashlib.sha256("|".join(ordered).encode()).digest()

    sealed = (ARTIFACTS / "flag.enc").read_bytes()
    tag, ciphertext = sealed[:16], sealed[16:]
    expected_tag = hmac.new(
        key, b"YANI-TAG" + ciphertext, hashlib.sha256
    ).digest()[:16]
    if not hmac.compare_digest(tag, expected_tag):
        raise RuntimeError("The recovered key failed HMAC verification")

    plaintext = bytes(
        left ^ right for left, right in zip(ciphertext, keystream(key, len(ciphertext)))
    )

    print(f"key: {key.hex()}")
    print("HMAC verified: True")
    print(f"flag: {plaintext.decode('ascii')}")


if __name__ == "__main__":
    main()
