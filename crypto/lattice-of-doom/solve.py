#!/usr/bin/env python3
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


DATA_FILE = Path(__file__).with_name("artifacts") / "output.json"

# secp256k1 parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

NONCE_BITS = 29 * 8
NONCE_BOUND = 1 << NONCE_BITS
CENTER = NONCE_BOUND // 2


def point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left

    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def scalar_multiply(value, point=(GX, GY)):
    result = None
    addend = point
    while value:
        if value & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        value >>= 1
    return result


def signature_relations(data):
    a_values = []
    b_values = []
    parsed = []

    for signature in data["signatures"]:
        message = bytes.fromhex(signature["msg"])
        r = int(signature["r"], 16)
        s = int(signature["s"], 16)
        h = int.from_bytes(hashlib.sha256(message).digest(), "big")
        inverse_s = pow(s, -1, N)

        a_values.append((r * inverse_s) % N)
        b_values.append((h * inverse_s) % N)
        parsed.append((h, r, s))

    return a_values, b_values, parsed


def build_lattice(a_values, b_values):
    count = len(a_values)
    dimension = count + 2
    basis = [[0] * dimension for _ in range(dimension)]

    for index in range(count):
        basis[index][index] = N * N

    secret_row = count
    for index, value in enumerate(a_values):
        basis[secret_row][index] = value * N
    basis[secret_row][secret_row] = CENTER

    constant_row = count + 1
    for index, value in enumerate(b_values):
        basis[constant_row][index] = (value - CENTER) * N
    basis[constant_row][constant_row] = CENTER * N

    return basis


def format_fplll_matrix(matrix):
    rows = ["[" + " ".join(map(str, row)) + "]" for row in matrix]
    return "[\n" + "\n".join(rows) + "\n]\n"


def reduce_lattice(basis):
    executable = shutil.which("fplll")
    if executable is None:
        raise RuntimeError("fplll is required but was not found in PATH")

    with tempfile.NamedTemporaryFile("w", suffix=".fplll") as matrix_file:
        matrix_file.write(format_fplll_matrix(basis))
        matrix_file.flush()
        process = subprocess.run(
            [
                executable,
                "-a", "lll",
                "-m", "proved",
                "-d", "0.999",
                "-f", "mpfr",
                "-p", "256",
                matrix_file.name,
            ],
            check=True,
            text=True,
            capture_output=True,
        )

    rows = []
    for line in process.stdout.splitlines():
        values = [int(value) for value in re.findall(r"-?\d+", line)]
        if values:
            rows.append(values)

    dimension = len(basis)
    if len(rows) != dimension or any(len(row) != dimension for row in rows):
        raise RuntimeError("Could not parse the reduced fplll matrix")
    return rows


def derive_nonces(private_key, signatures):
    return [
        ((h + r * private_key) * pow(s, -1, N)) % N
        for h, r, s in signatures
    ]


def recover_private_key(reduced_basis, signatures, expected_public_key):
    count = len(signatures)
    marker = CENTER * N

    for row in reduced_basis:
        if abs(row[-1]) != marker or row[count] % CENTER != 0:
            continue

        coefficient = row[count] // CENTER
        for candidate in {coefficient % N, (-coefficient) % N}:
            nonces = derive_nonces(candidate, signatures)
            if not all(0 < nonce < NONCE_BOUND for nonce in nonces):
                continue
            if scalar_multiply(candidate) != expected_public_key:
                continue
            return candidate, nonces

    raise RuntimeError("LLL did not expose a valid private-key candidate")


def decrypt_flag(flag_enc, private_key):
    executable = shutil.which("openssl")
    if executable is None:
        raise RuntimeError("openssl is required but was not found in PATH")

    key = hashlib.sha256(
        b"wallet-v1|" + private_key.to_bytes(32, "big")
    ).digest()[:16]
    iv, ciphertext = flag_enc[:16], flag_enc[16:]

    process = subprocess.run(
        [
            executable,
            "enc", "-aes-128-cbc", "-d",
            "-K", key.hex(),
            "-iv", iv.hex(),
        ],
        input=ciphertext,
        check=True,
        capture_output=True,
    )
    return key, process.stdout


def main():
    data = json.loads(DATA_FILE.read_text())
    a_values, b_values, signatures = signature_relations(data)

    print(f"signatures: {len(signatures)}")
    print(f"nonce bound: 2^{NONCE_BITS}")
    print(f"lattice dimension: {len(signatures) + 2}")

    basis = build_lattice(a_values, b_values)
    reduced = reduce_lattice(basis)

    public_key = (int(data["Qx"], 16), int(data["Qy"], 16))
    private_key, nonces = recover_private_key(reduced, signatures, public_key)
    key, flag = decrypt_flag(bytes.fromhex(data["flag_enc"]), private_key)

    print(f"private key: {private_key:064x}")
    print(f"largest nonce: {max(nonces).bit_length()} bits")
    print("public key verified: True")
    print(f"AES key: {key.hex()}")
    print(f"flag: {flag.decode('ascii')}")


if __name__ == "__main__":
    main()
