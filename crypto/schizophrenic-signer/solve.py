#!/usr/bin/env python3
import argparse
import re
import socket
from pathlib import Path

from fpylll import BKZ, IntegerMatrix, LLL


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def scalar_mul(point, scalar):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def parse_instance(text):
    pub_match = re.search(r"Public Key: \((0x[0-9a-f]+), (0x[0-9a-f]+)\)", text)
    gen_match = re.search(
        r"Generator params: a = (0x[0-9a-f]+), b = (0x[0-9a-f]+)", text
    )
    if not pub_match or not gen_match:
        raise ValueError("instance header not found")

    values = re.findall(
        r"h = (0x[0-9a-f]+)\s+r = (0x[0-9a-f]+)\s+s = (0x[0-9a-f]+)",
        text,
    )
    if len(values) != 85:
        raise ValueError(f"expected 85 signatures, got {len(values)}")

    pub = tuple(int(value, 16) for value in pub_match.groups())
    a, b = (int(value, 16) for value in gen_match.groups())
    signatures = [tuple(int(value, 16) for value in row) for row in values]
    return pub, a, b, signatures


def recover_key(pub, a, b, signatures):
    alpha = []
    beta = []
    for h, r, s in signatures:
        inv_s = pow(s, -1, Q)
        alpha.append(r * inv_s % Q)
        beta.append(h * inv_s % Q)

    inv_p = pow(P, -1, Q)
    aa = []
    bb = []
    for i in range(len(signatures) - 1):
        aa.append((a * alpha[i] - alpha[i + 1]) * inv_p % Q)
        bb.append((a * beta[i] + b - beta[i + 1]) * inv_p % Q)

    count = len(aa)
    dimension = count + 2
    basis = IntegerMatrix(dimension, dimension)
    for i in range(count):
        basis[i, i] = Q * Q
        basis[count, i] = aa[i] * Q
        basis[count + 1, i] = (bb[i] - a // 2) * Q
    basis[count, count] = a
    basis[count + 1, count + 1] = a * Q

    def candidate_from_rows():
        for row in range(dimension):
            key_coordinate = int(basis[row, count])
            if key_coordinate % a:
                continue
            d = key_coordinate // a % Q
            for candidate in (d, -d % Q):
                if not 1 <= candidate < Q:
                    continue
                if scalar_mul((GX, GY), candidate) != pub:
                    continue
                quotients = [(aa[i] * candidate + bb[i]) % Q for i in range(count)]
                if not all(value < a for value in quotients):
                    raise RuntimeError("public key matched but quotient bounds did not")
                return candidate
        return None

    LLL.reduction(basis, delta=0.999)
    for block_size in (20, 25, 30, 35, 40):
        BKZ.reduction(
            basis,
            BKZ.Param(block_size=block_size, max_loops=8, flags=BKZ.AUTO_ABORT),
        )
        candidate = candidate_from_rows()
        if candidate is not None:
            return candidate

    raise RuntimeError("lattice did not recover the private key")


def receive_instance(sock):
    data = bytearray()
    marker = b"Private Key (d) in hex:"
    while marker not in data:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("server closed before the key prompt")
        data.extend(chunk)
    return data.decode()


def solve_remote(host, port):
    for attempt in range(1, 301):
        sock = socket.create_connection((host, port), timeout=15)
        sock.settimeout(30)
        transcript = receive_instance(sock)
        pub, a, b, signatures = parse_instance(transcript)
        print(f"attempt {attempt}: q/a = {Q / a:.4f}", flush=True)

        if 1000 * Q < 15700 * a:
            sock.close()
            continue

        Path("live-transcript.txt").write_text(transcript)
        try:
            d = recover_key(pub, a, b, signatures)
        except RuntimeError:
            sock.close()
            continue

        print(f"private key: {d:#x}")
        sock.sendall(f"{d:x}\n".encode())
        response = bytearray()
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            response.extend(chunk)
        sock.close()
        print(response.decode(errors="replace"), end="")
        return

    raise RuntimeError("no favorable generator multiplier after 300 attempts")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--transcript", type=Path)
    parser.add_argument("--host", default="chal.thjcc.org")
    parser.add_argument("--port", type=int, default=11451)
    args = parser.parse_args()

    if args.transcript:
        pub, a, b, signatures = parse_instance(args.transcript.read_text())
        print(f"{recover_key(pub, a, b, signatures):#x}")
    else:
        solve_remote(args.host, args.port)


if __name__ == "__main__":
    main()
