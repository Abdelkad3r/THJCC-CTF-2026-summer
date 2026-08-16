#!/usr/bin/env python3
"""Exploit the RSA PKCS#1 v1.5 oracle used by A Million Messages."""

from __future__ import annotations

import socket
import time


HOST = "chal.thjcc.org"
PORT = 12003
BATCH_SIZE = 512


def ceil_div(a: int, b: int) -> int:
    return -(-a // b)


class Oracle:
    def __init__(self, host: str, port: int) -> None:
        self.sock = socket.create_connection((host, port), timeout=30)
        self.sock.settimeout(60)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.stream = self.sock.makefile("rwb", buffering=0)
        self.queries = 0

        values: dict[str, int] = {}
        for _ in range(3):
            key, value = self.stream.readline().decode().split()
            values[key] = int(value, 16)

        self.n = values["N"]
        self.e = values["E"]
        self.c = values["C"]

    def test_many(self, multipliers: list[int]) -> list[bool]:
        payload = bytearray()
        for multiplier in multipliers:
            candidate = self.c * pow(multiplier, self.e, self.n) % self.n
            payload.extend(f"{candidate:x}\n".encode())

        self.sock.sendall(payload)
        results = []
        for _ in multipliers:
            response = self.stream.readline()
            if not response:
                raise EOFError("padding oracle closed the connection")
            results.append(response.strip() == b"OK")

        self.queries += len(multipliers)
        return results

    def first_valid_from(self, start: int) -> int:
        candidate = start
        while True:
            batch = list(range(candidate, candidate + BATCH_SIZE))
            results = self.test_many(batch)
            for multiplier, valid in zip(batch, results):
                if valid:
                    return multiplier
            candidate += BATCH_SIZE
            if self.queries % (BATCH_SIZE * 20) == 0:
                print(f"[.] {self.queries:,} oracle queries", flush=True)

    def close(self) -> None:
        self.stream.close()
        self.sock.close()


def narrow(
    intervals: list[tuple[int, int]], s: int, n: int, boundary: int
) -> list[tuple[int, int]]:
    narrowed: list[tuple[int, int]] = []
    for low, high in intervals:
        r_low = ceil_div(low * s - (3 * boundary - 1), n)
        r_high = (high * s - 2 * boundary) // n
        for r in range(r_low, r_high + 1):
            new_low = max(low, ceil_div(2 * boundary + r * n, s))
            new_high = min(high, (3 * boundary - 1 + r * n) // s)
            if new_low <= new_high:
                narrowed.append((new_low, new_high))

    narrowed.sort()
    merged: list[tuple[int, int]] = []
    for low, high in narrowed:
        if not merged or low > merged[-1][1] + 1:
            merged.append((low, high))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], high))
    return merged


def recover(oracle: Oracle) -> int:
    n = oracle.n
    block_size = (n.bit_length() + 7) // 8
    boundary = 1 << (8 * (block_size - 2))
    intervals = [(2 * boundary, 3 * boundary - 1)]

    # The supplied ciphertext is already PKCS-conforming, so no blinding step
    # is necessary. Search for the first useful multiplier in batched queries.
    s = oracle.first_valid_from(ceil_div(n, 3 * boundary))
    print(f"[+] Initial conforming multiplier: {s}", flush=True)

    iteration = 1
    while True:
        intervals = narrow(intervals, s, n, boundary)
        if not intervals:
            raise RuntimeError("oracle responses eliminated every interval")

        if iteration % 25 == 0:
            width = sum(high - low + 1 for low, high in intervals)
            print(
                f"[.] round={iteration} intervals={len(intervals)} "
                f"width_bits={width.bit_length()} queries={oracle.queries:,}",
                flush=True,
            )

        if len(intervals) == 1 and intervals[0][0] == intervals[0][1]:
            return intervals[0][0]

        if len(intervals) > 1:
            s = oracle.first_valid_from(s + 1)
        else:
            low, high = intervals[0]
            r = ceil_div(2 * (high * s - 2 * boundary), n)

            while True:
                s_low = ceil_div(2 * boundary + r * n, high)
                s_high = (3 * boundary - 1 + r * n) // low
                if s_low <= s_high:
                    candidates = list(range(s_low, s_high + 1))
                    for offset in range(0, len(candidates), BATCH_SIZE):
                        batch = candidates[offset : offset + BATCH_SIZE]
                        results = oracle.test_many(batch)
                        match = next(
                            (x for x, valid in zip(batch, results) if valid), None
                        )
                        if match is not None:
                            s = match
                            break
                    else:
                        r += 1
                        continue
                    break
                r += 1

        iteration += 1


def unpad(block: bytes) -> bytes:
    if not block.startswith(b"\x00\x02"):
        raise ValueError(f"unexpected recovered block: {block.hex()}")
    separator = block.find(b"\x00", 2)
    if separator < 10:
        raise ValueError("invalid PKCS#1 v1.5 padding")
    return block[separator + 1 :]


def main() -> None:
    started = time.time()
    oracle = Oracle(HOST, PORT)
    try:
        print(f"[+] N = {oracle.n:x}")
        print(f"[+] C = {oracle.c:x}")
        plaintext = recover(oracle)
        block_size = (oracle.n.bit_length() + 7) // 8
        encoded = plaintext.to_bytes(block_size, "big")
        message = unpad(encoded)
        print(f"[+] Recovered block: {encoded.hex()}")
        print(f"[+] Plaintext: {message.decode(errors='replace')}")
        print(
            f"[+] Completed with {oracle.queries:,} queries in "
            f"{time.time() - started:.1f}s"
        )
    finally:
        oracle.close()


if __name__ == "__main__":
    main()
