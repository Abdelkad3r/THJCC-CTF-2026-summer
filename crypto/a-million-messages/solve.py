#!/usr/bin/env python3
"""Exploit the RSA PKCS#1 v1.5 oracle used by A Million Messages."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass


HOST = "chal.thjcc.org"
PORT = 12003
BATCH_SIZE = 512
SPECULATIVE_DEPTH = 8


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


@dataclass(frozen=True)
class Cursor:
    mode: str
    first: int
    second: int = 0


@dataclass(frozen=True)
class AttackState:
    intervals: tuple[tuple[int, int], ...]
    cursor: Cursor
    rounds: int


def make_cursor(
    intervals: tuple[tuple[int, int], ...],
    previous_s: int,
    n: int,
    boundary: int,
) -> Cursor:
    if len(intervals) > 1:
        return Cursor("linear", previous_s + 1)

    low, high = intervals[0]
    r = ceil_div(2 * (high * previous_s - 2 * boundary), n)
    return Cursor("single", r)


def reject_next(
    state: AttackState, n: int, boundary: int
) -> tuple[int, AttackState]:
    """Return the next multiplier and the state reached if it is rejected."""
    if state.cursor.mode == "linear":
        candidate = state.cursor.first
        rejected = AttackState(
            state.intervals, Cursor("linear", candidate + 1), state.rounds
        )
        return candidate, rejected

    low, high = state.intervals[0]
    r = state.cursor.first
    next_s = state.cursor.second
    while True:
        s_low = ceil_div(2 * boundary + r * n, high)
        s_high = (3 * boundary - 1 + r * n) // low
        candidate = max(s_low, next_s) if next_s else s_low
        if candidate <= s_high:
            if candidate < s_high:
                cursor = Cursor("single", r, candidate + 1)
            else:
                cursor = Cursor("single", r + 1)
            rejected = AttackState(state.intervals, cursor, state.rounds)
            return candidate, rejected
        r += 1
        next_s = 0


def accept(
    state: AttackState, candidate: int, n: int, boundary: int
) -> AttackState | None:
    intervals = tuple(narrow(list(state.intervals), candidate, n, boundary))
    if not intervals:
        return None
    return AttackState(
        intervals,
        make_cursor(intervals, candidate, n, boundary),
        state.rounds + 1,
    )


def collect_speculative_queries(
    state: AttackState,
    depth: int,
    n: int,
    boundary: int,
    candidates: set[int],
) -> None:
    if depth == 0 or (
        len(state.intervals) == 1
        and state.intervals[0][0] == state.intervals[0][1]
    ):
        return

    candidate, rejected = reject_next(state, n, boundary)
    candidates.add(candidate)
    collect_speculative_queries(rejected, depth - 1, n, boundary, candidates)

    accepted = accept(state, candidate, n, boundary)
    if accepted is not None:
        collect_speculative_queries(accepted, depth - 1, n, boundary, candidates)


def recover(oracle: Oracle) -> int:
    n = oracle.n
    block_size = (n.bit_length() + 7) // 8
    boundary = 1 << (8 * (block_size - 2))
    intervals = [(2 * boundary, 3 * boundary - 1)]

    # The supplied ciphertext is already PKCS-conforming, so no blinding step
    # is necessary. Search for the first useful multiplier in batched queries.
    s = oracle.first_valid_from(ceil_div(n, 3 * boundary))
    print(f"[+] Initial conforming multiplier: {s}", flush=True)
    intervals = narrow(intervals, s, n, boundary)
    if not intervals:
        raise RuntimeError("first oracle response eliminated every interval")
    state = AttackState(
        tuple(intervals),
        make_cursor(tuple(intervals), s, n, boundary),
        1,
    )

    reported_round = 0
    while not (
        len(state.intervals) == 1
        and state.intervals[0][0] == state.intervals[0][1]
    ):
        candidates: set[int] = set()
        collect_speculative_queries(
            state, SPECULATIVE_DEPTH, n, boundary, candidates
        )
        ordered = sorted(candidates)
        answers = dict(zip(ordered, oracle.test_many(ordered)))

        for _ in range(SPECULATIVE_DEPTH):
            if (
                len(state.intervals) == 1
                and state.intervals[0][0] == state.intervals[0][1]
            ):
                break
            candidate, rejected = reject_next(state, n, boundary)
            if answers[candidate]:
                accepted = accept(state, candidate, n, boundary)
                if accepted is None:
                    raise RuntimeError("conforming response produced no interval")
                state = accepted
            else:
                state = rejected

        if state.rounds // 25 > reported_round // 25:
            width = sum(high - low + 1 for low, high in state.intervals)
            print(
                f"[.] round={state.rounds} intervals={len(state.intervals)} "
                f"width_bits={width.bit_length()} queries={oracle.queries:,}",
                flush=True,
            )
        reported_round = state.rounds

    return state.intervals[0][0]


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
