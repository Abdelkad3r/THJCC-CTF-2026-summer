#!/usr/bin/env python3
"""TeaGod.exe — THJCC CTF 2026 Summer (reverse, 100 pts).

The reward string is not stored in the binary. It is rebuilt at runtime by a
two-stage transform whose inputs (a 3-entry pointer table, a 3-byte key, three
12-byte source blobs, and an 8-byte rolling key) all live in .rdata. This script
reads those inputs straight out of the PE and reproduces the transform, so it
recovers the flag statically — the Windows executable is never run.

Stage 1  (loop @ 0x140001e90):
    stage1[row*12 + j] = ((src[row][j] + (0xE7 - 7*j)) & 0xFF) ^ key3[row]
Stage 2  (loop @ 0x140001fd0):
    flag[i] = stage1[i] ^ key8[(1 + 3*i) & 7]

A GetTickCount() byte is also XORed into every output byte -- but exactly twice
(@0x14000204c and @0x140001fd0), so it cancels and the result is deterministic.

No third-party dependencies.

    python3 solve.py [path/to/TeaGod.exe] [--dump-image out.png]
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

DEFAULT = Path(__file__).parent / "artifacts" / "TeaGod.exe"
IMAGE_BASE = 0x140000000

# Addresses recovered from the disassembly.
PTR_TABLE_VA = 0x140005210   # 3 x qword -> source blob pointers
KEY3_VA = 0x140005228        # 3 bytes, one per row
KEY8 = (0x616E7368655F6368).to_bytes(8, "little")  # movabs -> b"hc_ehsna"
ROWS, COLS = 3, 12           # 3 blobs x 12 bytes = 36 flag bytes


def load_sections(data: bytes):
    """Return [(rva, vsize, raw_ptr, raw_size)] for every PE section."""
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsz = struct.unpack_from("<H", data, pe + 20)[0]
    st = pe + 24 + optsz
    secs = []
    for i in range(nsec):
        off = st + i * 40
        _, va, rsz, rptr = struct.unpack_from("<IIII", data, off + 8)
        vsz = struct.unpack_from("<I", data, off + 8)[0]
        secs.append((va, vsz, rptr, rsz))
    return secs


def make_va2off(data: bytes):
    secs = load_sections(data)

    def va2off(va: int) -> int:
        rva = va - IMAGE_BASE
        for sva, vsz, rptr, rsz in secs:
            if sva <= rva < sva + max(vsz, rsz):
                return rva - sva + rptr
        raise ValueError(f"VA {va:#x} not in any section")

    return va2off


def recover_flag(data: bytes) -> str:
    va2off = make_va2off(data)

    ptrs = struct.unpack_from("<3Q", data, va2off(PTR_TABLE_VA))
    key3 = data[va2off(KEY3_VA):va2off(KEY3_VA) + ROWS]
    srcs = [data[va2off(p):va2off(p) + COLS] for p in ptrs]

    # Stage 1: additive de-skew (0xE7 stepping down by 7) then per-row XOR.
    stage1 = bytes(
        ((srcs[row][j] + (0xE7 - 7 * j)) & 0xFF) ^ key3[row]
        for row in range(ROWS)
        for j in range(COLS)
    )

    # Stage 2: 8-byte rolling XOR indexed by (1 + 3*i) & 7.
    flag = bytes(stage1[i] ^ KEY8[(1 + 3 * i) & 7] for i in range(ROWS * COLS))

    text = flag.decode("ascii")
    if not (text.startswith("THJCC{") and text.endswith("}")):
        raise SystemExit(f"[-] decode produced unexpected output: {text!r}")
    return text


def dump_image(data: bytes, out: Path):
    """Carve the embedded RCDATA PNG (the reward image) to a file."""
    magic = b"\x89PNG\r\n\x1a\n"
    start = data.find(magic)
    end = data.find(b"IEND", start) + 8
    out.write_bytes(data[start:end])
    print(f"[+] wrote {out} ({end - start} bytes)")


def main() -> int:
    args = [a for a in sys.argv[1:]]
    path = DEFAULT
    dump = None
    i = 0
    while i < len(args):
        if args[i] == "--dump-image":
            dump = Path(args[i + 1])
            i += 2
        else:
            path = Path(args[i])
            i += 1

    if not path.exists():
        print(f"binary not found: {path}", file=sys.stderr)
        return 1
    data = path.read_bytes()

    va2off = make_va2off(data)
    ptrs = struct.unpack_from("<3Q", data, va2off(PTR_TABLE_VA))
    key3 = data[va2off(KEY3_VA):va2off(KEY3_VA) + ROWS]
    print(f"[*] pointer table @ {PTR_TABLE_VA:#x}: {[hex(p) for p in ptrs]}")
    print(f"[*] row key   @ {KEY3_VA:#x}: {key3.hex()}")
    print(f"[*] rolling key (movabs)   : {KEY8!r}")

    flag = recover_flag(data)
    print(f"\nflag: {flag}")

    if dump:
        dump_image(data, dump)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
