#!/usr/bin/env python3
"""Solver for the THJCC CTF 2026 Summer forensics challenge "Man!".

The challenge ships a PNG whose bytes hold two independent secrets:

1. A password-protected ZIP appended after the PNG ``IEND`` chunk.
2. The ZIP password stored in the LSBs of the red channel.

This solver is dependency-free: it decodes the PNG with ``zlib`` alone and
decrypts the legacy ZipCrypto entry with the standard library ``zipfile``.

    python3 solve.py
"""

from __future__ import annotations

import binascii
import io
import struct
import sys
import zipfile
import zlib
from pathlib import Path

HANDOUT = Path(__file__).parent / "artifacts" / "final_koby_challenge.png.zip"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


# --------------------------------------------------------------------------
# PNG parsing
# --------------------------------------------------------------------------
def iter_chunks(data: bytes):
    """Yield ``(offset, type, payload, crc_ok)`` for every PNG chunk."""
    if not data.startswith(PNG_MAGIC):
        raise ValueError("not a PNG")
    off = len(PNG_MAGIC)
    while off + 8 <= len(data):
        (length,) = struct.unpack(">I", data[off : off + 4])
        ctype = data[off + 4 : off + 8]
        payload = data[off + 8 : off + 8 + length]
        (stored,) = struct.unpack(">I", data[off + 8 + length : off + 12 + length])
        crc_ok = binascii.crc32(ctype + payload) & 0xFFFFFFFF == stored
        yield off, ctype, payload, crc_ok
        off += 12 + length
        if ctype == b"IEND":
            break
    yield off, b"__END__", b"", True


def paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def decode_png_rgb(data: bytes) -> tuple[int, int, bytearray]:
    """Decode a non-interlaced 8-bit RGB PNG into a flat RGB byte array."""
    width = height = None
    idat = bytearray()
    for _off, ctype, payload, _ok in iter_chunks(data):
        if ctype == b"IHDR":
            width, height, depth, color, _c, _f, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
            if (depth, color, interlace) != (8, 2, 0):
                raise ValueError("expected 8-bit non-interlaced RGB")
        elif ctype == b"IDAT":
            idat += payload
        elif ctype == b"IEND":
            break

    raw = zlib.decompress(bytes(idat))
    bpp, stride = 3, width * 3
    out = bytearray(height * stride)
    prev = bytearray(stride)
    pos = 0
    for y in range(height):
        ftype = raw[pos]
        pos += 1
        line = bytearray(raw[pos : pos + stride])
        pos += stride
        if ftype == 1:  # Sub
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif ftype == 2:  # Up
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:  # Average
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:  # Paeth
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                upleft = prev[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + paeth(left, prev[i], upleft)) & 0xFF
        elif ftype != 0:
            raise ValueError(f"bad filter type {ftype} on row {y}")
        out[y * stride : (y + 1) * stride] = line
        prev = line
    return width, height, out


# --------------------------------------------------------------------------
# Stage 1: carve the appended ZIP
# --------------------------------------------------------------------------
def carve_trailer(png: bytes) -> tuple[int, bytes]:
    """Return the offset just past IEND and the trailing bytes."""
    end = None
    for off, ctype, payload, ok in iter_chunks(png):
        if ctype == b"__END__":
            end = off
        status = "ok" if ok else "BAD CRC"
        if ctype != b"__END__":
            print(f"  chunk {ctype.decode():<4} off={off:<7} len={len(payload):<7} crc={status}")
    return end, png[end:]


# --------------------------------------------------------------------------
# Stage 2: recover the password from the red-channel LSBs
# --------------------------------------------------------------------------
def extract_lsb_password(width: int, height: int, rgb: bytearray) -> str:
    """Read red-channel LSBs MSB-first until the NUL terminator."""
    bits = [rgb[i] & 1 for i in range(0, len(rgb), 3)]
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i : i + 8]:
            byte = (byte << 1) | b
        if byte == 0:
            break
        out.append(byte)
    return out.decode("ascii")


# --------------------------------------------------------------------------
def main() -> int:
    if not HANDOUT.exists():
        print(f"handout not found: {HANDOUT}", file=sys.stderr)
        return 1

    with zipfile.ZipFile(HANDOUT) as zf:
        png = zf.read("final_koby_challenge.png")
    print(f"[*] handout PNG: {len(png)} bytes")

    print("[*] walking PNG chunks")
    end, trailer = carve_trailer(png)
    print(f"[+] IEND ends at offset {end}; {len(trailer)} trailing bytes")

    if not trailer.startswith(b"PK\x03\x04"):
        print("[-] no appended ZIP found", file=sys.stderr)
        return 1

    flags, method = struct.unpack("<HH", trailer[6:10])
    print(f"[+] appended ZIP: encrypted={bool(flags & 1)} method={method} (0=stored)")

    print("[*] decoding pixels and reading red-channel LSBs")
    width, height, rgb = decode_png_rgb(png)
    password = extract_lsb_password(width, height, rgb)
    print(f"[+] image {width}x{height}; recovered password: {password}")

    with zipfile.ZipFile(io.BytesIO(trailer)) as zf:
        info = zf.getinfo("flag.txt")
        flag = zf.read("flag.txt", pwd=password.encode())

    computed = binascii.crc32(flag) & 0xFFFFFFFF
    print(f"[+] CRC32 expected={info.CRC:08x} computed={computed:08x} "
          f"{'MATCH' if computed == info.CRC else 'MISMATCH'}")
    print(f"\nflag: {flag.decode().strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
