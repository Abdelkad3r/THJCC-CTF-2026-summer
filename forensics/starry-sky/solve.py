#!/usr/bin/env python3
"""Starry Sky — THJCC CTF 2026 Summer (forensics, 499 pts).

The handout is a 512x512 starry-sky PNG whose tEXt comment is the recipe:

    "Even the truth wears a mask here -- a single byte lifts it. The rest is
     just knowing which grains to read, and how far apart."

  * "a single byte lifts it"        -> a one-byte XOR mask (0x5A)
  * "which grains to read"          -> the blue channel's least-significant bit
  * "how far apart"                 -> take every 5th such bit (stride 5)

Reading the blue LSB of every pixel (row-major), keeping every 5th bit, packing
MSB-first into bytes and XORing each with 0x5A yields the flag at offset 0.

This solver has no third-party dependencies: it decodes the PNG with zlib
(implementing the None/Sub/Up/Average/Paeth defilters directly). It can also
auto-discover the whole configuration by searching for the "THJCC{" prefix.

    python3 solve.py [--search]
"""
from __future__ import annotations

import struct
import sys
import zipfile
import zlib
from pathlib import Path

HANDOUT = Path(__file__).parent / "artifacts" / "challenge.png.zip"
MEMBER = "challenge.png"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

# recovered configuration
CHANNEL = 2      # 0=R, 1=G, 2=B  -> blue
BIT = 0          # least-significant bit
STRIDE = 5       # keep every 5th bit
XOR_KEY = 0x5A   # single-byte mask


# --------------------------------------------------------------------------
# minimal PNG decoder (8-bit, non-interlaced, colour type 2 / RGB)
# --------------------------------------------------------------------------
def paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def iter_chunks(data: bytes):
    off = len(PNG_MAGIC)
    while off + 8 <= len(data):
        (length,) = struct.unpack(">I", data[off:off + 4])
        ctype = data[off + 4:off + 8]
        payload = data[off + 8:off + 8 + length]
        yield ctype, payload
        off += 12 + length
        if ctype == b"IEND":
            break


def decode_rgb(data: bytes):
    if not data.startswith(PNG_MAGIC):
        raise ValueError("not a PNG")
    width = height = None
    idat = bytearray()
    text = {}
    for ctype, payload in iter_chunks(data):
        if ctype == b"IHDR":
            width, height, depth, color, _c, _f, interlace = struct.unpack(">IIBBBBB", payload)
            if (depth, color, interlace) != (8, 2, 0):
                raise ValueError("expected 8-bit non-interlaced RGB")
        elif ctype == b"IDAT":
            idat += payload
        elif ctype == b"tEXt":
            k, _, v = payload.partition(b"\x00")
            text[k.decode("latin1")] = v.decode("latin1")

    raw = zlib.decompress(bytes(idat))
    bpp, stride = 3, width * 3
    out = bytearray(height * stride)
    prev = bytearray(stride)
    pos = 0
    for y in range(height):
        ftype = raw[pos]; pos += 1
        line = bytearray(raw[pos:pos + stride]); pos += stride
        if ftype == 1:      # Sub
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif ftype == 2:    # Up
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:    # Average
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:    # Paeth
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                upleft = prev[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + paeth(left, prev[i], upleft)) & 0xFF
        elif ftype != 0:
            raise ValueError(f"bad filter {ftype} on row {y}")
        out[y * stride:(y + 1) * stride] = line
        prev = line
    return width, height, bytes(out), text


# --------------------------------------------------------------------------
def channel_lsb_bits(rgb: bytes, channel: int, bit: int):
    """Yield the given bit of the given channel, pixel by pixel (row-major)."""
    return [(rgb[i * 3 + channel] >> bit) & 1 for i in range(len(rgb) // 3)]


def pack_msb(bits) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


def extract(rgb: bytes, channel, bit, stride, key):
    bits = channel_lsb_bits(rgb, channel, bit)[::stride]
    data = pack_msb(bits)
    return bytes(b ^ key for b in data)


def search(rgb: bytes):
    """Auto-discover channel/bit/stride/key by finding the THJCC{ prefix."""
    target = b"THJCC{"
    for channel in range(3):
        for bit in range(3):
            base = channel_lsb_bits(rgb, channel, bit)
            for stride in range(1, 9):
                data = pack_msb(base[::stride])
                for i in range(len(data) - len(target)):
                    key = data[i] ^ target[0]
                    if all((data[i + j] ^ key) == target[j] for j in range(len(target))):
                        return dict(channel=channel, bit=bit, stride=stride,
                                    key=key, offset=i)
    return None


def main() -> int:
    if not HANDOUT.exists():
        print(f"handout not found: {HANDOUT}", file=sys.stderr)
        return 1
    with zipfile.ZipFile(HANDOUT) as zf:
        png = zf.read(MEMBER)
    w, h, rgb, text = decode_rgb(png)
    print(f"[*] {w}x{h} RGB; tEXt Comment: {text.get('Comment','')!r}")

    if "--search" in sys.argv:
        cfg = search(rgb)
        print(f"[+] auto-discovered config: {cfg}")
        if cfg:
            globals().update()  # no-op; use cfg below
            data = extract(rgb, cfg["channel"], cfg["bit"], cfg["stride"], cfg["key"])
            flag = data[cfg["offset"]:data.index(b"}", cfg["offset"]) + 1]
            print(f"\nflag: {flag.decode()}")
            return 0

    print(f"[*] channel={'RGB'[CHANNEL]} bit={BIT} stride={STRIDE} xor={XOR_KEY:#04x}")
    data = extract(rgb, CHANNEL, BIT, STRIDE, XOR_KEY)
    start = data.index(b"THJCC{")
    flag = data[start:data.index(b"}", start) + 1]
    print(f"\nflag: {flag.decode()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
