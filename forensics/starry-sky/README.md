# Starry Sky

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Forensics |
| Points | 499 |
| Author | denny |
| Artifact | [`artifacts/challenge.png.zip`](artifacts/challenge.png.zip) |
| Flag | `THJCC{c0unt1ng_blu3s_by_thr33s}` |

> Let's see if there's anything special about this starry sky.

## Overview

The handout is a 512×512 PNG of a purple night sky flecked with faint stars.
There is no appended data, no broken chunk, and no trailing archive — the whole
challenge is steganography inside the pixels. A single `tEXt` chunk spells out
the method in riddle form, and the flag itself names the trick once decoded.

The recovered pipeline is:

1. Read the **least-significant bit of the blue channel** of every pixel,
   row-major.
2. Keep **every 5th** of those bits (stride 5).
3. Pack them MSB-first into bytes.
4. **XOR each byte with `0x5A`.**

The result begins, at offset 0, with `THJCC{c0unt1ng_blu3s_by_thr33s}` — and
"counting blues by threes" is exactly what the extraction does (blue channel,
stepped sampling).

## 1. Triage

```bash
unzip challenge.png.zip
file challenge.png
```

```text
challenge.png: PNG image data, 512 x 512, 8-bit/color RGB, non-interlaced
```

Walking the chunk list shows a completely well-formed PNG — all eight chunks
pass their CRCs, and `IEND` is the last byte of the file:

```text
IHDR  512x512 depth=8 color=2 (RGB) interlace=0   crc ok
tEXt  Comment                                     crc ok
tEXt  Author                                      crc ok
IDAT  x7                                           crc ok
IEND                                              trailing bytes: 0
```

No container tricks. Everything lives in the raster.

## 2. The Comment Is the Recipe

The `tEXt` chunks decode to:

```text
Author  : forensics-chal
Comment : Even the truth wears a mask here -- a single byte lifts it.
          The rest is just knowing which grains to read, and how far apart.
```

Read as a set of instructions:

| Riddle phrase | Meaning |
| --- | --- |
| "the truth wears a mask … a single byte lifts it" | the payload is masked with a **one-byte XOR** |
| "which grains to read" | which channel / bit-plane the "grains" (bits) live in |
| "and how far apart" | a fixed **stride** between the sampled bits |

So the shape of the solution is fixed before any pixels are touched: pick a
bit-plane, sub-sample it at some spacing, and XOR the bytes with a single key.
Three unknowns — channel/bit, stride, key.

## 3. Confirming It's an LSB Layer

Checking the mean of each low bit-plane (0.5 ≈ uniformly random, the signature
of embedded or noise data):

```text
R LSB mean = 0.5000     R bit6 mean = 0.9394
G LSB mean = 0.4982     R bit7 mean = 0.0056
B LSB mean = 0.4994
```

The three least-significant bits look like pure noise (mean ≈ 0.5), while the
upper bits carry the visible image (bit 7 is almost all 0 — a dark sky). That
random-looking low layer is where the "grains" are.

## 4. Recovering All Three Unknowns at Once

Rather than guess the channel, stride and key independently, exploit the fact
that the mask is a **single constant** and the plaintext starts with a known
prefix, `THJCC{`. For any candidate byte stream, if some six consecutive bytes
XORed with one constant equal `THJCC{`, that constant *is* the key and that
position *is* the start of the flag.

Sweep the small parameter space — `{R,G,B} × {bit 0,1,2} × stride 1..8 ×
{MSB,LSB-first} × {row,column-major}` — and test every offset of each resulting
byte stream against the prefix:

```python
target = b"THJCC{"
for channel in (0, 1, 2):
    for bit in (0, 1, 2):
        base = [(rgb[i*3+channel] >> bit) & 1 for i in range(npix)]
        for stride in range(1, 9):
            data = pack_msb(base[::stride])
            for i in range(len(data) - 6):
                key = data[i] ^ target[0]
                if all((data[i+j] ^ key) == target[j] for j in range(6)):
                    print(channel, bit, stride, hex(key), i)
```

Exactly one configuration matches:

```text
channel = B (blue)   bit = 0 (LSB)   stride = 5   key = 0x5A   offset = 0
```

## 5. Extracting the Flag

Applying that configuration:

- 512 × 512 = **262 144** blue-channel LSBs, row-major.
- Every 5th bit → **52 429** bits → **6 553** bytes after MSB-first packing.
- XOR each byte with `0x5A`.

```text
THJCC{c0unt1ng_blu3s_by_thr33s}\x00…
```

The flag sits at offset 0 and is followed immediately by a `0x00` terminator —
a deliberately clean plant, and confirmation the parameters are exactly right.
The plaintext is self-describing: **c0unt1ng_blu3s_by_thr33s** = counting the
**blue** channel's bits **by threes**… or, as the stride turned out, by fives —
the "threes" in the flag are the leetspeak flavour, while the true spacing is 5.
Either way, the decode is unambiguous: any other channel, bit, stride or key
produces noise, and only this one yields the `THJCC{` prefix.

## 6. Automated Solver

[`solve.py`](solve.py) has **no third-party dependencies**. It decodes the PNG
with the standard-library `zlib` (implementing the None/Sub/Up/Average/Paeth
defilters directly), then extracts the blue-LSB / stride-5 / XOR-0x5A stream:

```bash
python3 solve.py
```

```text
[*] 512x512 RGB; tEXt Comment: 'Even the truth wears a mask here -- ...'
[*] channel=B bit=0 stride=5 xor=0x5a

flag: THJCC{c0unt1ng_blu3s_by_thr33s}
```

`--search` re-derives the configuration from scratch by hunting the `THJCC{`
prefix, printing the channel/bit/stride/key it discovers:

```bash
python3 solve.py --search
```

```text
[+] auto-discovered config: {'channel': 2, 'bit': 0, 'stride': 5, 'key': 90, 'offset': 0}
flag: THJCC{c0unt1ng_blu3s_by_thr33s}
```

## Lessons

- **Read the metadata first — sometimes it hands you the algorithm.** The
  `tEXt` comment described the entire scheme (mask + which bits + spacing); the
  work was only turning three unknowns into values.
- **A constant XOR is a gift when you know a prefix.** `THJCC{` XORed against
  the ciphertext reveals both the key and the offset in one pass, so you never
  have to brute-force 256 keys blindly.
- **Sub-sampling defeats naive LSB tools.** Reading *every* blue LSB gives
  noise; the payload only appears when you keep every 5th bit, which is why a
  plain `zsteg`-style dump misses it.
- **Bit-plane means expose the hiding place.** A low plane sitting at mean ≈ 0.5
  under a visibly structured image is the tell that data (not just dithering)
  lives there.

## Flag

```text
THJCC{c0unt1ng_blu3s_by_thr33s}
```
