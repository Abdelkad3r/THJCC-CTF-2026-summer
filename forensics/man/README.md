# Man!

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Forensics |
| Points | 100 |
| Author | denny |
| Artifact | [`artifacts/final_koby_challenge.png.zip`](artifacts/final_koby_challenge.png.zip) |
| Flag | `THJCC{Man_BA_0ut_Seeyouaga1n_1978}` |

> 「直升機上的黑盒子損壞了」，只剩下一張最後傳出來的迷因梗圖。
> 你能幫忙重構現場，找到牢大最後留下的遺言嗎？
>
> *"The helicopter's black box is damaged. All that is left is one last meme
> image that was transmitted. Can you help reconstruct the scene and find
> 牢大's final words?"*

## Overview

The handout is a single PNG of the well-known 牢大 helicopter meme. The prompt
claims the file is "damaged", which invites you to start repairing chunk
headers and CRCs. That framing is misdirection: every chunk in the PNG is
structurally valid and passes its CRC check.

The challenge is actually a two-stage container puzzle, and the two stages are
completely independent of one another:

1. **A password-protected ZIP is appended after the `IEND` chunk.** It holds a
   single stored (uncompressed) entry, `flag.txt`, encrypted with legacy
   ZipCrypto.
2. **The ZIP password is hidden in the image pixels.** It is written into the
   least-significant bits of the red channel as a NUL-terminated ASCII string.

"Reconstruct the scene" is the real hint. The *scene* is the raster image, and
you have to reconstruct it from the compressed IDAT stream to read the bits
that carry the password. The theme wrapped around the puzzle is consistent
throughout: `MambaOut`, `Helicopter_Blackbox`, GPS coordinates pointing at
Kobe Bryant's home arena, and a password referencing his birth year.

## 1. Initial Triage

Record the hashes and identify the handout:

```bash
shasum -a 256 final_koby_challenge.png.zip
unzip -l final_koby_challenge.png.zip
```

```text
ef6f92513bfd8ee4fc813b8a43556e9249900091e460d41529d8b62ce67ab372  final_koby_challenge.png.zip

  Length      Date    Time    Name
---------  ---------- -----   ----
   181383  07-19-2026 11:03   final_koby_challenge.png
      376  07-19-2026 11:03   __MACOSX/._final_koby_challenge.png
```

The `__MACOSX/` entry is an AppleDouble resource fork left behind by macOS
Archive Utility. It is packaging noise, not part of the challenge.

```bash
unzip final_koby_challenge.png.zip
file final_koby_challenge.png
shasum -a 256 final_koby_challenge.png
```

```text
final_koby_challenge.png: PNG image data, 365 x 547, 8-bit/color RGB, non-interlaced
3c7dcb3d8734049fa2dbf7a522fb690b981f0fef1038870b076e1298a5009ec1
```

An 8-bit RGB, non-interlaced image is the friendliest possible case for
bit-plane analysis later: three bytes per pixel, no palette indirection, no
Adam7 de-interlacing, and no alpha channel that tools might strip.

`binwalk` immediately reports the important structural fact:

```bash
binwalk final_koby_challenge.png
```

```text
DECIMAL     HEXADECIMAL   DESCRIPTION
--------------------------------------------------------------------
0           0x0           PNG image, total size: 181154 bytes
181154      0x2C3A2       ZIP archive, file count: 1, total size: 229 bytes
```

The PNG proper is 181,154 bytes, but the file on disk is 181,383 bytes. There
are 229 bytes of trailing data, and they begin with a ZIP local file header.

## 2. Verifying the PNG Is Not Actually Damaged

Before chasing the trailer it is worth disproving the challenge's own premise.
A PNG is a sequence of chunks, each laid out as:

```text
[4-byte big-endian length][4-byte type][length bytes of data][4-byte CRC32]
```

The CRC is computed over the *type and data*, not over the length field.
Walking the chunk list and recomputing each CRC gives:

```text
off=       8  type=IHDR  len=      13  crc=OK
off=      33  type=tEXt  len=      15  crc=OK
off=      60  type=tEXt  len=      29  crc=OK
off=     101  type=eXIf  len=     206  crc=OK
off=     319  type=IDAT  len=   65536  crc=OK
off=   65867  type=IDAT  len=   65536  crc=OK
off=  131415  type=IDAT  len=   49715  crc=OK
off=  181142  type=IEND  len=       0  crc=OK
IEND ends at offset 181154; trailing bytes: 229
```

Every chunk validates. There is no truncated IDAT, no corrupted CRC, no
swapped chunk type, and no height/width tampering in `IHDR`. This rules out
the entire family of "repair the PNG header" techniques and confirms the
trailing 229 bytes are the actual payload.

Note also that `IEND` carries a zero-length payload, so its CRC is a constant
(`0xAE426082`) for every valid PNG. Its presence at offset 181,142 is the clean
boundary between the image and the appended archive.

## 3. Carving the Appended ZIP

Everything from offset 181,154 onward is a self-contained ZIP:

```bash
dd if=final_koby_challenge.png of=trailing.zip bs=1 skip=181154
unzip -l trailing.zip
```

```text
  Length      Date    Time    Name
---------  ---------- -----   ----
       35  07-19-2026 11:02   flag.txt
```

Parsing the local file header by hand is what tells us how to attack it:

```text
504b0304 0a00 0900 0000 4488f35c 1854f221 2f000000 23000000 0800 1c00 666c61672e747874
         └ver └flag└mth └mtime   └crc32   └csize   └usize   └nlen└elen└"flag.txt"
```

| Field | Value | Meaning |
| --- | --- | --- |
| Version needed | `0x000a` (1.0) | Very old writer profile |
| General purpose flags | `0x0009` | **bit 0 set** = encrypted; bit 3 set = data descriptor follows |
| Compression method | `0` | **Stored** — no deflate |
| CRC-32 | `0x21f25418` | Checksum of the *plaintext* |
| Compressed size | `47` | 35 plaintext bytes + 12-byte encryption header |
| Uncompressed size | `35` | The flag, including trailing newline |

Two details matter for the rest of the solve:

- **Bit 0 without bit 6** means classic ZipCrypto, not AES. ZipCrypto is a
  stream cipher keyed by three 32-bit registers seeded from the password.
- **Method 0 (stored)** means the ciphertext maps byte-for-byte onto the
  plaintext with no deflate layer in between. This is what makes a
  known-plaintext attack viable as a fallback (see
  [section 7](#7-fallback-path-known-plaintext-attack)).

The 12-byte prefix is ZipCrypto's encryption header, whose final byte is
checked against the high byte of the CRC. That check is only 8 bits wide, so
roughly 1 in 256 wrong passwords will pass it — a wrong password can survive
the header check and still produce garbage, which is why the CRC verification
in section 6 is the real proof of a correct decrypt.

## 4. Metadata Reconnaissance

The PNG carries two `tEXt` chunks and an `eXIf` chunk. These are read directly
by `exiftool`:

```bash
exiftool -a -u -g1 final_koby_challenge.png
```

```text
---- PNG ----
Artist                : MambaOut
Copyright             : Helicopter_Blackbox
---- GPS ----
GPS Latitude          : 34 deg 2' 34.80" N
GPS Longitude         : 118 deg 16' 2.28" W
```

Converted to decimal, the coordinates are `34.0430, -118.2673`. That is
Crypto.com Arena (formerly the Staples Center) in downtown Los Angeles — Kobe
Bryant's home court, not the Calabasas crash site. The location is thematic
rather than functional.

Every one of these strings is a plausible password, and all of them fail:

```bash
for pw in MambaOut Helicopter_Blackbox Mamba KobeBryant Blackbox 24 8; do
  7z x -p"$pw" -so trailing.zip 2>/dev/null && echo "hit: $pw"
done
```

No output. The metadata is set dressing that establishes the theme and tells
you *what* to look for, but the password itself is stored somewhere else.

## 5. Recovering the Password from the Pixels

This is the "reconstruct the scene" step. The password is not in the file's
byte stream — it is in the decoded raster, so it only becomes visible after
the IDAT chunks are concatenated, inflated, and un-filtered.

Rather than guessing a single embedding scheme, sweep the whole space. The
relevant degrees of freedom for LSB steganography are:

- **Channel selection**: R, G, B individually, plus interleaved RGB and BGR.
- **Bit plane**: bit 0 (least significant) through bit 2.
- **Bit order within a byte**: MSB-first or LSB-first.
- **Traversal order**: row-major or column-major.

That is 60 combinations. Extract each as a byte stream and grep for runs of
printable ASCII:

```python
from PIL import Image
import numpy as np, re

a = np.array(Image.open('final_koby_challenge.png').convert('RGB'))
printable = re.compile(rb'[ -~]{6,}')

for order, arr in (('row', a), ('col', a.transpose(1, 0, 2))):
    for cname, cidx in {'r': [0], 'g': [1], 'b': [2],
                        'rgb': [0, 1, 2], 'bgr': [2, 1, 0]}.items():
        sel = arr[:, :, cidx]
        for bit in range(3):
            plane = ((sel >> bit) & 1).reshape(-1).astype(np.uint8)
            n = (len(plane) // 8) * 8
            for msb in (True, False):
                grouped = plane[:n].reshape(-1, 8)
                if not msb:
                    grouped = grouped[:, ::-1]
                data = np.packbits(grouped, axis=1).tobytes()
                for m in printable.findall(data[:200000]):
                    print(f"[{order}/{cname}/bit{bit}/{'msb' if msb else 'lsb'}] {m[:60]!r}")
```

Most combinations return short, random-looking fragments. Exactly one returns
a clean English string, and it sits at offset 0 of its stream:

```text
[row/r/bit0/msb] b'SeeYouAgain1978'
```

Dumping the start of that specific stream confirms the embedding is
deliberate:

```text
b'SeeYouAgain1978\x00\xff\xff8\xdb\x1c\xdb\xff\x00\xffZ\xf1\x00\x0c\xc0\xa0e\x7f...'
```

The string is followed by a `0x00` terminator and then noise. So the payload is
a C-style NUL-terminated string occupying 16 bytes = **128 bits = the red LSBs
of the first 128 pixels**, which all lie in row 0 of a 365-pixel-wide image.
The green and blue planes contain only image noise.

`SeeYouAgain1978` is Kobe Bryant's birth year paired with the farewell phrase,
which fits the theme exactly.

### Why the surrounding noise looks structured

The LSB planes are full of `0x00` and `0xff` bytes. A packed byte of `0xff`
means eight consecutive pixels whose LSBs are all 1. This is normal for an
image that was originally JPEG-compressed and later re-saved as PNG: smooth
and saturated regions produce long runs of identical low bits.

This matters when interpreting scan results. A byte-signature sweep across all
24 bit planes reports several apparent JPEG SOI markers (`ff d8 ff`), and the
blue LSB plane even opens with `ff db 00 43 00`, which resembles a JPEG
quantization-table segment. All of these are coincidences — a 3-byte pattern
recurs by chance in 200 KB of structured noise, none appears at offset 0, and
none is followed by a decodable JPEG. There is no second stego layer.

## 6. Decrypting and Verifying

With the password recovered, the archive opens:

```bash
7z x -p"SeeYouAgain1978" -so trailing.zip
```

```text
THJCC{Man_BA_0ut_Seeyouaga1n_1978}
```

Because ZipCrypto's header check is only 8 bits wide, confirm the result
against the CRC-32 recorded in the local file header:

```bash
python3 -c "
import binascii
d = open('flag.txt','rb').read()
print('computed %08x' % (binascii.crc32(d) & 0xffffffff), 'expected 21f25418')
"
```

```text
computed 21f25418 expected 21f25418
```

The checksums match over all 35 bytes, so the decryption is correct rather
than merely header-plausible.

The flag reads as a layered pun: `Man_BA_0ut` splits "Mamba Out" — Kobe's
final-game farewell — so that it also contains the challenge title "Man!",
followed by the password's two components.

## 7. Fallback Path: Known-Plaintext Attack

Worth recording because it works even if the stego stage is never solved.
ZipCrypto is vulnerable to Biham–Kocher known-plaintext recovery, and this
entry is an ideal target:

- The entry is **stored**, so plaintext bytes map directly onto ciphertext
  bytes with no deflate layer to invert first.
- The flag format gives a guaranteed 6-byte prefix, `THJCC{`, at offset 0, and
  a `}` plus newline at the end.

`bkcrack` needs around 12 known bytes for a comfortable attack:

```bash
bkcrack -C trailing.zip -c flag.txt -p known_prefix.bin -o 0
```

This recovers the three internal keystream registers rather than the password
itself, which is enough to decrypt the entry. It was unnecessary here, but it
is the standard answer for a stored, ZipCrypto-protected entry with a known
flag format.

## 8. Automated Solver

[`solve.py`](solve.py) reproduces the full chain from the original handout and
has **no third-party dependencies** — it decodes the PNG with `zlib` and
decrypts ZipCrypto with the standard library `zipfile` module:

```bash
python3 solve.py
```

```text
[*] handout PNG: 181383 bytes
[*] walking PNG chunks
  chunk IHDR off=8       len=13      crc=ok
  chunk tEXt off=33      len=15      crc=ok
  chunk tEXt off=60      len=29      crc=ok
  chunk eXIf off=101     len=206     crc=ok
  chunk IDAT off=319     len=65536   crc=ok
  chunk IDAT off=65867   len=65536   crc=ok
  chunk IDAT off=131415  len=49715   crc=ok
  chunk IEND off=181142  len=0       crc=ok
[+] IEND ends at offset 181154; 229 trailing bytes
[+] appended ZIP: encrypted=True method=0 (0=stored)
[*] decoding pixels and reading red-channel LSBs
[+] image 365x547; recovered password: SeeYouAgain1978
[+] CRC32 expected=21f25418 computed=21f25418 MATCH

flag: THJCC{Man_BA_0ut_Seeyouaga1n_1978}
```

The script implements the PNG defiltering step directly (None, Sub, Up,
Average and Paeth predictors), which is the part that "reconstructs the scene"
needed to read the hidden bits.

## Lessons

- **Verify the premise before repairing anything.** The prompt said the file
  was damaged; recomputing all eight chunk CRCs disproved that in seconds and
  redirected effort to the trailer.
- **`IEND` is a boundary, not an end-of-file.** Anything after it is
  unreferenced by decoders and is a standard place to smuggle data.
- **Metadata often supplies the theme rather than the secret.** `MambaOut`,
  `Helicopter_Blackbox`, and the GPS tag all narrow the guess space without
  ever being the answer.
- **Sweep the stego parameter space instead of guessing.** Channel, bit plane,
  bit order and traversal order are only 60 combinations; brute-forcing them
  is faster and more reliable than trying one scheme at a time.
- **Confirm a ZipCrypto decrypt with the CRC-32.** The built-in header check
  is 8 bits wide and passes on roughly 1 in 256 wrong passwords.

## Flag

```text
THJCC{Man_BA_0ut_Seeyouaga1n_1978}
```
