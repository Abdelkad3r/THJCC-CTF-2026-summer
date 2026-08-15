# License

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Reverse Engineering |
| Points | 184 |
| Author | hsuan0223x |
| Artifact | [`artifacts/license_v2`](artifacts/license_v2) |
| Valid license | `A9F3-1C7D-EE42-0B6A-5D91-7F20` |
| Flag | `THJCC{license_pipeline_rebuilt}` |

## Overview

The challenge provides a small stripped x86-64 Linux ELF implementing a custom
license verifier. A valid argument consists of 24 hexadecimal characters split
into six four-character groups. The verifier permutes and transforms those
characters into a 24-byte state, applies four neighbor-mixing rounds, and
compares the result with 24 embedded constants.

The four rounds look expensive because the compiler vectorizes part of the
pipeline with SSE instructions. At the byte level, however, each round is a
rotation of an XOR relation between state positions `i` and `(i + 7) mod 24`.
Since 7 and 24 are coprime, the relation forms one cycle and can be inverted by
trying only one seed byte. Reversing all rounds and enforcing the hexadecimal
alphabet leaves exactly one license.

After validation, a separate rolling-XOR decoder reveals the flag.

## 1. Initial Triage

Identify the artifact and preserve its hash:

```bash
file license_v2
shasum -a 256 license_v2
```

```text
license_v2: ELF 64-bit LSB executable, x86-64, statically linked, stripped
777e6278d52c9222c404d75cb75bc45327ffeff9d69e5efeacf51b5cd99f4e03
```

The file is only 3,608 bytes. Its relevant sections are:

```text
.rodata  VMA 0x200120, size 0x10f
.text    VMA 0x201230, size 0xa63
entry    0x201c74
```

Visible strings reveal only the interface:

```text
invalid license
usage: %s <license>
```

Like the earlier `404` challenge, this executable is statically linked and
uses raw Linux system calls instead of libc.

## 2. Recovering the License Format

The checker first counts the candidate string, including its terminating NUL:

```asm
cmp byte [rsi + rax], 0
lea rax, [rax + 1]
jne ...
cmp rax, 0x1e
```

Therefore the visible license must contain 29 characters:

```text
29 characters + NUL = 0x1e bytes
```

The next loop uses multiplication by `0xcccccccccccccccd` to calculate division
by five. It requires a hyphen whenever the string index is congruent to four
modulo five:

```text
positions 4, 9, 14, 19, and 24 = '-'
```

All other characters must be one of:

```text
0-9, A-F, or a-f
```

This establishes the format:

```text
XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
```

The checker calculates numeric nibble values while validating the alphabet,
but stores the original ASCII characters in its 24-byte input buffer.

## 3. Recognizing the Checksum Decoy

At `0x201398`, the binary initializes a 32-bit accumulator with `0x31415926`,
mixes all 24 ASCII characters into it, and rotates the accumulator after every
operation. This looks like an important license checksum.

Immediately after the loop, however, the code does this:

```asm
mov eax, dword [rsp - 0x50]
xor eax, eax
```

The computed checksum is loaded and then discarded before any comparison or
later use. It is deliberate noise and imposes no constraint on the license.

## 4. Reconstructing the Preprocessing Layer

The 24-byte permutation at `.rodata` address `0x2001f0` is:

```text
07 00 13 04 0c 17 02 10 09 05 15 0b
01 0e 12 06 14 03 0f 0a 08 16 0d 11
```

The first 16 positions are gathered and transformed using SSE. The remaining
eight are emitted by scalar instructions, but both paths implement the same
formula. Let `raw` be the 24 license characters with hyphens removed, and let
`P` be the permutation above:

```text
state[i] = (
    ROL8(raw[P[i]] XOR ((0x31 + 17*i) mod 256), i mod 5)
    + 11*i
) mod 256
```

This equation is independently invertible for each byte:

```text
raw[P[i]] = ROR8((state[i] - 11*i) mod 256, i mod 5)
            XOR ((0x31 + 17*i) mod 256)
```

## 5. Simplifying the Four Mixing Rounds

The compiler expands each round into arithmetic that calculates modulo seven,
selects one byte from a 32-bit constant, rotates bytes, and handles the
24-element wraparound. Translating the assembly back to byte operations gives:

```text
next[i] = ROL8(
    state[i]
    XOR state[(i + 7) mod 24]
    XOR ((i + offset[r]) mod 256)
    XOR byte(constant[r], i mod 4),
    (i + r) mod 7
)
```

The round parameters are:

| Round `r` | Constant | Offset |
| ---: | ---: | ---: |
| 0 | `0x13579bdf` | `0x00` |
| 1 | `0x2468ace0` | `0x1d` |
| 2 | `0x0badf00d` | `0x3a` |
| 3 | `0x55aa55aa` | `0x57` |

`byte(constant, i mod 4)` selects the constant in little-endian byte order.

After four rounds, the verifier expects:

```text
95 54 0c 2f 5a c7 a9 9f bc a4 9a d2
96 c3 2d 88 3a 57 8b ad 1d 2f 2b 46
```

## 6. Inverting a Round

Undo the rotation and known constants for each output byte:

```text
d[i] = ROR8(next[i], (i + r) mod 7)
       XOR ((i + offset[r]) mod 256)
       XOR byte(constant[r], i mod 4)
```

The remaining equation is simply:

```text
d[i] = state[i] XOR state[(i + 7) mod 24]
```

Because `gcd(7, 24) = 1`, repeatedly adding seven visits every index exactly
once before returning to zero. Choose `state[0]`, propagate around that cycle,
and ensure the final equation returns to the chosen seed.

Only 256 seed values are possible. Reversing each round and retaining states
that satisfy the preceding round's cycle invariant produces:

```text
after inverse round 4:    256 states
after inverse round 3:  1,024 states
after inverse round 2:  2,048 states
after inverse round 1: 16,384 states
```

This is tiny compared with enumerating all 24 hexadecimal characters.

## 7. Recovering the Unique License

Invert the preprocessing equation for each of the 16,384 pre-round states.
Most candidates immediately produce bytes outside the accepted hexadecimal
alphabet. Exactly one state maps entirely to valid hex characters:

```text
A9F31C7DEE420B6A5D917F20
```

Reinsert a hyphen after every four characters:

```text
A9F3-1C7D-EE42-0B6A-5D91-7F20
```

Forward evaluation gives these intermediate states:

```text
preprocess: 75119fcb80ede5c33ffb0b369750fcac9c40d7d59c3089e4
round 1:   6969c486d69c392b88d7b09f32969572defd3849273e4a14
round 2:   7f4d23231108e47dfc1c2075ac37d1c03861c26670ec36e9
round 3:   d4d3eaa6d56b7c9b9b79157e81e163a569b49b0320091e75
round 4:   95540c2f5ac7a99fbca49ad296c32d883a578bad1d2f2b46
```

The final line exactly matches all 24 comparison constants.

## 8. Decoding the Flag

The success path at `0x201bc3` reads 31 bytes beginning at `.rodata` address
`0x200210`:

```text
25 36 c1 db e6 c9 d3 a5 ba 83 9d 73 68 45 57 5d
31 2b 37 01 1b e7 d0 ee cc d4 b6 b9 b1 9e 8a
```

It processes two bytes per iteration with a rolling byte initialized to
`0x7e`:

```text
plain[i]     = encrypted[i]     XOR ((rolling - 0x0d) mod 256)
plain[i + 1] = encrypted[i + 1] XOR rolling
rolling      = (rolling + 0x1a) mod 256
```

The final iteration contains only the first equation because the flag length
is odd. The plaintext is:

```text
THJCC{license_pipeline_rebuilt}
```

## 9. Automated Solver

The included [`solve.py`](solve.py) uses only the Python standard library. It:

1. Parses the ELF64 section table.
2. Extracts the permutation and encrypted flag table from `.rodata`.
3. Reverses all four neighbor-XOR rounds algebraically.
4. Inverts the preprocessing layer for every candidate state.
5. Applies the hexadecimal-character constraint and requires uniqueness.
6. Re-runs the complete forward pipeline against the 24-byte target.
7. Decrypts the flag using the native success-handler algorithm.

Run it from the challenge directory:

```bash
python3 solve.py --verbose
```

Expected output:

```text
after inverse round 4: 256 states
after inverse round 3: 1024 states
after inverse round 2: 2048 states
after inverse round 1: 16384 states
pre-round candidates: 16384
hex-valid licenses: 1
license: A9F3-1C7D-EE42-0B6A-5D91-7F20
target verified: True
flag: THJCC{license_pipeline_rebuilt}
```

On x86-64 Linux, the recovered key can also be tested against the original
binary:

```bash
chmod +x artifacts/license_v2
./artifacts/license_v2 A9F3-1C7D-EE42-0B6A-5D91-7F20
```

```text
THJCC{license_pipeline_rebuilt}
```

## Flag

```text
THJCC{license_pipeline_rebuilt}
```
