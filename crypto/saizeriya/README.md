# お昼はサイゼリヤに行こうニャ！

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Cryptography |
| Points | 100 |
| Author | MaZon |
| Handout | [`artifacts/chal.zip`](artifacts/chal.zip) |
| Flag | `THJCC{46Z-WQv_vFc}` |

## Overview

The challenge title translates roughly to "Let's go to Saizeriya for lunch,
nya!" The handout describes a missing note containing four numeric seeds. The
remaining materials are the original table-generation script, a large packed
rainbow table, five resident password hashes, and an authenticated encrypted
flag.

The solution has three distinct stages:

1. Reconstruct the four numeric seeds from the note and character information.
2. Use the supplied rainbow table to invert five custom 40-bit password hashes.
3. Derive the final key, verify the HMAC, and decrypt the flag.

The main engineering difficulty is the second stage. A direct Python
implementation would require hundreds of millions of custom hash operations per
target. The included solution uses an optimized multithreaded C++ inverter and
a compact reverse index for the bit-packed table.

## 1. Handout Contents

The archive contains:

```text
README.md
gen_table.py
shadow.txt
nyan.tbl
flag.enc
note.png
note.txt
```

The original ZIP has SHA-256:

```text
fe06872b7449089f03312c5ece1046cec2fec1d4c73b1e7664af3ccc68cb3d74
```

`gen_table.py` completely documents the custom hash, reduction function, table
format, key derivation, and flag encryption. Only the four values `K1` through
`K4` have been erased.

## 2. Recovering the Four Seeds

The text version of the note fixes the order and identity of each seed:

```text
K1 = Yaniko's age
K2 = Yakuko's age
K3 = Aruko's age
K4 = Hameko's subscriber count
```

The [official Yani Neko character page](https://yanineko-anime.com/) gives the
three ages:

```text
Yaniko = 21
Yakuko = 20
Aruko  = 24
```

The screenshot transcribed in `note.txt` shows:

```text
チャンネル登録者数 10.8万人
```

`10.8万人` means 108,000 subscribers, giving:

```python
K = (21, 20, 24, 108000)
```

### Verifying the Seeds

The guessed values can be checked against `nyan.tbl` without attempting any
password recovery. Chain zero begins with `idx_to_pw(0)`, or fourteen `y`
characters. Walking it for 24,576 steps with the recovered seeds gives:

```text
full endpoint: niokiyiknakyyy
stored 8-character endpoint value: 1264664
calculated endpoint value:          1264664
```

This exact match confirms all four seed values before the expensive inversion
stage begins.

## 3. Understanding the Password Space

Passwords have length 14 and use only six characters:

```python
CHARSET = "yaniko"
PWLEN = 14
```

The total search space is:

```text
N = 6^14 = 78,364,164,096
```

`yani40()` maintains four 32-bit state words, processes the password for three
passes, performs four final mixing rounds, and returns five bytes. Its output is
therefore a 40-bit hash.

Directly enumerating almost 78.4 billion passwords is not practical. The
provided table is a time-memory tradeoff intended to invert hashes from this
space.

## 4. How the Rainbow Chains Work

The table parameters are:

```text
chain length = 24,576
chain count  = N / 24,576 = 3,188,646
```

Chain `c` starts at `idx_to_pw(c)`. At position `i`, the next password is:

```text
password_(i+1) = reduce_at(yani40(password_i), i)
```

The reduction depends on the position. This prevents every column from using
the same mapping and makes the construction a rainbow table rather than a
single-reduction Hellman table.

Only the first eight characters of each final endpoint are stored. Those eight
base-6 digits represent a value in the range `0` through `6^8-1`:

```text
6^8 = 1,679,616
bits per endpoint = ceil(log2(6^8)) = 21
```

The values are packed consecutively in little-endian bit order. The expected
table size is:

```text
ceil(3,188,646 * 21 / 8) = 8,370,196 bytes
```

This exactly matches `nyan.tbl`.

## 5. Building a Reverse Endpoint Index

The table is stored in chain-start order. During inversion, we instead need to
find every chain whose truncated endpoint equals a calculated value.

The C++ solver builds a compact counting-sort index:

1. Decode every 21-bit endpoint and count each value.
2. Convert counts into prefix offsets.
3. Make a second pass and place each chain ID into a contiguous array.

For endpoint value `v`, all matching chain IDs are then found in:

```text
chain_ids[offsets[v] : offsets[v+1]]
```

The index uses flat `uint32_t` arrays rather than millions of map or list
objects. Its main storage is about 13 MB for chain IDs plus 7 MB for offsets.

## 6. Inverting One Shadow Hash

Suppose a target hash `h` was produced by a password at unknown chain position
`j`. Try every possible position from the end of the chain toward the start.

For one assumed position `j`, calculate the endpoint that would follow `h`:

```text
p = reduce_at(h, j)

for i = j+1 through CHAIN_LEN-1:
    p = reduce_at(yani40(p), i)
```

The first eight characters of `p` identify candidate chain IDs through the
reverse index. Because the table stores truncated endpoints, unrelated chains
can share the same stored value. Each candidate chain must therefore be replayed
from its known start:

```text
p = idx_to_pw(chain_id)

for i = 0 through j:
    if yani40(p) == target:
        return p
    p = reduce_at(yani40(p), i)
```

Trying all positions has quadratic worst-case chain-walking cost. The solver
uses native 32-bit arithmetic, `-O3`, and all available CPU cores. Workers claim
possible positions from an atomic counter and stop as soon as a valid preimage
is found.

On the system used for this solve, all five targets were recovered in about 49
seconds.

## 7. Recovered Resident Passwords

The five entries in `shadow.txt` invert to:

```text
yaniko:yaayniiakyiiyo
yakuko:yiyyyanooonaik
hameko:inaiyoiykiokyo
kaoruko:akoyayaknakikk
aruko:nakoynnkiyoaaa
```

The Python driver recalculates `yani40()` for every recovered password and
checks it against the supplied five-byte shadow. This ensures the native lookup
did not return an unverified endpoint candidate.

## 8. Deriving and Verifying the Final Key

`gen_table.py` fixes the resident order:

```python
RESIDENTS = ["yaniko", "yakuko", "hameko", "kaoruko", "aruko"]
```

Join the passwords in that order with vertical bars and hash the result:

```python
key = sha256("|".join(plaintexts).encode()).digest()
```

This produces:

```text
84c5152980a504dcfd178fa71baf54b0a8e2522e64a6c73952cc4eeb818dbf32
```

`flag.enc` consists of a 16-byte authentication tag followed by ciphertext:

```text
tag = HMAC-SHA256(key, b"YANI-TAG" + ciphertext)[:16]
```

The supplied and recalculated tags are identical:

```text
9ced667a7ae95708c51e92cad86dc15d
```

This authentication check proves that the recovered passwords and their order
are correct.

## 9. Decrypting the Flag

The ciphertext is XORed with a SHA-256 counter-mode keystream. Counter block
`ctr` is:

```python
sha256(key + b"YANI-CTR" + ctr.to_bytes(4, "big")).digest()
```

XORing the ciphertext with that stream yields:

```text
THJCC{46Z-WQv_vFc}
```

## 10. Reproducing the Solve

The repository includes:

- `crack.cpp`: the optimized rainbow-table inverter.
- `solve.py`: compilation, hash verification, key derivation, HMAC checking,
  and final decryption.

A C++17 compiler and Python 3 are required. Run:

```bash
python3 solve.py
```

The driver compiles the C++ program into a temporary directory, so no
machine-specific executable is left in the repository.

Expected final output:

```text
yaniko:yaayniiakyiiyo
yakuko:yiyyyanooonaik
hameko:inaiyoiykiokyo
kaoruko:akoyayaknakikk
aruko:nakoynnkiyoaaa
key: 84c5152980a504dcfd178fa71baf54b0a8e2522e64a6c73952cc4eeb818dbf32
HMAC verified: True
flag: THJCC{46Z-WQv_vFc}
```

## Flag

```text
THJCC{46Z-WQv_vFc}
```
