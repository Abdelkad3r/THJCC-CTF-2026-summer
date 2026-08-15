# Because There is no one Make Reverse So I Create This Chal

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Reverse Engineering |
| Points | 100 |
| Author | LemonTea |
| Handout | [`artifacts/chal.zip`](artifacts/chal.zip) |
| Flag | `THJCC{1_w0nd3r_h0w_l0n6_41_50lv35_17_>w<}` |

## Overview

The handout contains a stripped ARM64 Mach-O executable. At first glance, the
program appears small: it reads a candidate flag and eventually prints either
`Correct!` or `Nope.`. The actual verification logic is not present as ordinary
native comparisons. Instead, the executable decrypts an embedded bytecode
payload and executes it with a custom virtual machine.

The solution therefore has three parts:

1. Recover the key used to generate the payload keystream.
2. Decrypt and understand the custom VM program.
3. Invert each VM check to recover the required input.

## 1. Initial Triage

After extracting the archive, identify the binary and calculate a hash:

```bash
unzip chal.zip
file chal/chal
shasum -a 256 chal/chal
```

The result is:

```text
chal: Mach-O 64-bit executable arm64
c85cd9cdfb4b18d651f51f7f171ce9eceba7197f660e5eaea180db6482766951
```

The binary is PIE, stripped, and protected with a stack canary. Its imports are
limited to basic memory and standard input/output functions such as `malloc`,
`free`, `fgets`, `puts`, and `strcspn`. Useful strings include:

```text
flag>
No input.
Nope.
Payload error.
Correct!
```

Because there are no cryptographic library imports, the payload decryption and
flag verification must both be implemented inside the executable.

## 2. Locating the Encrypted Payload

The entry function reads at most `0x101` characters, removes the trailing
newline, and allocates `0x2c4` bytes. It then processes data from the Mach-O
`__const` section beginning at virtual address `0x100000b98`, which is also file
offset `0xb98`.

The important constants are:

```text
payload offset = 0x0b98
payload size   = 0x02c4 (708 bytes)
XTEA delta     = 0x9e3779b9
```

Before the payload loop, the function at `0x100000ab0` constructs a 16-byte key
by XORing two adjacent constant arrays:

```text
binary[0xe5c:0xe6c] XOR binary[0xe6c:0xe7c]
```

This yields the following little-endian 32-bit words:

```text
2580f501 d194e025 9f48ceeb 05488ea6
```

## 3. Reproducing the XTEA Keystream

The native loop is the standard 32-round XTEA encryption structure. It does not
decrypt the embedded bytes directly. For each eight-byte block, it encrypts a
predictable pair of words and XORs the resulting eight bytes with the embedded
payload.

For block index `i`, the initial values are:

```text
v0 = 0xafd9e340 + i
v1 = 0x1e403058
sum = 0
```

The round operation is:

```python
v0 += ((((v1 << 4) ^ (v1 >> 5)) + v1)
       ^ (sum + key[sum & 3]))
sum += 0x9e3779b9
v1 += ((((v0 << 4) ^ (v0 >> 5)) + v0)
       ^ (sum + key[(sum >> 11) & 3]))
```

All arithmetic is truncated to 32 bits. Packing the final `v0` and `v1` as
little-endian words produces the keystream for that block.

The binary verifies the decrypted payload using FNV-1a. Reproducing the same
calculation gives:

```text
FNV-1a-32(decrypted_payload) = 0x4b9fb9f7
```

This is a useful checkpoint: if this hash does not match, the key derivation,
XTEA arithmetic, or byte order is wrong.

## 4. Reversing the Custom VM

After the integrity check, the entry function calls the interpreter at
`0x1000008dc`. The VM maintains an eight-bit accumulator, an input cursor, a
program counter, and a failure accumulator. It also limits execution to
`0x589` instructions.

The decoded instruction set is:

| Opcode | Instruction | Behavior |
| ---: | --- | --- |
| `0x15` | `XOR imm8` | XOR the accumulator with the operand. |
| `0x18` | `ADD imm8` | Add the operand to the accumulator. |
| `0x5a` | `HALT` | Accept only if no comparison has failed. |
| `0x5b` | `SKIP imm8` | Skip dead bytes used as obfuscation. |
| `0x74` | `ROL imm8` | Rotate the low accumulator byte left by 1-7 bits. |
| `0x86` | `LOAD` | Load the selected input byte into the accumulator. |
| `0x8f` | `CHECK imm8` | OR `accumulator XOR operand` into the failure value. |
| `0x97` | `INDEX imm8` | Select an input position. |
| `0xcd` | `LENGTH imm8` | Compare the candidate length with the operand. |
| `0xe5` | `SUB imm8` | Subtract the operand from the accumulator. |

`LOAD` and `HALT` are one-byte instructions; the others consume an additional
operand byte. Recognizing that `LOAD` has no operand is important. Treating the
following opcode as its operand immediately desynchronizes the disassembly.

The first real instruction checks that the input length is `0x29`, so the flag
has exactly 41 bytes. The bytecode then repeatedly performs this pattern:

```text
INDEX position
LOAD
one or more XOR/ADD/SUB/ROL transformations
CHECK expected_byte
```

The `SKIP` opcode jumps over random-looking dead bytes between some checks. They
are never executed and exist only to make a raw byte dump harder to read.

## 5. Recovering the Flag

Every check operates on one input byte independently. There is no need to solve
all 41 bytes simultaneously. For each `INDEX` block, try all values from 0 to
255, emulate the accumulator operations, and retain the value that satisfies
the `CHECK` instruction.

The included solver performs the complete process:

```bash
python3 solve.py
```

Expected output:

```text
key: 2580f501 d194e025 9f48ceeb 05488ea6
payload fnv1a32: 4b9fb9f7
instructions: 347
flag: THJCC{1_w0nd3r_h0w_l0n6_41_50lv35_17_>w<}
verified: True
```

The final line comes from running the recovered candidate through a faithful
Python implementation of the VM, rather than merely printing the reconstructed
bytes.

## Flag

```text
THJCC{1_w0nd3r_h0w_l0n6_41_50lv35_17_>w<}
```
