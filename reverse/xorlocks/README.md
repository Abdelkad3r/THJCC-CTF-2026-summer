# xorlocks

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Reverse Engineering |
| Points | 100 |
| Author | hsuan0223x |
| Artifact | [`artifacts/xorlock`](artifacts/xorlock) |
| Flag | `THJCC{xor_basics_are_not_magic}` |

## Overview

The challenge provides a very small, statically linked x86-64 Linux executable.
It accepts a password as its only command-line argument. An incorrect candidate
prints `access denied`, while the correct password reaches a second decoder that
constructs and prints the actual flag.

The checker uses two independent XOR-based transformations:

1. A 20-byte table validates the command-line password.
2. A 31-byte table in the success branch decrypts the flag.

This distinction matters because the password itself is not the submitted flag.

## 1. Initial Triage

Start by identifying the file and recording its hash:

```bash
file xorlock
shasum -a 256 xorlock
```

```text
xorlock: ELF 64-bit LSB executable, x86-64, statically linked, stripped
99bd67f0782e97865279e4bd2f8613199db96f958f98e2e8c4bbbc493747e48b
```

The file is only 1,256 bytes. Its relevant sections are equally small:

```text
.rodata  file offset 0x120, size 0x6f
.text    file offset 0x190, size 0x1d3
```

The visible strings are limited to:

```text
access denied
usage: %s <password>
```

There are no imported functions and no dynamic linker. The program performs
input handling and output with raw Linux syscalls, so all verification logic is
contained in the short `.text` section.

## 2. Finding the Main Checker

The ELF entry point is `0x201344`. It reads `argc` and `argv` directly from the
initial stack and calls the main checker at `0x201190`:

```asm
0x201344  xor  rbp, rbp
0x201347  mov  rdi, qword [rsp]       ; argc
0x20134b  lea  rsi, [rsp + 8]         ; argv
0x201354  call 0x201190
```

The checker first requires exactly two arguments: the executable name and one
password. It then computes the password length manually.

The length loop increments `rcx` after testing each byte, including the final
NUL terminator. It compares the result with `0x15`, which means the password
itself must contain 20 bytes:

```text
20 password bytes + 1 NUL byte = 0x15
```

## 3. Reversing the Password Check

The password-validation loop begins at `0x2011d0`. For every position `i`, it
loads one password byte, XORs it with `0x5a`, adds a rolling value, and compares
the result with a byte in `.rodata`:

```asm
movzx esi, byte [rax + rdx]          ; password[i]
xor   sil, 0x5a
add   sil, cl
movzx edi, byte [rdx + 0x200150]     ; table[i]
cmp   sil, dil
add   cl, 3
```

Since `cl` starts at zero and increases by three after every successful byte,
the check can be written as:

```text
table[i] = ((password[i] XOR 0x5a) + 3*i) mod 256
```

Inverting it gives:

```text
password[i] = ((table[i] - 3*i) mod 256) XOR 0x5a
```

The 20-byte table is stored at virtual address `0x200150`, which corresponds to
file offset `0x150`:

```text
22 38 2e 0e 43 4e 17 48 54 20 41 56 53 2c 63 68 64 38 9e a5
```

Applying the inverse transformation recovers:

```text
xor_me_if_you_can_26
```

## 4. Decoding the Hidden Flag

Passing the password check does not print the password or a generic success
message. Instead, execution enters a second loop beginning at `0x2011fd`. This
loop decodes 31 bytes from the table at virtual address `0x200170`, or file
offset `0x170`:

```text
67 08 07 19 24 0f f9 e1 e9 f7 d7 a3 bc b5 8a 85
5c 71 6f 4f 68 2a 3e 2a 34 15 e4 f5 f6 cf c4
```

The loop processes two output bytes at a time. Let `i` be the output index and
define the rolling byte as:

```text
cl = (0x40 + 0x1a * floor(i / 2)) mod 256
```

Even and odd positions use slightly different XOR keys:

```text
flag[i] = table[i] XOR (cl - 0x0d)   when i is even
flag[i] = table[i] XOR cl            when i is odd
```

The final iteration emits only the even-position byte, producing a 31-character
string. The program appends a NUL terminator and writes the result directly to
standard output with syscall number 1 (`write`).

Decoding the complete table gives:

```text
THJCC{xor_basics_are_not_magic}
```

## 5. Automated Solver

The included solver reads both tables directly from the provided ELF, applies
the inverse transformations, and independently checks the recovered password:

```bash
python3 solve.py
```

Expected output:

```text
password: xor_me_if_you_can_26
password verified: True
flag: THJCC{xor_basics_are_not_magic}
```

For an end-to-end test on Linux:

```bash
chmod +x artifacts/xorlock
./artifacts/xorlock xor_me_if_you_can_26
```

```text
THJCC{xor_basics_are_not_magic}
```

## Flag

```text
THJCC{xor_basics_are_not_magic}
```
