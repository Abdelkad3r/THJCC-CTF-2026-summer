# 404

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Reverse Engineering |
| Points | 100 |
| Author | hsuan0223x |
| Artifact | [`artifacts/404`](artifacts/404) |
| Required input | `vm_is_not_magic!` |
| Flag | `THJCC{vm_bytecode_is_a_contract}` |

## Overview

The challenge provides a tiny stripped x86-64 Linux ELF. It accepts one
16-byte command-line argument but rejects ordinary guesses with
`vm rejected input`.

The binary implements an eight-opcode virtual machine. At runtime it copies 18
separate 16-byte pieces from `.rodata` into a 288-byte stack buffer, appends a
final success opcode, and interprets the resulting 289-byte program. The VM
checks each input byte independently using XOR, addition, rotation, comparison,
and assertion instructions.

Rebuilding the bytecode and inverting those operations recovers the required
input. The VM's success opcode then decrypts a separate 32-byte table to print
the actual flag.

## 1. Initial Triage

Identify the handout and preserve its hash:

```bash
file 404
shasum -a 256 404
```

```text
404: ELF 64-bit LSB executable, x86-64, statically linked, stripped
1582f806dc958ba7bfab2796327609e92bec4be1ee19dfdfa337e0534bb7e37e
```

The file is only 2,104 bytes. Its meaningful sections are similarly small:

```text
.rodata  virtual address 0x200120, file offset 0x120, size 0x1af
.text    virtual address 0x2012d0, file offset 0x2d0, size 0x3e3
entry    0x201694
```

The visible strings reveal the interface but not a password or flag:

```bash
strings -a -n 4 404
```

```text
vm rejected input
usage: %s <16-byte input>
```

The program is statically linked because it does not need libc. It prints with
the raw Linux `write` syscall and exits with the raw `exit` syscall.

## 2. Input-Length Validation

The main routine at `0x2012d0` requires exactly two arguments. It then counts
bytes in `argv[1]` with this loop:

```asm
0x2012f0  cmp byte [rax + rcx], 0
0x2012f4  lea rcx, [rcx + 1]
0x2012f8  jne 0x2012f0
0x2012fa  cmp rcx, 0x11
```

The counter is incremented even when the current byte is the NUL terminator.
Consequently, `rcx == 0x11` means:

```text
16 input bytes + 1 NUL terminator = 17 bytes
```

Any other length goes directly to the rejection message.

## 3. Locating the VM State

After the length check, the routine allocates `0xc0` bytes on the stack. Two
adjacent regions matter:

```text
[rsp - 0x78, rsp - 0x71]  eight one-byte VM registers
[rsp - 0x70, rsp + 0xb0]  289-byte VM program
```

The register bank is initialized to zero. The bytecode buffer is populated by
18 `movaps` copies, but the source addresses are deliberately not in ascending
order:

```text
0x2001c0, 0x2001b0, 0x200160, 0x200150,
0x200120, 0x200130, 0x200180, 0x2001e0,
0x200190, 0x2001f0, 0x200210, 0x200220,
0x200140, 0x200200, 0x200230, 0x200170,
0x2001a0, 0x2001d0
```

Each source contributes 16 bytes:

```text
18 chunks * 16 bytes = 288 bytes
```

The binary then writes byte `0x07` at offset `0x120`, producing a total program
length of `0x121`, or 289 bytes. Reading `.rodata` linearly therefore gives a
scrambled program; the copy order above must be respected.

## 4. Mapping the Opcodes

The interpreter fetches a byte, subtracts one, verifies that the result is at
most seven, and dispatches through the jump table at `0x200240`:

```asm
movzx r9d, byte [program + pc]
dec   r9d
cmp   r9d, 7
ja    reject
jmp   qword [r9*8 + 0x200240]
```

Reversing the eight handlers gives the following instruction set:

| Opcode | Size | Semantics |
| ---: | ---: | --- |
| `1` | 3 | `LOAD r[a], input[b]` |
| `2` | 3 | `XOR r[a], b` |
| `3` | 3 | `ADD r[a], b` modulo 256 |
| `4` | 3 | `ROL r[a], b` as an 8-bit value |
| `5` | 3 | `CMP r[a], b`; store the Boolean result |
| `6` | 3 | `ASSERT`; reject if the preceding comparison failed |
| `7` | 1 | Success handler and flag decoder |
| `8` | 2 | Relative bytecode jump modulo `0x121` |

The interpreter also limits execution to 4,096 iterations and rejects if the
program counter escapes the 289-byte bytecode buffer.

## 5. Reconstructing the Program

Once the chunks are placed in runtime order, the program has a very regular
shape. The first 18 bytes are:

```text
01 00 00    LOAD   r0, input[0]
02 00 20    XOR    r0, 0x20
03 00 07    ADD    r0, 0x07
04 00 00    ROL    r0, 0
05 00 5d    CMP    r0, 0x5d
06 00 00    ASSERT
```

The next 15 blocks use the same six-opcode sequence. Every block checks one
input position, and the final byte is opcode `7`. Although the VM implements a
jump instruction, this particular program is a straight-line sequence and
does not use opcode `8`.

For input position `i`, the constants follow these patterns:

```text
XOR key       = 0x20 + i
ADD key       = 0x07 + 3*i
rotation      = i mod 7
compare value = target[i]
```

The complete forward equation is:

```text
target[i] = ROL8(
    ((input[i] XOR (0x20 + i)) + (0x07 + 3*i)) mod 256,
    i mod 7
)
```

## 6. Inverting the Byte Checks

Each block is independent, so no brute force or symbolic execution is needed.
Reverse the operations in the opposite order:

```text
x        = ROR8(target[i], i mod 7)
x        = (x - (0x07 + 3*i)) mod 256
input[i] = x XOR (0x20 + i)
```

Applying this equation to all 16 blocks gives:

| `i` | XOR | ADD | ROL | Target | Input |
| ---: | ---: | ---: | ---: | ---: | :---: |
| 0 | `20` | `07` | 0 | `5d` | `v` |
| 1 | `21` | `0a` | 1 | `ac` | `m` |
| 2 | `22` | `0d` | 2 | `2a` | `_` |
| 3 | `23` | `10` | 3 | `d2` | `i` |
| 4 | `24` | `13` | 4 | `a6` | `s` |
| 5 | `25` | `16` | 5 | `12` | `_` |
| 6 | `26` | `19` | 6 | `58` | `n` |
| 7 | `27` | `1c` | 0 | `64` | `o` |
| 8 | `28` | `1f` | 1 | `f6` | `t` |
| 9 | `29` | `22` | 2 | `62` | `_` |
| 10 | `2a` | `25` | 3 | `63` | `m` |
| 11 | `2b` | `28` | 4 | `27` | `a` |
| 12 | `2c` | `2b` | 5 | `ce` | `g` |
| 13 | `2d` | `2e` | 6 | `9c` | `i` |
| 14 | `2e` | `31` | 0 | `7e` | `c` |
| 15 | `2f` | `34` | 1 | `84` | `!` |

The required 16-byte argument is therefore:

```text
vm_is_not_magic!
```

Forward evaluation produces the exact target sequence embedded in the
bytecode:

```text
5d ac 2a d2 a6 12 58 64 f6 62 63 27 ce 9c 7e 84
```

## 7. Reversing the Success Handler

Passing every assertion reaches opcode `7`, whose native handler begins at
`0x201615`. The handler reads 32 encrypted bytes from `.rodata` at `0x200280`:

```text
7c 7d 08 0c 1f 12 00 ee cf ff d3 c3 a1 b2 b1 8f
9d 5a 7b 6c 73 58 19 30 0f 03 0e f5 f5 c2 da c6
```

It processes two bytes at a time. Let `j` be the pair number and define:

```text
k = (0x35 + 0x1a*j) mod 256
```

The two plaintext bytes are:

```text
plain[2*j]     = encrypted[2*j]     XOR ((k - 0x0d) mod 256)
plain[2*j + 1] = encrypted[2*j + 1] XOR k
```

Decoding all 16 pairs yields:

```text
THJCC{vm_bytecode_is_a_contract}
```

The handler appends a NUL terminator and prints the string directly with the
Linux `write` syscall.

## 8. Automated Solver

The included [`solve.py`](solve.py) reproduces the complete analysis using only
the Python standard library. It:

1. Parses the ELF64 section table and locates `.rodata`.
2. Reads the 18 bytecode chunks in their runtime copy order.
3. Verifies the expected six-opcode pattern for every input block.
4. Inverts the XOR, addition, and rotation operations.
5. Emulates all eight VM opcodes and confirms that the recovered input reaches
   success.
6. Decrypts the success table with the handler's rolling-key algorithm.

Run it from the challenge directory:

```bash
python3 solve.py
```

Expected output:

```text
bytecode length: 289
input: vm_is_not_magic!
VM accepted: True
flag: THJCC{vm_bytecode_is_a_contract}
```

On an x86-64 Linux system, the original binary can also be tested directly:

```bash
chmod +x artifacts/404
./artifacts/404 'vm_is_not_magic!'
```

```text
THJCC{vm_bytecode_is_a_contract}
```

## Flag

```text
THJCC{vm_bytecode_is_a_contract}
```
