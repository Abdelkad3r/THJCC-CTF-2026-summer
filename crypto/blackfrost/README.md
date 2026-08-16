# BlackFrost

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Cryptography |
| Points | 498 |
| Author | hsuan0223x |
| Executable | [`artifacts/BlackFrost.exe`](artifacts/BlackFrost.exe) |
| Capture | [`artifacts/traffic.pcap`](artifacts/traffic.pcap) |
| Flag | `THJCC{blackfrost_config_recovered}` |

## Overview

BlackFrost provides a small Windows x86-64 executable and a two-packet network
capture. The program accepts a token, hashes it with FNV-1a, decrypts an
embedded configuration, connects to a local replay server, decrypts a second
configuration from the server response, and finally decodes an embedded flag.

The interesting detail is that the two configuration layers do not use the
same key. The accepted handshake value and captured traffic use `0xb700b632`,
while the configuration stored in the PE requires `0xa667d26f`. Running the
unmodified sample therefore stops at `stage unpack failed`. This mismatch is
deliberate evidence rather than a dead end: the PCAP reveals the expected
configuration format, which provides enough known plaintext to recover the
embedded key algebraically.

Once both layers are reconstructed, the success routine at `0x140001777`
contains a separate 34-byte rolling-XOR decoder. Reimplementing that routine
recovers the flag without executing an untrusted sample.

## 1. Safe Initial Triage

The challenge explicitly recommends a Windows sandbox. Treat the executable as
untrusted and begin with static inspection:

```bash
file BlackFrost.exe traffic.pcap
shasum -a 256 BlackFrost.exe traffic.pcap
```

```text
BlackFrost.exe: PE32+ executable (console) x86-64, for MS Windows
traffic.pcap:   pcap capture file, microsecond ts, Ethernet

1e010132501b16f34e7347fc06e7f69eb58b0acffe2b388e05ba6a9396b49007  BlackFrost.exe
9c56d24cb5d5d87c7e29e42552e375966cb5b4a66e5e0f4e8b3b347e8664bcf1  traffic.pcap
```

The PE is only 7,168 bytes and has two sections:

| Section | RVA | Raw offset | Raw size | Permissions |
| --- | ---: | ---: | ---: | --- |
| `.text` | `0x1000` | `0x400` | `0x1200` | Read/execute |
| `.rdata` | `0x3000` | `0x1600` | `0x600` | Read-only |

Its imports are narrowly scoped:

```text
kernel32.dll: ExitProcess, GetCommandLineA, GetStdHandle, GetTickCount,
              IsDebuggerPresent, VirtualAlloc, VirtualFree, WriteFile
ws2_32.dll:   WSAStartup, closesocket, connect, htons, inet_addr,
              recv, send, socket
```

Visible strings describe the expected execution stages:

```text
usage: BlackFrost.exe --token <token>
analysis mode disabled
sandbox timeout
C2 unavailable; start the local replay server
handshake rejected
stage unpack failed
configuration rejected
127.0.0.1
```

`IsDebuggerPresent` is called at `0x1400011a1`, and the program also rejects a
run that takes more than approximately three seconds. Static extraction avoids
both checks.

## 2. Reconstructing the PCAP Conversation

The capture contains two IPv4/TCP packets over loopback. Following the TCP
payload gives:

```text
client -> server
BFHELLO b700b632

server -> client
BF2:0bbc114acd70a708ed0748e357ca0ebc179ed807ae3feb38afdb77f739c53bec2e0cab21e810922353d14df411dc0ba1d441c96988449fd84cec0f
```

The destination port is `31337`, matching the executable's call to `htons` at
`0x140001a38`. The client always connects to `127.0.0.1`; the capture is a
recording of the local replay server mentioned in the error message.

The `BFHELLO` value gives the first 32-bit key directly:

```text
handshake key = 0xb700b632
```

The `BF2:` body consists of 118 hexadecimal characters, or 59 encrypted bytes.

## 3. Token Parsing and the FNV-1a Gate

The command-line parser searches for the exact marker `--token ` and copies the
following bytes until NUL, space, tab, CR, or LF. Its length loop increments
the counter for the terminating NUL and then compares the result with `0x11`:

```text
16 token characters + 1 NUL = 17 bytes
```

At `0x1400012b6`, the program hashes those 16 characters with standard 32-bit
FNV-1a:

```text
h_0     = 0x811c9dc5
h_(i+1) = ((h_i XOR token[i]) * 0x01000193) mod 2^32
```

The result must equal the value seen in the PCAP:

```text
FNV1a(token) == 0xb700b632
```

For example, the printable 16-byte preimage `blackfrosta6tLzo` satisfies this
gate. It is not required to recover the flag, because the cryptographic layers
can be decoded directly from the two artifacts.

## 4. Recovering the Stream Primitive

The PE uses the same byte-wise primitive for the embedded configuration and
the `BF2:` response. The compiler vectorizes the first use with SSE, making it
look more complicated than it is.

Let `C[i]` be one ciphertext byte and let `K` be a 32-bit little-endian key.
The plaintext equation is:

```text
P[i] = C[i]
       XOR byte(K, i mod 4)
       XOR ((0x5a + 0x11*i) mod 256)
```

where:

```text
byte(K, j) = (K >> (8*j)) AND 0xff
```

XOR is its own inverse, so the same equation encrypts and decrypts.

## 5. Decrypting the Captured Configuration

Apply the stream equation to the `BF2:` ciphertext with `K = 0xb700b632`.
The first bytes demonstrate the calculation:

```text
C[0]    = 0x0b
key[0]  = 0x32
mask[0] = 0x5a
P[0]    = 0x0b XOR 0x32 XOR 0x5a = 0x63 = 'c'

C[1]    = 0xbc
key[1]  = 0xb6
mask[1] = 0x6b
P[1]    = 0xbc XOR 0xb6 XOR 0x6b = 0x61 = 'a'
```

Decrypting all 59 bytes produces:

```text
campaign=BLACKFROST-26;nonce=4c2f17;directive=collect-only;
```

Later code checks these three fields individually before entering the success
handler:

```text
campaign=BLACKFROST-26;
nonce=4c2f17;
directive=collect-only;
```

## 6. Explaining the Embedded-Key Mismatch

Before opening the socket, the program allocates 60 bytes and decrypts 56
bytes from `.rdata` RVA `0x3000`. It then generates three final bytes from the
key and appends a NUL terminator.

Using the accepted handshake key does not produce text:

```text
key 0xb700b632 -> 3e050a613c0d007f...
```

There is a NUL at offset six, so the subsequent string-length test fails and
the original program prints:

```text
stage unpack failed
```

The captured configuration tells us that this blob should begin with
`campaign=`. Rearrange the stream equation to recover each key byte:

```text
key[i] = C[i] XOR P[i] XOR ((0x5a + 0x11*i) mod 256)
```

For the first four ciphertext bytes `56 d8 76 5b` and plaintext bytes
`63 61 6d 70` (`camp`), the result is:

```text
key bytes = 6f d2 67 a6
key       = 0xa667d26f
```

Decrypting the 56-byte table with that key yields:

```text
campaign=BLACKFROST-26;nonce=4c2f17;directive=collect-on
```

The executable generates the missing tail as follows:

```text
tail[0] = key_byte[0] XOR 0x03 = 'l'
tail[1] = key_byte[1] XOR 0xab = 'y'
tail[2] = key_byte[2] XOR 0x5c = ';'
```

The complete embedded plaintext is therefore identical to the captured
plaintext:

```text
campaign=BLACKFROST-26;nonce=4c2f17;directive=collect-only;
```

This proves that the sample contains two intentionally inconsistent keys:

| Purpose | Key |
| --- | ---: |
| Token check and captured `BF2:` response | `0xb700b632` |
| Embedded configuration at RVA `0x3000` | `0xa667d26f` |

## 7. Reversing the Final Flag Decoder

The success routine begins at `0x140001777`. It reads 34 bytes from `.rdata`
RVA `0x3080`, corresponding to file offset `0x1680`:

```text
4d 6e 79 03 0e 21 05 18 e0 ed f0 ce c7 ad bc a8
b6 95 6c 7e 7b 43 50 1b 23 3b 08 17 f3 f7 ed c9
dd bb
```

The routine processes two bytes at a time with a rolling byte initialized to
`0x26`:

```text
plain[2*j]     = encrypted[2*j]     XOR ((rolling - 0x0d) mod 256)
plain[2*j + 1] = encrypted[2*j + 1] XOR rolling
rolling        = (rolling + 0x1a) mod 256
```

The first pair is:

```text
0x4d XOR (0x26 - 0x0d) = 0x54 = 'T'
0x6e XOR 0x26          = 0x48 = 'H'
```

Applying all 17 iterations gives:

```text
THJCC{blackfrost_config_recovered}
```

## 8. Automated Solver

The included [`solve.py`](solve.py) uses only the Python standard library and
does not execute the PE. It:

1. Parses the classic PCAP container and extracts both TCP payloads.
2. Reads the handshake key and decodes the `BF2:` hexadecimal body.
3. Parses the PE32+ section table and maps the relevant RVAs to file offsets.
4. Derives the embedded key from the known `camp` prefix.
5. Reconstructs and compares both complete configuration strings.
6. Reimplements the native rolling-XOR success handler to recover the flag.

Run it from the challenge directory:

```bash
python3 solve.py
```

Expected output:

```text
handshake key: 0xb700b632
captured config: campaign=BLACKFROST-26;nonce=4c2f17;directive=collect-only;
embedded config key: 0xa667d26f
embedded config: campaign=BLACKFROST-26;nonce=4c2f17;directive=collect-only;
key mismatch: True
flag: THJCC{blackfrost_config_recovered}
```

## 9. Isolated Runtime Validation

Static recovery is sufficient and safer, but the final decoder was also
validated in an isolated Windows-compatible Wine prefix. The unmodified sample
accepted an FNV-1a preimage and then printed `stage unpack failed`, exactly as
predicted by the embedded-key mismatch.

For a final behavioral check, a temporary copy was patched at file offset
`0x61c` (RVA `0x121c`) with the relative branch `e9 56 05 00 00`, redirecting
execution to the success routine at `0x140001777`. The sandbox output was:

```text
THJCC{blackfrost_config_recovered}
```

The original executable and capture were not modified. The repository solver
performs no dynamic execution and is safe to run on any platform with Python 3.

## Flag

```text
THJCC{blackfrost_config_recovered}
```
