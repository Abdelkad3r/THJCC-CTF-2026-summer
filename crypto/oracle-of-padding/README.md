# Oracle of Padding

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Cryptography |
| Points | 100 |
| Author | 燒餅不加蛋 |
| Connection | `nc chal.thjcc.org 12000` |
| Protocol sample | [`artifacts/protocol-sample.txt`](artifacts/protocol-sample.txt) |
| Flag | `THJCC{p4dd1ng_0r4cl3s_l34k_0n3_byt3_p3r_qu3ry}` |

## Overview

The service supplies an encrypted token and accepts arbitrary hexadecimal
ciphertexts for validation. It does not return decrypted data, but it responds
with `OK` when the submitted ciphertext has valid padding and `BAD` otherwise.

That one-bit distinction is enough to decrypt CBC ciphertext without knowing
the encryption key. By manipulating the block immediately before a target
block, we can force chosen values into the target plaintext and recover one byte
of the CBC intermediate state at a time.

## 1. Mapping the Protocol

Connect to the service with Netcat:

```bash
nc chal.thjcc.org 12000
```

The server begins each connection with a fresh token:

```text
TOKEN 5a31c94bba8d65e280db4cb97a244e5e...
```

The token contains 224 hexadecimal characters:

```text
224 hex characters / 2 = 112 bytes
112 bytes / 16 = 7 blocks
```

The first block is the CBC initialization vector, leaving six encrypted data
blocks:

```text
IV || C1 || C2 || C3 || C4 || C5 || C6
```

Submitting the unchanged token produces `OK`, while malformed or randomly
modified data normally produces `BAD`. The connection remains open after a
query, allowing many requests against the same oracle.

```text
unchanged token -> OK
00              -> BAD
```

This is the defining behavior of a padding oracle.

## 2. Why CBC Padding Leaks Plaintext

For one CBC ciphertext block `Ci`, decryption first produces an intermediate
block:

```text
Ii = D_K(Ci)
```

The plaintext is obtained by XORing that intermediate value with the previous
ciphertext block:

```text
Pi = Ii XOR C(i-1)
```

For the first encrypted block, `C(i-1)` is the IV.

We cannot calculate `D_K(Ci)` because the key is unknown. However, we can replace
the preceding block with a controlled block `C'` and ask the service whether:

```text
Ii XOR C'
```

ends in valid PKCS#7 padding. This lets us infer `Ii` byte by byte.

## 3. Recovering an Intermediate Block

Make the block under attack the final ciphertext block by submitting only:

```text
C' || Ci
```

Start at byte position 15, the final byte of the block. For padding length 1,
try every possible value `g` for `C'[15]`. When the oracle returns `OK`, the
resulting plaintext byte is `0x01`, so:

```text
Ii[15] XOR g = 0x01
Ii[15] = g XOR 0x01
```

For padding length 2, force the already recovered last byte to decrypt as
`0x02`:

```text
C'[15] = Ii[15] XOR 0x02
```

Then try all 256 values for `C'[14]`. A valid response reveals:

```text
Ii[14] = g XOR 0x02
```

The general step for padding value `p` is:

```text
C'[j] = Ii[j] XOR p                  for every known suffix byte j
Ii[position] = successful_guess XOR p
```

Repeating this process for padding values 1 through 16 recovers the complete
intermediate block. The original plaintext block is then:

```text
Pi = Ii XOR original_C(i-1)
```

Apply the same attack independently to `C1` through `C6`.

## 4. Handling Padding False Positives

The final-byte attack can occasionally produce more than one `OK` response. One
guess creates the intended `0x01` padding, while another may accidentally retain
a longer valid padding sequence.

To identify the real `0x01` candidate, flip byte 14 and query again:

- Genuine one-byte padding remains valid because byte 14 is outside the padding.
- Accidental two-byte or longer padding becomes invalid.

The solver implements this confirmation whenever multiple last-byte candidates
appear.

## 5. Batching the Oracle Queries

A straightforward attack sends one request and waits for one response. That
works, but network latency dominates the runtime. At each byte position, all 256
guesses are independent, so the solver sends all 256 hexadecimal lines in one
batch and then reads the 256 responses in order.

The normal query count is:

```text
6 blocks * 16 bytes * 256 guesses = 24,576 queries
```

Batching does not reduce the number of oracle decisions, but it reduces the
number of network round trips dramatically.

## 6. Decrypting the Token

Running the attack reveals the plaintext block by block:

```text
[1/6] b'{"user":"guest",'
[2/6] b'"admin":false,"n'
[3/6] b'ote":"THJCC{p4dd'
[4/6] b'1ng_0r4cl3s_l34k'
[5/6] b'_0n3_byt3_p3r_qu'
[6/6] b'3ry}"}\n\n\n\n\n\n\n\n\n\n'
```

The final ten `0x0a` bytes are valid PKCS#7 padding. Removing them gives the
complete JSON token:

```json
{"user":"guest","admin":false,"note":"THJCC{p4dd1ng_0r4cl3s_l34k_0n3_byt3_p3r_qu3ry}"}
```

The flag is stored directly in the `note` field; no token forgery is required.

## 7. Reproducing the Solve

Run the included solver while the challenge endpoint is available:

```bash
python3 solve.py
```

The script automatically:

1. Connects to the service and parses the fresh token.
2. Splits the IV and ciphertext into 16-byte blocks.
3. Recovers each intermediate block using batched padding-oracle queries.
4. XORs each intermediate block with its original predecessor.
5. Validates and removes PKCS#7 padding.
6. Prints the recovered JSON plaintext.

Expected final output:

```text
queries: 24576
plaintext: {"user":"guest","admin":false,"note":"THJCC{p4dd1ng_0r4cl3s_l34k_0n3_byt3_p3r_qu3ry}"}
```

## Flag

```text
THJCC{p4dd1ng_0r4cl3s_l34k_0n3_byt3_p3r_qu3ry}
```
