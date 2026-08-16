# Forbidden

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Cryptography |
| Points | 248 |
| Author | 燒餅不加蛋 |
| Connection | `nc chal.thjcc.org 12002` |
| Protocol sample | [`artifacts/protocol-sample.txt`](artifacts/protocol-sample.txt) |
| Flag | `THJCC{h_r3c0v3r3d_gcm_1s_f0rb1dd3n_w1th0ut_fr3sh_n0nc3s}` |

## Overview

The service is an AES-GCM "vault" that encrypts a handful of house messages and
challenges you to authenticate one it never issued. Its fatal mistake is in the
name: it reuses **one nonce for every message**. In GCM a nonce must never
repeat under the same key — doing so is *forbidden* — because it lets an attacker
recover the GHASH authentication subkey `H` and forge tags at will. This is the
classic **Forbidden Attack** (Joux, 2006).

On each connection the server prints:

```text
NONCE  <96-bit nonce, reused for all messages>
MSG    <plaintext_hex> <ciphertext_hex> <tag_hex>     (x3)
TARGET <plaintext_hex>                                 ("give me the flag")
```

We forge a valid `(ciphertext, tag)` for the `TARGET` and send it back as
`<ct_hex> <tag_hex>`; the server verifies it under its secret key and returns the
flag. Two independent leaks, both consequences of the reused nonce, make this
possible.

## 1. Reading the Handshake

Decoding the hex fields of one session:

| Field | Value |
| --- | --- |
| MSG 1 | `welcome to the vault, there is nothing to see here` |
| MSG 2 | `status: nominal` |
| MSG 3 | `reminder: rotate your keys, some day, maybe, but not today` |
| TARGET | `give me the flag` |

Three known `(plaintext, ciphertext, tag)` triples, all under the **same
`NONCE`**, and one target plaintext to authenticate. The flavour text
("rotate your keys… but not today") is a wink at the vulnerability.

## 2. Leak One — Keystream Reuse

GCM is counter mode for confidentiality: `C = P XOR keystream`, where the
keystream depends only on the key and nonce. Same key + same nonce ⇒ **same
keystream**. So from any known message,

```text
keystream = plaintext XOR ciphertext
```

and the keystream prefixes of all three messages are identical — a direct
confirmation of the nonce reuse:

```text
MSG1 keystream[:15] = 4040e89c9e852637d769039db6708f
MSG2 keystream[:15] = 4040e89c9e852637d769039db6708f   (identical)
```

`TARGET` is 16 bytes, so its ciphertext is simply
`"give me the flag" XOR keystream[:16]`. Encrypting the forged message is free.
The hard part is the **tag**.

## 3. Leak Two — Recovering the GHASH Key `H`

The GCM tag is

```text
T = GHASH_H(C) XOR S
```

where `H = E_K(0^128)` is the GHASH subkey and `S = E_K(J0)` is the encrypted
counter block. Both `H` and `S` depend only on the key and nonce, so under a
reused nonce **they are constant across every message**.

`GHASH_H` evaluates a polynomial in `H` over the field GF(2^128): for ciphertext
blocks `C_1 … C_n` (zero-padded) followed by the 128-bit length block `L`,

```text
GHASH_H(C) = C_1·H^(n+1) + C_2·H^n + … + C_n·H^2 + L·H^1
```

(all arithmetic in GF(2^128), addition = XOR). Define, for each message,

```text
f_i(H) = GHASH_H(C_i) XOR T_i
```

Then `f_i(H) = S` for **every** message — the same constant `S`. Subtracting two
messages cancels the unknown `S` and leaves a polynomial equation whose root is
the true `H`:

```text
P_12(H) = f_1(H) XOR f_2(H) = 0
P_13(H) = f_1(H) XOR f_3(H) = 0
```

Both polynomials vanish at the real `H`. Rather than factor a high-degree
polynomial over GF(2^128), take their **greatest common divisor** — the true `H`
is a common root, and with three messages the GCD collapses to a single linear
factor:

```text
gcd(P_12, P_13) = x + H   (degree 1)   ->   H read off directly
```

For one session:

```text
H = 0xe6da73500c6da225e6234d9c9b88bad8
```

Recovering `S` is then one polynomial evaluation, `S = f_0(H)`, and the fact that
`f_1(H) = f_2(H) = f_3(H)` all yield the *same* `S` is the proof that `H` is
correct:

```text
S = 0x26d1806944976885fe9dcff5b5fd0ff9   (consistent across all 3 messages)
```

## 4. Forging the Target Tag

With `H` and `S` known we can authenticate anything under this nonce:

```text
ct  = TARGET XOR keystream[:16]
tag = GHASH_H(ct) XOR S
```

Send `<ct_hex> <tag_hex>`. The server recomputes the tag under its own key,
finds it valid, and releases the flag:

```text
FLAG THJCC{h_r3c0v3r3d_gcm_1s_f0rb1dd3n_w1th0ut_fr3sh_n0nc3s}
```

The flag spells out the lesson: recover `H`, and GCM is forbidden without fresh
nonces.

## 5. Automated Solver

[`solve.py`](solve.py) has **no third-party dependencies** — the GF(2^128)
field, polynomials over it, and Euclidean polynomial GCD are all implemented
from scratch (GCM right-shift multiply with reduction polynomial
`x^128 + x^7 + x^2 + x + 1`, multiplicative identity `1<<127`).

```bash
python3 solve.py
```

```text
NONCE ...
MSG ...
TARGET 67697665206d652074686520666c6167

[+] H = 0x....
[+] S = 0x....  (consistent across all messages)
[+] forged ct  = ...
[+] forged tag = ...
[<] FLAG THJCC{h_r3c0v3r3d_gcm_1s_f0rb1dd3n_w1th0ut_fr3sh_n0nc3s}
```

Because the nonce and key are regenerated per connection, the recovery must run
inside a single session — but the attack itself is reproducible offline against
the committed transcript:

```bash
python3 solve.py --offline artifacts/protocol-sample.txt
```

```text
[+] H = 0xe6da73500c6da225e6234d9c9b88bad8
[+] S = 0x26d1806944976885fe9dcff5b5fd0ff9
[+] forged ct/tag for TARGET: b29f1e74...c30e aca6a7b6...be1c
```

## Lessons

- **A repeated GCM nonce is catastrophic for authentication, not just secrecy.**
  Keystream reuse (the "two-time pad") is the obvious harm; the subtler and worse
  one is that the polynomial-MAC key `H` becomes recoverable, so tags can be
  forged for *arbitrary* messages.
- **GHASH is a polynomial, so treat forgery as polynomial algebra.** Two messages
  give a polynomial with `H` as a root; a third lets you pin `H` exactly via GCD
  instead of factoring over GF(2^128).
- **Verify by over-determination.** Requiring the same `S` from all three
  messages turns "a root of the polynomial" into "the actual subkey" with no
  guesswork.
- **The fix is trivial and mandatory:** never reuse a `(key, nonce)` pair — use a
  random 96-bit nonce per message or a deterministic counter that never repeats.

## Flag

```text
THJCC{h_r3c0v3r3d_gcm_1s_f0rb1dd3n_w1th0ut_fr3sh_n0nc3s}
```
