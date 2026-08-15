# Nonce Sense

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Cryptography |
| Points | 100 |
| Author | 燒餅不加蛋 |
| Connection | `nc chal.thjcc.org 12001` |
| Protocol sample | [`artifacts/protocol-sample.txt`](artifacts/protocol-sample.txt) |
| Flag | `THJCC{n3v3r_3v3r_r3us3_th3_s4m3_n0nc3}` |

## Overview

The service acts as a toy signing oracle for a coin-transfer ledger. On every
connection it generates a fresh secp256k1 keypair, prints the public key, and
hands you two ECDSA signatures over two different transfer messages. It then
prints a `TARGET` message and waits for a signature.

The title is the entire hint. The two signatures reuse the same ECDSA **nonce**
`k` — visible immediately because they share the same `r` value. A single reused
nonce collapses ECDSA's security: the private key can be recovered with
schoolbook algebra. With the key in hand we forge a signature over the `TARGET`
message (`admin=true;action=release_flag`) and the server releases the flag.

## 1. Mapping the Protocol

Connect and read what the service offers:

```bash
nc chal.thjcc.org 12001
```

```text
PUB  <x> <y>
SIG  <msg1_hex> <r> <s1>
SIG  <msg2_hex> <r> <s2>
TARGET <msg_hex>
```

Decoding the hex messages:

```text
msg1   = "transfer 1 coin to alice"
msg2   = "transfer 2 coins to bob"
TARGET = "admin=true;action=release_flag"
```

Two structural facts jump out:

- **`PUB` is two 32-byte integers** — an uncompressed curve point `(x, y)`. A
  256-bit field points at a 256-bit curve; secp256k1 and secp256r1 (P-256) are
  the usual suspects.
- **Both `SIG` lines carry the same `r`.** In ECDSA, `r` is the x-coordinate of
  `k·G`, so an identical `r` across two signatures means an identical nonce `k`.
  That is the whole game.

Sending anything that is not a valid signature over `TARGET` returns `NOPE`, and
each connection mints a brand-new key, so the attack has to complete inside a
single session.

## 2. Why a Reused Nonce Is Fatal

ECDSA produces a signature `(r, s)` over a message representative `z` (the hash
of the message, reduced mod the group order `n`) as:

```text
r = (k·G).x  mod n
s = k⁻¹ · (z + r·d)  mod n
```

where `d` is the private key and `k` is a per-signature random nonce. The nonce
is the one value that must never repeat and must never be predictable.

Given two signatures with the **same** `k` (hence the same `r`):

```text
s1 = k⁻¹ · (z1 + r·d)
s2 = k⁻¹ · (z2 + r·d)
```

Subtracting eliminates `d`:

```text
s1 − s2 = k⁻¹ · (z1 − z2)   (mod n)
```

which solves directly for the nonce:

```text
k = (z1 − z2) · (s1 − s2)⁻¹   (mod n)
```

Substituting `k` back into either signature equation recovers the private key:

```text
d = (s1·k − z1) · r⁻¹   (mod n)
```

Everything on the right-hand side is public. Two signatures and one shared nonce
are all it takes.

## 3. Pinning Down the Curve and Hash

The algebra above needs three modeling choices to be correct: the curve (which
fixes `n` and `G`), and the hash used to turn each message into `z`. Rather than
guess, we let the math referee itself: recover a candidate `d`, then test whether
`d·G == PUB`. Only the correct combination reproduces the published public key.

Trying `{secp256k1, secp256r1} × {sha256, sha1, sha512, ...}`:

- **`PUB` is not even on secp256r1** — the point fails the curve equation, so
  P-256 is out before any signing math.
- **secp256k1 with SHA-256** yields a `d` satisfying `d·G == PUB`. Match.

secp256k1's order `n` is just under 2²⁵⁶, so the standard ECDSA left-truncation
of a 256-bit SHA-256 digest is effectively the full digest reduced mod `n`; both
conventions give the same `z` here.

```text
### secp256k1  PUB on curve: True
  *** MATCH hash=sha256  d=0xe1f84fc2...
### secp256r1  PUB on curve: False
```

## 4. Recovering the Key

There is a small sign subtlety worth handling explicitly. The value `r` is only
the x-coordinate of `k·G`, so the true nonce could be `k` or `n − k`, and the
subtraction `s1 − s2` could equally be written `s2 − s1`. Rather than reason
about which branch the server used, the solver simply enumerates the few
sign combinations and keeps the one whose recovered `d` satisfies `d·G == PUB`:

```python
for sk in (s1 - s2, s2 - s1):
    k = (z1 - z2) * inv(sk, n) % n
    for kk in (k, -k % n):
        d = (s1 * kk - z1) * inv(r, n) % n
        if mul(d, G) == PUB:
            return kk, d          # verified against the public key
```

The verification step is what makes this robust: a wrong sign branch is silently
discarded instead of producing a bad key.

## 5. Forging the Admin Signature

With `d` known we are the signer. Sign the `TARGET` message with any nonce we
like — crucially a **fresh** one, so we do not re-leak our own key:

```text
z   = SHA-256("admin=true;action=release_flag")  mod n
k'  = a fresh nonce (deterministic from d and the message here)
r'  = (k'·G).x  mod n
s'  = k'⁻¹ · (z + r'·d)  mod n
```

Submit `r'` and `s'` as two space-separated 64-hex-digit values — the same
`<r> <s>` shape the server used to print its own signatures:

```text
87a9946a5198f80c05300edfa15894e5405fbf9367d20aac203bf701a99b5763 b1c8...f649
```

The service verifies the signature against `PUB` and the `TARGET` message and
replies:

```text
FLAG THJCC{n3v3r_3v3r_r3us3_th3_s4m3_n0nc3}
```

## 6. Automated Solver

The solve is split into a from-scratch curve library and a client, with **no
third-party dependencies** — the elliptic-curve arithmetic, modular inverses and
key recovery are all implemented directly.

- [`ecdsa_tool.py`](ecdsa_tool.py) — secp256k1/secp256r1 parameters, point
  add/double/multiply, the nonce-reuse recovery, and a signer.
- [`solve.py`](solve.py) — connects, parses the handshake, recovers and verifies
  `d`, forges the `TARGET` signature, and submits it.

```bash
python3 solve.py
```

```text
PUB ...
SIG 7472616e73666572203120636f696e20746f20616c696365 ...
SIG 7472616e73666572203220636f696e7320746f20626f62 ...
TARGET 61646d696e3d747275653b616374696f6e3d72656c656173655f666c6167

[+] reused nonce  k = 0xcb2a7286...
[+] private key   d = 0x8fa40d8d...
[+] verified: d*G == PUB  ->  True
[>] 87a9946a...5763 b1c841e3...f649
[<] FLAG THJCC{n3v3r_3v3r_r3us3_th3_s4m3_n0nc3}
```

Because the key is regenerated per connection, a saved transcript cannot be
replayed against the live service — but the recovery itself is fully
reproducible offline against the committed sample:

```bash
python3 solve.py --offline artifacts/protocol-sample.txt
```

```text
[+] reused nonce  k = 0x9f96cd05...
[+] private key   d = 0x9a7075cd...
[+] verified: d*G == PUB  ->  True
[+] forged sig for TARGET: cb369cd7...ccd7 32fc82cd...6d4a
```

## Lessons

- **A repeated `r` is a repeated nonce, and a repeated nonce is a leaked key.**
  It is the first thing to check on any ECDSA signature dump.
- **Recover, then verify.** Testing `d·G == PUB` turns "which curve? which hash?
  which sign?" from four separate guesses into one self-checking loop.
- **The countermeasure is deterministic nonces.** RFC 6979 derives `k` from the
  private key and the message, so the same message signs identically and distinct
  messages never collide — exactly what the flag says out loud.

## Flag

```text
THJCC{n3v3r_3v3r_r3us3_th3_s4m3_n0nc3}
```
