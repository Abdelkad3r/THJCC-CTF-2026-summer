# Schizophrenic Signer

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Cryptography |
| Points | 223 |
| Author | Not specified |
| Connection | `nc chal.thjcc.org 11451` |
| Handout | [`artifacts/deploy.zip`](artifacts/deploy.zip) |
| Flag | `THJCC{w0w_y0u_f0und_th3_h1dd3n_d3lt4_b3tw33n_p_4nd_q!}` |

## Overview

The service signs 85 known messages with ECDSA over secp256k1. Its nonces come
from a linear congruential generator (LCG), but the implementation moves the
nonce state between two different moduli:

- the LCG evolves modulo the secp256k1 field prime `p`;
- ECDSA arithmetic uses the secp256k1 group order `q`.

The two constants are close, but they are not equal. That mismatch turns each
pair of consecutive signatures into a modular equation whose quotient is
bounded by the public LCG multiplier. With 85 signatures, the 84 resulting
inequalities form a Hidden Number Problem (HNP).

The private key can be recovered with a Kannan embedding followed by LLL and
BKZ lattice reduction. The server randomizes the multiplier for every
connection, so the solver deliberately keeps a session whose multiplier gives
close to four bits of leakage per transition.

## 1. Inspecting the Handout

The archive contains:

```text
.env
Dockerfile
docker-compose.yml
server.py
```

The original archive has SHA-256:

```text
afc6b4e14a1a76e411b3655e7f6d08d32842b3b334c15f0ae2293b232284f8d7
```

The important constants are the normal secp256k1 parameters:

```python
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
```

Their difference is small relative to either 256-bit modulus:

```text
p - q = 0x14551231950b75fc4402da1722fc9baee
bit length = 129
```

The nonce generator is:

```python
class DualGenerator:
    def __init__(self, seed):
        self.state = seed
        self.a = random.randint(2**252, 2**253 - 1)
        self.b = random.randint(1, p - 1)

    def next_nonce(self):
        self.state = (self.a * self.state + self.b) % p
        return self.state % q
```

The service discloses the public key, `a`, `b`, and 85 triples `(h, r, s)`. It
then asks for the ECDSA private scalar `d`.

## 2. Recovering a Nonce as a Function of the Key

For an ECDSA signature, the signing equation is:

```text
s_i * k_i = h_i + r_i * d  (mod q)
```

Multiplying by the inverse of `s_i` gives:

```text
k_i = alpha_i*d + beta_i  (mod q)
```

where all terms except `d` are known:

```text
alpha_i = r_i * inverse(s_i, q) mod q
beta_i  = h_i * inverse(s_i, q) mod q
```

This relation alone is ordinary ECDSA and does not reveal the key. The LCG
recurrence supplies the missing bounded information.

## 3. Exposing the Cross-Modulus Quotient

Let `t_i` be the integer quotient removed when the LCG reduces modulo `p`:

```text
k_(i+1) = a*k_i + b - t_i*p
```

The internal state is uniform modulo `p`, while the returned nonce is reduced
modulo `q`. A state differs from its returned nonce only when it lands in the
small interval `[q, p)`, which has probability approximately `2^-128`.
Across 85 samples this event remains negligible, and the final candidate is
independently verified against every bounded relation and the public key.

Because `0 <= k_i < q < p` and `a` is between `2^252` and `2^253`, the quotient
is bounded:

```text
0 <= t_i < a
```

Reduce the recurrence modulo `q` and substitute the ECDSA expressions:

```text
t_i*p = a*k_i + b - k_(i+1)  (mod q)

t_i = inverse(p, q) *
      ((a*alpha_i - alpha_(i+1))*d
       + a*beta_i + b - beta_(i+1))  (mod q)
```

Define:

```text
A_i = inverse(p, q) * (a*alpha_i - alpha_(i+1)) mod q
B_i = inverse(p, q) * (a*beta_i + b - beta_(i+1)) mod q
```

Each transition now gives the HNP relation:

```text
t_i = A_i*d + B_i  (mod q), with 0 <= t_i < a
```

There are 84 such relations.

## 4. Why the Multiplier Matters

One bounded quotient leaks approximately:

```text
log2(q/a) bits
```

The server samples `a` uniformly from `[2^252, 2^253)`, so `q/a` lies roughly
between 8 and 16. A multiplier near the upper end leaks only about three bits
per transition, which puts 84 samples at the edge of lattice feasibility.

Every new TCP connection creates a new key pair and new LCG parameters. The
solver therefore reconnects until:

```text
q/a >= 15.7
```

The successful session had:

```text
a   = 0x104b24e3d993f78532a2685410c77e263e4a127159bb9847d5b68d9da4cdd947
b   = 0x0d66d6deab1af4dac715ba9ee4af0b22fbbc4d759e31766f33c132f160d59625
q/a = 15.711756391507445
```

This leaks about 3.973 bits per transition, or approximately 334 bits across
the 84 modular inequalities. The selected connection must remain open while
the lattice reduction runs because its private key is unique to that session.

## 5. Constructing the Kannan Embedding

Let `m = 84` and let the quotient bound be `X = a`. Center each quotient around
zero:

```text
e_i = t_i - X/2
```

For suitable integers `z_i`:

```text
e_i = A_i*d + B_i - X/2 + z_i*q
```

Build an `(m+2) x (m+2)` integer basis. The first `m` rows contain `q^2` on
their diagonal. The next row encodes the secret coefficient, and the final row
encodes the centered constants:

```text
[ q^2       0      ...      0       0      0 ]
[   0      q^2     ...      0       0      0 ]
[  ...      ...    ...     ...      ...    ...]
[   0       0      ...     q^2      0      0 ]
[ q*A_0  q*A_1     ...   q*A_83     X      0 ]
[q(B_0-X/2) ... q(B_83-X/2)         0     X*q]
```

Consider the lattice combination consisting of `d` times the secret row, once
the constant row is added, and suitable multiples of the diagonal rows:

```text
(q*e_0, q*e_1, ..., q*e_83, X*d, X*q)
```

Every `e_i` is bounded by `X/2`, so this vector is unusually short. The final
coordinate acts as an embedding marker, while coordinate `m` contains the
private-key coefficient scaled by `X`.

The factors of `q` are an exact integer form of the usual rational HNP
embedding. No floating-point approximation is introduced while constructing
the basis.

## 6. Reducing the Lattice

The solver first applies LLL with `delta = 0.999`, then progressively increases
the BKZ block size:

```python
LLL.reduction(basis, delta=0.999)

for block_size in (20, 25, 30, 35, 40):
    BKZ.reduction(
        basis,
        BKZ.Param(
            block_size=block_size,
            max_loops=8,
            flags=BKZ.AUTO_ABORT,
        ),
    )
```

After every stage, it scans the reduced rows for a secret coordinate divisible
by `X`:

```text
d_candidate = row[m] / X mod q
```

The short vector can appear with either sign, so both `d_candidate` and
`-d_candidate mod q` are tested.

The successful private scalar was:

```text
fb5db1705ca92225ac021149683639fa7ea101a72a17f8c0bcad2a5b941ffef9
```

## 7. Verifying the Candidate

The solver does not trust a lattice row merely because it has the expected
shape. It performs two independent checks before sending anything to the
service.

First, all 84 reconstructed quotients must satisfy the original bound:

```python
t_i = (A_i * d + B_i) % q
assert all(t_i < a for t_i in quotients)
```

For the successful session:

```text
largest quotient =
0x102620dd77e9c7fccc1b15070dcc2a8f2674c82fc015568bf202918920011aac

largest quotient bit length = 253
all quotients below a       = True
```

Second, scalar multiplication must reproduce the exact public key printed by
the server:

```text
Qx = b75b6c253f572e8c0fe598c5fcd7844ea02d4ad5cd16f13dd1cc9b8dbea0dd65
Qy = bf0d1924d0a34b6607afd19b7e48911ed1fecd476f2b803e94d9751b6e3a2d6d

d*G == (Qx, Qy) = True
```

Only after both checks pass does the exploit submit the hexadecimal scalar on
the still-open connection.

## 8. Reproducing the Solve

The solver requires Python 3.11 or later and `fpylll`:

```bash
python3 -m pip install fpylll cysignals
```

Run the live exploit from the challenge directory:

```bash
python3 solve.py --host chal.thjcc.org --port 11451
```

The session-selection loop may open many connections before finding a low
enough multiplier. BKZ-40 can also take several minutes depending on the
machine and the selected basis.

The successful run ended with:

```text
attempt 98: q/a = 15.7118
private key: 0xfb5db1705ca92225ac021149683639fa7ea101a72a17f8c0bcad2a5b941ffef9
Incredible! Here is your flag: THJCC{w0w_y0u_f0und_th3_h1dd3n_d3lt4_b3tw33n_p_4nd_q!}
```

An offline copy of the successful public transcript is included. It can be
used to reproduce private-key recovery without contacting the service:

```bash
python3 solve.py --transcript artifacts/successful-transcript.txt
```

Expected offline output:

```text
0xfb5db1705ca92225ac021149683639fa7ea101a72a17f8c0bcad2a5b941ffef9
```

## Flag

```text
THJCC{w0w_y0u_f0und_th3_h1dd3n_d3lt4_b3tw33n_p_4nd_q!}
```
