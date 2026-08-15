# Lattice of Doom

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Cryptography |
| Points | 100 |
| Author | 燒餅不加蛋 |
| Handout | [`artifacts/chal-Lattice-of-Doom.zip`](artifacts/chal-Lattice-of-Doom.zip) |
| Flag | `THJCC{l4tt1c3s_turn_b14s3d_n0nc3s_1nt0_pr1v4t3_k3ys}` |

## Overview

The handout contains 60 secp256k1 ECDSA signatures, the corresponding public
key, an encrypted flag, and a fragment of the wallet's signing code. The private
key never appears directly, and none of the nonces are repeated.

The weakness is more subtle: every nonce contains only 29 random bytes. A
secp256k1 scalar is approximately 256 bits, while these nonces are bounded by
`2^232`. Therefore, 24 leading nonce bits are known to be zero in every
signature.

One such signature does not reveal enough to recover the key. Sixty modular
relations with the same private scalar do. This is an instance of the Hidden
Number Problem, which can be solved by constructing a lattice containing an
unusually short vector.

## 1. Inspecting the Handout

The archive contains:

```text
README.md
output.json
signer_excerpt.py
```

The original archive has SHA-256:

```text
0e8d26aee90a352b6fafdb8d9cf912fd025d5276b7f55dfc19021ef10732b6e5
```

The leaked signing routine is short:

```python
NONCE_BYTES = 29

def make_nonce(trng):
    return int.from_bytes(trng.read(NONCE_BYTES), "big")

def sign(d, msg, trng):
    k = make_nonce(trng)
    r = (k * G).x() % N
    s = pow(k, -1, N) * (sha256_int(msg) + r * d) % N
    return r, s
```

There are indeed about `2^232`, or `10^69`, possible nonces. Exhausting that
space is impossible. The problem is not the total number of candidates; it is
that all nonces occupy a small interval relative to the 256-bit curve order.

## 2. Turning ECDSA into Linear Relations

For each ECDSA signature `(r_i, s_i)` on hash `h_i`, the signing equation is:

```text
s_i * k_i = h_i + r_i * d  (mod n)
```

Multiply both sides by the inverse of `s_i` and define:

```text
a_i = r_i * inverse(s_i) mod n
b_i = h_i * inverse(s_i) mod n
```

Then every signature gives a linear modular relation involving the same private
key `d`:

```text
k_i = a_i * d + b_i  (mod n)
```

The nonce generator supplies the extra information:

```text
0 <= k_i < K, where K = 2^232
```

Thus, each signature says that a known linear function of `d`, reduced modulo
`n`, lies in the same unusually small interval.

## 3. Centering the Nonces

Lattice reduction works best with small signed values centered around zero.
Set:

```text
X = K / 2 = 2^231
e_i = k_i - X
```

Now every error satisfies:

```text
-X <= e_i < X
```

For some integer `q_i`, the modular equation can be written over the integers:

```text
e_i = a_i*d + (b_i - X) - q_i*n
```

The unknowns are the private key `d` and the quotients `q_i`, while all `e_i`
are small.

## 4. Constructing the Lattice

Let `m = 60`, the number of signatures. Build an `(m+2)` by `(m+2)` integer
basis, giving a 62-dimensional lattice.

The first `m` rows contain `n^2` on the diagonal:

```text
B_i[i] = n^2
```

The secret row contains the normalized signature coefficients and a scaling
value in coordinate `m`:

```text
B_d = (n*a_1, n*a_2, ..., n*a_m, X, 0)
```

The constant row contains the centered offsets and a marker in the final
coordinate:

```text
B_c = (n*(b_1-X), ..., n*(b_m-X), 0, X*n)
```

Written schematically, the basis is:

```text
[ n^2       0      ...      0       0      0 ]
[   0      n^2     ...      0       0      0 ]
[  ...      ...    ...     ...      ...    ...]
[   0       0      ...     n^2      0      0 ]
[ n*a_1  n*a_2     ...   n*a_m      X      0 ]
[n(b_1-X) ...      ... n(b_m-X)     0     X*n]
```

Consider the following integer combination of basis rows:

```text
d*B_d + B_c - sum(q_i*B_i)
```

Its first `m` coordinates become:

```text
n * (a_i*d + b_i - X - q_i*n) = n*e_i
```

The complete vector is therefore:

```text
(n*e_1, n*e_2, ..., n*e_m, d*X, n*X)
```

All error coordinates are bounded by `n*X`. The final coordinate is the fixed
marker `n*X`, and the secret coordinate encodes `d`. Compared with ordinary
vectors in this lattice, this vector is exceptionally short, so LLL reduction
brings it into the reduced basis.

The factors of `n` in this construction are an integer-scaled version of the
usual rational Hidden Number Problem embedding. They let `fplll` operate using
only exact integers.

## 5. Running LLL and Extracting the Key

The solver invokes `fplll` with proved LLL reduction, delta `0.999`, and 256-bit
MPFR precision:

```bash
fplll -a lll -m proved -d 0.999 -f mpfr -p 256 basis.txt
```

The target row is easy to recognize because the absolute value of its final
coordinate equals the marker `n*X`. Divide coordinate `m` by `X` to obtain the
private-key coefficient.

Because the lattice also contains a vector with secret coordinate `n*X`, the
coefficient can appear as `d-n` rather than the canonical scalar `d`. Reducing
the extracted coefficient modulo `n` gives:

```text
d = a808ed16f3523aa75d754fef34d4247f4eebbc33ba38729e0c151149f7bb37a2
```

The solver performs two independent validations:

1. It reconstructs all 60 nonces and confirms that every one is less than
   `2^232`.
2. It calculates `d*G` on secp256k1 and confirms that the point exactly matches
   the supplied `(Qx, Qy)` public key.

The largest recovered nonce is exactly 232 bits, consistent with the leaked
29-byte generator.

## 6. Deriving the AES Key

The KDF is documented in `output.json`:

```python
key = sha256(b"wallet-v1|" + d.to_bytes(32, "big"))[:16]
```

Using the recovered private scalar gives:

```text
AES key = 14de8409635e9e3c392f1fae8ec1b479
```

The first 16 bytes of `flag_enc` are the CBC IV:

```text
e29c5a18cded2b6781677a6f771d021a
```

The remaining 64 bytes are the AES-128-CBC ciphertext. Decrypting and removing
PKCS#7 padding reveals:

```text
THJCC{l4tt1c3s_turn_b14s3d_n0nc3s_1nt0_pr1v4t3_k3ys}
```

## 7. Reproducing the Solve

The solver uses only Python's standard library plus two command-line tools:

```text
fplll
openssl
```

Run it from the challenge directory:

```bash
python3 solve.py
```

Expected output:

```text
signatures: 60
nonce bound: 2^232
lattice dimension: 62
private key: a808ed16f3523aa75d754fef34d4247f4eebbc33ba38729e0c151149f7bb37a2
largest nonce: 232 bits
public key verified: True
AES key: 14de8409635e9e3c392f1fae8ec1b479
flag: THJCC{l4tt1c3s_turn_b14s3d_n0nc3s_1nt0_pr1v4t3_k3ys}
```

## Flag

```text
THJCC{l4tt1c3s_turn_b14s3d_n0nc3s_1nt0_pr1v4t3_k3ys}
```
