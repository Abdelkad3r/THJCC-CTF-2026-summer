# Two Exponents

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Cryptography |
| Difficulty | Medium |
| Points | 421 |
| Author | 燒餅不加蛋 |
| Handout | [`artifacts/chal-Two-Exponents.zip`](artifacts/chal-Two-Exponents.zip) |
| Solver | [`solve.py`](solve.py) |
| Flag | `THJCC{n0t_c0pr1m3_but_st1ll_br0k3n_4nyw4y}` |

## Overview

The challenge provides two RSA ciphertexts of the same plaintext. Both use the
same modulus, but each was generated with a different public exponent:

```text
c1 = m^111 mod n
c2 = m^39  mod n
```

This resembles the standard RSA common-modulus attack. That attack normally
assumes the exponents are coprime, allowing Bezout coefficients to combine the
ciphertexts into `m`. Here they are deliberately not coprime:

```text
gcd(111, 39) = 3
```

The attack therefore produces `m^3 mod n` rather than `m`. The plaintext is
short enough that its cube is still smaller than the 1023-bit modulus, so no
modular reduction occurred. An exact integer cube root recovers the flag.

## 1. Inspecting the Handout

The original archive contains two files:

```text
chal-Two-Exponents/
|-- README.md
`-- output.txt
```

Their SHA-256 hashes are:

```text
a2f5638e817b3ad2367c66ec9b7ec7ff03f2be5071e8de7d6d3bf8c27777ab64  chal-Two-Exponents.zip
fe552523b6653bbde2ffcbcede3675b5248130f92a7b503746b527551614e3df  README.md
e3d3457fcc730c8712f078dfa6250ec563c814616a0e2108d57571ff3d9eb6f5  output.txt
```

`output.txt` supplies one modulus and two exponent/ciphertext pairs:

```text
n  = 77858147671482407634775491427040805492076980205563716402246138065521424847352748333947251695438000383243920464095595462728641255858191058453473003730294210301598211003700846609849972322991848231552293626273416217314260783103263284010287945923693495357051277469279606933481196189861065420108007616409643776013
e1 = 111
c1 = 18223062994297197653234717982144573569773880742037431830544439999553795195125626505331124696776901462144736197874973901036255517289372748992723223498997000791202721932133429983002886149582411413191392795467958837528737663052532838054771927153786855378458367115645172309532793321789113491998416988084430368204
e2 = 39
c2 = 76348018939213272185590808359388052466934484463344890672730708364972146374564171707212345714373329559752891016395108524379113926994557487020813255966324592722174363480000800186421273525315732093443649340134436194571066648858343990234218106682132787231616400778754021668597178594337592606373176172822415096792
```

There is no padding, random salt, or separate modulus. The two ciphertexts are
raw textbook RSA encryptions of the same integer message.

## 2. Reviewing the Classic Common-Modulus Attack

Suppose the same message is encrypted under one modulus with two coprime
exponents:

```text
c1 = m^e1 mod n
c2 = m^e2 mod n
```

If `gcd(e1, e2) = 1`, the extended Euclidean algorithm finds integers `a` and
`b` satisfying:

```text
a*e1 + b*e2 = 1
```

The ciphertexts can then be combined:

```text
c1^a * c2^b
= (m^e1)^a * (m^e2)^b
= m^(a*e1 + b*e2)
= m                         (mod n)
```

This works without factoring `n` and without recovering either RSA private
key. A negative coefficient is handled using a modular inverse.

## 3. Accounting for the Non-Coprime Exponents

The challenge hint specifically warns us to check the coprimality assumption:

```text
111 = 3 * 37
39  = 3 * 13
gcd(111, 39) = 3
```

The extended Euclidean algorithm returns the coefficients:

```text
6*111 - 17*39 = 3
```

Combining the ciphertexts with those coefficients gives:

```text
c1^6 * c2^-17
= (m^111)^6 * (m^39)^-17
= m^(666 - 663)
= m^3                       (mod n)
```

The negative exponent does not mean ordinary integer exponentiation. It means
the modular inverse of `c2` raised to the positive power 17:

```python
c2_to_minus_17 = pow(pow(c2, -1, n), 17, n)
```

Python's three-argument `pow` computes the inverse directly. If `c2` were not
invertible modulo `n`, `gcd(c2, n)` would instead expose a nontrivial factor of
the RSA modulus. For this instance, the inverse exists.

## 4. Recovering the Integer Message

After the modular combination, we hold a value congruent to `m^3`. In general,
that is not enough to recover `m`: modular cube-root extraction is related to
RSA decryption and normally requires factoring the modulus.

The plaintext in this challenge is much smaller than the modulus. The measured
bit lengths are:

```text
message: 335 bits
m^3:    1004 bits
n:      1023 bits
```

Because the cube has fewer bits than `n`, it is strictly smaller than `n`.
Consequently, reduction modulo `n` did not alter it:

```text
m^3 mod n = m^3
```

An exact integer cube root therefore yields the original message. Floating
point arithmetic is unsuitable for integers this large, so the solver uses a
binary-search integer root and verifies that the result cubes exactly to the
recovered value.

Converting the resulting integer to big-endian bytes produces:

```text
THJCC{n0t_c0pr1m3_but_st1ll_br0k3n_4nyw4y}
```

## 5. Independent Verification

An exact cube root strongly indicates success, but the solver also checks the
candidate against both original RSA equations:

```python
assert pow(message, e1, n) == c1
assert pow(message, e2, n) == c2
```

Both assertions pass. This confirms that the decoded bytes are the one message
which generated both intercepted ciphertexts, rather than an accidental
printable cube root.

## 6. Reproducing the Solve

The included solver uses only Python's standard library:

```bash
python3 solve.py
```

Expected output:

```text
gcd(e1, e2) = 3
Bezout coefficients = (6, -17)
message bits = 335
m^gcd bits = 1004
modulus bits = 1023
flag = THJCC{n0t_c0pr1m3_but_st1ll_br0k3n_4nyw4y}
```

The complete recovery can be summarized in four operations:

1. Calculate `g = gcd(e1, e2)` and the corresponding Bezout coefficients.
2. Combine the ciphertexts with signed modular powers to recover `m^g mod n`.
3. Take an exact integer `g`-th root because the message power did not wrap.
4. Re-encrypt the candidate under both exponents to verify it.

## Lessons

- Textbook RSA is deterministic, so encrypting the same plaintext under the
  same modulus creates algebraic relations between ciphertexts.
- Different public exponents do not make modulus reuse safe.
- A non-unit exponent GCD changes the common-modulus result from `m` to `m^g`;
  it does not necessarily prevent plaintext recovery.
- Short unpadded messages are vulnerable to exact-root attacks whenever the
  relevant power remains below the modulus.
- Real RSA encryption should use a standard randomized padding construction,
  such as RSA-OAEP, and each key pair should have its own modulus.

## Flag

```text
THJCC{n0t_c0pr1m3_but_st1ll_br0k3n_4nyw4y}
```
