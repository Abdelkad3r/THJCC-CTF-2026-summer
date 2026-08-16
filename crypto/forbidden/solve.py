#!/usr/bin/env python3
"""Forbidden — THJCC CTF 2026 Summer (crypto, 248 pts).

An AES-GCM "vault" that reuses a single nonce for every message it hands you.
Nonce reuse in GCM is *forbidden* precisely because it breaks authentication:
given a few (plaintext, ciphertext, tag) triples under one nonce, the GHASH
subkey H can be recovered and arbitrary tags forged. This is the classic
"Forbidden Attack" (Joux).

The service prints:

    NONCE  <96-bit nonce, reused>
    MSG    <plaintext_hex> <ciphertext_hex> <tag_hex>   x3
    TARGET <plaintext_hex>                 ("give me the flag")

We forge a valid ciphertext+tag for TARGET and send back "<ct_hex> <tag_hex>".

Two leaks, both from the reused nonce:
  * keystream reuse:  ct = pt XOR keystream, and keystream = pt XOR ct of any
    known message, so the target ciphertext is trivial.
  * GHASH-key recovery: T = GHASH_H(C) XOR S, with H = E_K(0) and S = E_K(J0)
    both constant across the reused nonce. Define f_i(H) = GHASH(C_i) XOR T_i;
    every message gives f_i(H) = S, so pairwise differences P_ij = f_i XOR f_j
    are polynomials in GF(2^128) with H as a root. gcd(P_12, P_13) is degree 1
    -> H directly, no root-finding. Then S = f_0(H), and the forged tag is
    GHASH_H(ct) XOR S.

No third-party crypto library: the GF(2^128) field, polynomials over it, and
Euclidean polynomial GCD are implemented from scratch.

    python3 solve.py            # play the live service
    python3 solve.py --offline artifacts/protocol-sample.txt
"""
from __future__ import annotations

import socket
import struct
import sys
import time

HOST, PORT = "chal.thjcc.org", 12002

# ---------------------------------------------------------------------------
# GF(2^128) with the GCM convention (a 16-byte block is int.from_bytes(b,"big");
# the multiplicative identity is 1<<127; reduction poly x^128+x^7+x^2+x+1).
# ---------------------------------------------------------------------------
_R = 0xE1 << 120
ONE = 1 << 127


def gmul(x: int, y: int) -> int:
    z, v = 0, x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ _R if v & 1 else v >> 1
    return z


def gpow(x: int, n: int) -> int:
    r = ONE
    while n:
        if n & 1:
            r = gmul(r, x)
        x = gmul(x, x)
        n >>= 1
    return r


def ginv(x: int) -> int:
    return gpow(x, (1 << 128) - 2)


# ---------------------------------------------------------------------------
# polynomials over GF(2^128): coefficient lists, index = power, low-order first.
# ---------------------------------------------------------------------------
def p_trim(p):
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p


def p_add(a, b):
    n = max(len(a), len(b))
    r = [(a[i] if i < len(a) else 0) ^ (b[i] if i < len(b) else 0) for i in range(n)]
    return p_trim(r)


def p_divmod(a, b):
    a = a[:]
    b = p_trim(b[:])
    binv = ginv(b[-1])
    q = [0] * max(0, len(a) - len(b) + 1)
    while p_trim(a) != [0] and len(a) >= len(b):
        if a[-1] == 0:
            a.pop()
            continue
        d = len(a) - len(b)
        c = gmul(a[-1], binv)
        q[d] = c
        for i in range(len(b)):
            a[d + i] ^= gmul(b[i], c)
        a = p_trim(a)
        if len(a) < len(b):
            break
    return p_trim(q), p_trim(a)


def p_gcd(a, b):
    a, b = p_trim(a[:]), p_trim(b[:])
    while b != [0]:
        _, r = p_divmod(a, b)
        a, b = b, r
    inv = ginv(a[-1])                       # make monic
    return [gmul(c, inv) for c in a]


def p_eval(poly, x):
    r = 0
    for c in reversed(poly):
        r = gmul(r, x) ^ c
    return r


def b2e(b: bytes) -> int:
    return int.from_bytes(b, "big")


# ---------------------------------------------------------------------------
# GHASH as a polynomial in H (no AAD here). GHASH = B1 H^m + ... + Bm H^1,
# blocks = ciphertext blocks (zero-padded) then the 64|64-bit length block.
# ---------------------------------------------------------------------------
def ghash_poly(ct: bytes, aad: bytes = b""):
    def blocks(x):
        return [b2e(x[i:i + 16].ljust(16, b"\x00")) for i in range(0, len(x), 16)]

    B = blocks(aad) + blocks(ct)
    B.append(b2e(struct.pack(">QQ", len(aad) * 8, len(ct) * 8)))
    m = len(B)
    poly = [0] * (m + 1)
    for i, Bi in enumerate(B):
        poly[m - i] ^= Bi                   # B[0] -> H^m, B[m-1] -> H^1
    return p_trim(poly)


# ---------------------------------------------------------------------------
# the forbidden attack
# ---------------------------------------------------------------------------
def recover_H_S(trips):
    """trips: list of (pt, ct, tag). Returns (H, S)."""
    f = [p_add(ghash_poly(ct), [b2e(tag)]) for (_pt, ct, tag) in trips]
    g = p_gcd(p_add(f[0], f[1]), p_add(f[0], f[2]))
    if len(g) != 2:
        raise ValueError(f"gcd is degree {len(g) - 1}, expected 1")
    H = g[0]                                # monic (x + H): root is the constant
    S = p_eval(f[0], H)
    if not all(p_eval(fi, H) == S for fi in f):
        raise ValueError("S inconsistent across messages -- wrong H")
    return H, S


def forge(trips, target):
    H, S = recover_H_S(trips)
    pt0, ct0, _ = max(trips, key=lambda t: len(t[0]))
    keystream = bytes(a ^ b for a, b in zip(pt0, ct0))
    ct = bytes(a ^ b for a, b in zip(target, keystream[:len(target)]))
    tag = (p_eval(ghash_poly(ct), H) ^ S).to_bytes(16, "big")
    return ct, tag, H, S


# ---------------------------------------------------------------------------
# protocol
# ---------------------------------------------------------------------------
def parse(buf: bytes):
    nonce = target = None
    trips = []
    for line in buf.decode(errors="replace").splitlines():
        f = line.split()
        if not f:
            continue
        if f[0] == "NONCE":
            nonce = bytes.fromhex(f[1])
        elif f[0] == "MSG":
            trips.append((bytes.fromhex(f[1]), bytes.fromhex(f[2]), bytes.fromhex(f[3])))
        elif f[0] == "TARGET":
            target = bytes.fromhex(f[1])
    return nonce, trips, target


def play() -> int:
    s = socket.create_connection((HOST, PORT), timeout=15)
    s.settimeout(8)
    buf = b""
    while buf.count(b"\n") < 5:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    print(buf.decode(errors="replace").rstrip())

    nonce, trips, target = parse(buf)
    ct, tag, H, S = forge(trips, target)
    print(f"\n[+] H = {H:#034x}")
    print(f"[+] S = {S:#034x}  (consistent across all messages)")
    print(f"[+] forged ct  = {ct.hex()}")
    print(f"[+] forged tag = {tag.hex()}")

    line = f"{ct.hex()} {tag.hex()}"
    s.sendall((line + "\n").encode())
    time.sleep(1.0)
    try:
        s.settimeout(6)
        reply = s.recv(4096).decode(errors="replace").strip()
    except socket.timeout:
        reply = "(timeout)"
    print(f"[<] {reply}")
    return 0 if "FLAG" in reply or "THJCC" in reply else 1


def offline(path: str) -> int:
    with open(path, "rb") as fh:
        nonce, trips, target = parse(fh.read())
    H, S = recover_H_S(trips)
    print(f"[+] H = {H:#034x}")
    print(f"[+] S = {S:#034x}")
    if target:
        ct, tag, _, _ = forge(trips, target)
        print(f"[+] forged ct/tag for TARGET: {ct.hex()} {tag.hex()}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--offline":
        sys.exit(offline(sys.argv[2]))
    sys.exit(play())
