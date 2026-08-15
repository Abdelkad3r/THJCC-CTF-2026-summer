#!/usr/bin/env python3
"""Nonce Sense — THJCC CTF 2026 Summer (crypto, 100 pts).

The service issues a fresh secp256k1 keypair each connection and prints two
ECDSA signatures that reuse the same nonce k (identical r). Reused nonces leak
the private key by elementary algebra; from there we forge a signature over the
server's TARGET message and it returns the flag.

No third-party dependencies: the curve arithmetic and key recovery live in
ecdsa_tool.py, implemented from scratch.

    python3 solve.py                 # play against the live service
    python3 solve.py --offline FILE  # recover the key from a saved transcript
"""
from __future__ import annotations

import argparse
import hashlib
import socket
import sys
import time

from ecdsa_tool import Curve, recover, sign

HOST, PORT = "chal.thjcc.org", 12001


def sha256_z(msg: bytes, n: int) -> int:
    """ECDSA message representative: full SHA-256 digest reduced mod n."""
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % n


def parse(buf: bytes):
    pub = tgt = None
    sigs = []
    for line in buf.decode(errors="replace").splitlines():
        f = line.split()
        if not f:
            continue
        if f[0] == "PUB":
            pub = (int(f[1], 16), int(f[2], 16))
        elif f[0] == "SIG":
            sigs.append((bytes.fromhex(f[1]), int(f[2], 16), int(f[3], 16)))
        elif f[0] == "TARGET":
            tgt = bytes.fromhex(f[1])
    return pub, sigs, tgt


def recover_key(cur: Curve, pub, sigs):
    """Recover d from two nonce-reusing signatures; verify against PUB."""
    (m1, r, s1), (m2, r2, s2) = sigs[0], sigs[1]
    if r != r2:
        raise SystemExit("[-] signatures do not share a nonce (r differs)")
    z1, z2 = sha256_z(m1, cur.n), sha256_z(m2, cur.n)
    for k, d in recover(cur, r, s1, s2, z1, z2):
        if cur.mul(d, cur.G) == pub:
            return d, k
    raise SystemExit("[-] key recovery failed (wrong curve/hash assumption?)")


def forge(cur: Curve, d: int, tgt: bytes):
    """Sign TARGET with a fresh, deterministic nonce derived from d and msg."""
    z = sha256_z(tgt, cur.n)
    k = int.from_bytes(
        hashlib.sha256(b"forge" + tgt + d.to_bytes(32, "big")).digest(), "big"
    ) % cur.n or 1
    sig = sign(cur, d, z, k)
    while sig is None:                       # r==0 or s==0: try the next nonce
        k = (k + 1) % cur.n
        sig = sign(cur, d, z, k)
    return sig


def recv_lines(sock, want=4, timeout=10) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while buf.count(b"\n") < want:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def play() -> int:
    cur = Curve("secp256k1")
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        handshake = recv_lines(s, want=4)
        print(handshake.decode(errors="replace").rstrip())
        pub, sigs, tgt = parse(handshake)
        if not (pub and len(sigs) >= 2 and tgt):
            raise SystemExit("[-] incomplete handshake")

        d, k = recover_key(cur, pub, sigs)
        print(f"\n[+] reused nonce  k = {k:#066x}")
        print(f"[+] private key   d = {d:#066x}")
        print(f"[+] verified: d*G == PUB  ->  {cur.mul(d, cur.G) == pub}")

        r, sval = forge(cur, d, tgt)
        line = f"{r:064x} {sval:064x}"
        print(f"[>] {line}")
        s.sendall((line + "\n").encode())
        time.sleep(1.0)
        try:
            s.settimeout(6)
            reply = s.recv(8192).decode(errors="replace").strip()
        except socket.timeout:
            reply = "(timeout)"
        print(f"[<] {reply}")
        return 0 if "FLAG" in reply or "THJCC" in reply else 1


def offline(path: str) -> int:
    cur = Curve("secp256k1")
    with open(path, "rb") as fh:
        pub, sigs, tgt = parse(fh.read())
    if not (pub and len(sigs) >= 2):
        raise SystemExit("[-] transcript missing PUB or two SIG lines")
    d, k = recover_key(cur, pub, sigs)
    print(f"[+] reused nonce  k = {k:#066x}")
    print(f"[+] private key   d = {d:#066x}")
    print(f"[+] verified: d*G == PUB  ->  {cur.mul(d, cur.G) == pub}")
    if tgt:
        r, sval = forge(cur, d, tgt)
        print(f"[+] forged sig for TARGET: {r:064x} {sval:064x}")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", metavar="FILE",
                    help="recover the key from a saved transcript instead of "
                         "connecting")
    args = ap.parse_args()
    sys.exit(offline(args.offline) if args.offline else play())
