"""Pure-python ECDSA: curve params, point ops, key recovery from nonce reuse."""
import hashlib

CURVES = {
    "secp256k1": dict(
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        a=0, b=7,
        n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        Gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        Gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    ),
    "secp256r1": dict(
        p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        Gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        Gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    ),
}


class Curve:
    def __init__(self, name):
        c = CURVES[name]
        self.name = name
        self.p, self.a, self.b, self.n = c["p"], c["a"], c["b"], c["n"]
        self.G = (c["Gx"], c["Gy"])

    def inv(self, x, m):
        return pow(x % m, -1, m)

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        (x1, y1), (x2, y2) = P, Q
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None
        if P == Q:
            m = (3 * x1 * x1 + self.a) * self.inv(2 * y1, self.p) % self.p
        else:
            m = (y2 - y1) * self.inv(x2 - x1, self.p) % self.p
        x3 = (m * m - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def mul(self, k, P):
        R = None
        k %= self.n
        while k:
            if k & 1:
                R = self.add(R, P)
            P = self.add(P, P)
            k >>= 1
        return R

    def on_curve(self, P):
        if P is None:
            return False
        x, y = P
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0


def hash_variants(msg: bytes, n: int):
    """Yield (label, z) candidate message representatives."""
    nbits = n.bit_length()
    for hname in ("sha256", "sha1", "sha512", "sha3_256", "md5"):
        h = hashlib.new(hname, msg).digest()
        e = int.from_bytes(h, "big")
        # ECDSA truncation: take leftmost nbits
        excess = len(h) * 8 - nbits
        z = e >> excess if excess > 0 else e
        yield f"{hname}", z % n
        yield f"{hname}|full", e % n
    # raw message as integer (no hash), and left-truncated
    e = int.from_bytes(msg, "big")
    yield "raw", e % n


def recover(curve: Curve, r, s1, s2, z1, z2):
    """Recover (k, d) from two sigs sharing nonce. Try both nonce-sign options."""
    n = curve.n
    for sk in (s1 - s2, s2 - s1):
        for zd in ((z1 - z2),):
            try:
                k = zd * curve.inv(sk, n) % n
            except ValueError:
                continue
            for kk in (k, -k % n):
                try:
                    d = (s1 * kk - z1) * curve.inv(r, n) % n
                except ValueError:
                    continue
                yield kk, d


def sign(curve: Curve, d, z, k):
    n = curve.n
    R = curve.mul(k, curve.G)
    r = R[0] % n
    s = curve.inv(k, n) * (z + r * d) % n
    if r == 0 or s == 0:
        return None
    return r, s
