# Leaked excerpt from the hardware wallet firmware (wallet-v1).
#
# The chip's TRNG hands us 8 bits at a time and the read is slow, so we
# shortened the loop a little. Still 10^69 possibilities, which is more atoms
# than there are in the observable universe, so this is completely fine.

NONCE_BYTES = 29


def make_nonce(trng):
    return int.from_bytes(trng.read(NONCE_BYTES), "big")


def sign(d, msg, trng):
    k = make_nonce(trng)
    r = (k * G).x() % N
    s = pow(k, -1, N) * (sha256_int(msg) + r * d) % N
    return r, s
