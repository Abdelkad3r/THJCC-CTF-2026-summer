#!/usr/bin/env python3
"""Solve Two Exponents using the non-coprime common-modulus attack."""

from __future__ import annotations

import math
import re
from pathlib import Path


OUTPUT = Path(__file__).with_name("artifacts") / "output.txt"


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (g, x, y) such that ax + by = g = gcd(a, b)."""
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_gcd(b, a % b)
    return gcd, y1, x1 - (a // b) * y1


def signed_modular_power(value: int, exponent: int, modulus: int) -> int:
    """Evaluate a modular power whose exponent may be negative."""
    if exponent >= 0:
        return pow(value, exponent, modulus)
    return pow(pow(value, -1, modulus), -exponent, modulus)


def integer_nth_root(value: int, degree: int) -> tuple[int, bool]:
    """Return floor(value**(1/degree)) and whether the root is exact."""
    low, high = 0, 1
    while high**degree <= value:
        high *= 2

    while low + 1 < high:
        middle = (low + high) // 2
        if middle**degree <= value:
            low = middle
        else:
            high = middle

    return low, low**degree == value


def main() -> None:
    values = {
        name: int(number)
        for name, number in re.findall(
            r"^(n|e1|c1|e2|c2)\s*=\s*(\d+)$", OUTPUT.read_text(), re.MULTILINE
        )
    }
    if values.keys() != {"n", "e1", "c1", "e2", "c2"}:
        raise RuntimeError("failed to parse all RSA parameters")

    n = values["n"]
    e1, e2 = values["e1"], values["e2"]
    c1, c2 = values["c1"], values["c2"]

    gcd, coefficient1, coefficient2 = extended_gcd(e1, e2)
    assert gcd == math.gcd(e1, e2)
    assert coefficient1 * e1 + coefficient2 * e2 == gcd

    message_to_gcd = (
        signed_modular_power(c1, coefficient1, n)
        * signed_modular_power(c2, coefficient2, n)
    ) % n

    message, exact = integer_nth_root(message_to_gcd, gcd)
    if not exact:
        raise RuntimeError("m^gcd wrapped modulo n; exact root not recovered")

    plaintext = message.to_bytes((message.bit_length() + 7) // 8, "big")

    # Verify the candidate independently against both intercepted ciphertexts.
    assert pow(message, e1, n) == c1
    assert pow(message, e2, n) == c2

    print(f"gcd(e1, e2) = {gcd}")
    print(f"Bezout coefficients = ({coefficient1}, {coefficient2})")
    print(f"message bits = {message.bit_length()}")
    print(f"m^gcd bits = {message_to_gcd.bit_length()}")
    print(f"modulus bits = {n.bit_length()}")
    print(f"flag = {plaintext.decode()}")


if __name__ == "__main__":
    main()
