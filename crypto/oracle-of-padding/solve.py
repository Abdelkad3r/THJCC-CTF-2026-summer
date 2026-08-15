#!/usr/bin/env python3
import socket


HOST = "chal.thjcc.org"
PORT = 12000
BLOCK_SIZE = 16


class Oracle:
    def __init__(self):
        self.sock = socket.create_connection((HOST, PORT), timeout=10)
        self.file = self.sock.makefile("rwb", buffering=0)
        banner = self.file.readline().strip().split()
        if len(banner) != 2 or banner[0] != b"TOKEN":
            raise RuntimeError(f"Unexpected banner: {b' '.join(banner)!r}")
        self.token = bytes.fromhex(banner[1].decode())
        self.queries = 0

    def batch(self, ciphertexts):
        payload = b"".join(value.hex().encode() + b"\n" for value in ciphertexts)
        self.sock.sendall(payload)
        replies = []
        for _ in ciphertexts:
            line = self.file.readline().strip()
            if not line:
                raise EOFError("Oracle closed the connection")
            replies.append(line == b"OK")
        self.queries += len(ciphertexts)
        return replies

    def close(self):
        self.file.close()
        self.sock.close()


def recover_intermediate(oracle, target):
    intermediate = bytearray(BLOCK_SIZE)

    for position in range(BLOCK_SIZE - 1, -1, -1):
        padding = BLOCK_SIZE - position
        base = bytearray(BLOCK_SIZE)
        for index in range(position + 1, BLOCK_SIZE):
            base[index] = intermediate[index] ^ padding

        probes = []
        for guess in range(256):
            crafted = bytearray(base)
            crafted[position] = guess
            probes.append(bytes(crafted) + target)

        valid = [guess for guess, ok in enumerate(oracle.batch(probes)) if ok]

        # A last-byte probe can accidentally preserve a longer valid padding.
        # Flip the preceding byte: true 0x01 padding survives, longer padding does not.
        if position == BLOCK_SIZE - 1 and len(valid) > 1:
            confirmations = []
            confirm_probes = []
            for guess in valid:
                crafted = bytearray(base)
                crafted[position] = guess
                crafted[position - 1] ^= 1
                confirm_probes.append(bytes(crafted) + target)
            for guess, ok in zip(valid, oracle.batch(confirm_probes)):
                if ok:
                    confirmations.append(guess)
            valid = confirmations

        if len(valid) != 1:
            raise RuntimeError(
                f"Expected one valid guess at position {position}, got {valid}"
            )

        intermediate[position] = valid[0] ^ padding

    return bytes(intermediate)


def pkcs7_unpad(data):
    if not data:
        raise ValueError("Empty plaintext")
    amount = data[-1]
    if amount == 0 or amount > BLOCK_SIZE or data[-amount:] != bytes([amount]) * amount:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-amount]


def main():
    oracle = Oracle()
    try:
        blocks = [
            oracle.token[offset:offset + BLOCK_SIZE]
            for offset in range(0, len(oracle.token), BLOCK_SIZE)
        ]
        if len(blocks) < 2 or any(len(block) != BLOCK_SIZE for block in blocks):
            raise ValueError(f"Unexpected token length: {len(oracle.token)}")

        plaintext = bytearray()
        for number in range(1, len(blocks)):
            intermediate = recover_intermediate(oracle, blocks[number])
            block = bytes(a ^ b for a, b in zip(intermediate, blocks[number - 1]))
            plaintext.extend(block)
            print(f"[{number}/{len(blocks) - 1}] {block!r}", flush=True)

        plaintext = pkcs7_unpad(bytes(plaintext))
        print(f"queries: {oracle.queries}")
        print(f"plaintext: {plaintext.decode('utf-8', errors='replace')}")
    finally:
        oracle.close()


if __name__ == "__main__":
    main()
