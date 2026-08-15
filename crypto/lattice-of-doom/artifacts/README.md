# Lattice of Doom (hard)

We shipped a hardware wallet. It signs with secp256k1 ECDSA, the private key
never leaves the secure element, and here are 60 signatures it produced — go
ahead, they are public on the ledger anyway.

Someone leaked a fragment of the firmware's signing routine
(`signer_excerpt.py`). The engineer's comment claims the nonce space is larger
than the number of atoms in the observable universe. They are not wrong about
the number. They are wrong about why that does not save them.

Files: `output.json`, `signer_excerpt.py`

`output.json` contains the public key, the signatures, and the flag encrypted
with a key derived from the private scalar (the derivation is documented in
the file).

> Hint: brute force is not the intended solution, and neither is any amount of
> guessing. Each signature tells you something *small* about a linear
> combination of the secret. Many small things together are a lattice problem.

Flag format: `THJCC{...}`
