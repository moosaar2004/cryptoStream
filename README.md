# cryptoStream

# Overview
This project implements three cryptographic ciphers in java:

1) A stream cipher using a linear congruential generator (LCG) for keystream generation and a hashed key.
2) An enhanced stream cipher incorporating an 8-byte initialization vector (IV) to prevent keystream reuse.
3) A 10-round Feistel cipher operating on 128-bit blocks with 64-bit keys and PKCS#7 padding.

These ciphers demonstrate fundamental cryptographic techniques for encrypting and decrypting files, handling various edge cases, and ensuring robust file I/O.

# Features
- Stream Cipher: Generates a pseudorandom keystream using an LCG, seeded by a hashed password, to XOR with plaintext.
- Stream Cipher with IV: Adds a random 8-byte IV (stored in little-endian format) to ensure unique ciphertexts for identical inputs.
- Feistel Cipher: Implements a 10-round Feistel structure with a simple round function, 64-bit round keys, and PKCS#7 padding for arbitrary file sizes.
- Handles edge cases: empty files, partial blocks, non-readable files, and invalid command usage.



