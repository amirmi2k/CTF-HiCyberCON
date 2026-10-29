---
name: ctf-crypto
description: >-
  Activate this skill when a CTF challenge involves cryptography, ciphers,
  encoded data, or math-based puzzles. Covers classical ciphers, RSA attacks,
  AES weaknesses, hash cracking, elliptic curve crypto, and protocol flaws.
  Also handles encoding/decoding tasks (base64, hex, etc.).
---

# CTF Cryptography Skill

## Step 1 — Identify What You Have
```bash
# Identify encoding
file <file>
xxd <file> | head
# Try: base64, base32, hex, rot13, URL encoding, binary

# Quick decode chain
echo "<data>" | base64 -d
echo "<data>" | xxd -r -p
python3 -c "import base64; print(base64.b32decode('<data>'))"
```

## Classical Ciphers
```python
# Caesar / ROT
from string import ascii_lowercase
def caesar(text, shift):
    return ''.join(chr((ord(c)-97+shift)%26+97) if c.isalpha() else c for c in text.lower())
# Try all 26 shifts

# Vigenère (unknown key → use Index of Coincidence)
# Tool: https://www.dcode.fr/vigenere-cipher

# XOR (single-byte key)
ciphertext = bytes.fromhex("<hex>")
for key in range(256):
    plain = bytes(b ^ key for b in ciphertext)
    if b'flag' in plain.lower() or b'CTF' in plain:
        print(key, plain)
```

## RSA Attacks
```python
from Crypto.Util.number import *
from sympy import factorint

# Small N → factordb / sympy
n = <N>
factors = factorint(n)  # or query factordb.com

# Small e / large plaintext → cube root
import gmpy2
c = <C>; e = 3
m, exact = gmpy2.iroot(c, e)

# Common modulus attack (same N, different e, same plaintext)
# e1*s1 + e2*s2 = 1 → m = pow(c1,s1,n) * pow(c2,s2,n) % n

# Wiener's attack (small d)
# Use owiener library

# LSB Oracle
# Chosen ciphertext: double plaintext each iteration

# Hastad broadcast (same e, k ciphertexts, different N)
# CRT → e-th root
```

## AES Attacks
```python
# ECB mode → block pattern analysis
# Identical plaintext blocks → identical ciphertext blocks

# CBC bit-flipping
# Modify byte i in ciphertext → flips byte i+16 in plaintext

# CBC padding oracle
# Tool: padbuster, python-paddingoracle

# CTR nonce reuse
# XOR two ciphertexts → XOR of plaintexts

# AES-GCM nonce reuse
# Recover auth key H, forge tags
```

## Hash Attacks
```bash
# Identify hash type
hash-identifier <hash>
hashid <hash>

# Crack with hashcat
hashcat -m 0 <hash_file> rockyou.txt        # MD5
hashcat -m 1000 <hash_file> rockyou.txt     # NTLM
hashcat -m 1800 <hash_file> rockyou.txt     # SHA-512

# MD5 length extension
hashpump -s <signature> -d <data> -a <append> -k <key_len>
```

## Elliptic Curve
```python
# Invalid curve attack
# ECDSA nonce reuse (k reuse) → private key recovery
# Pohlig-Hellman (smooth order subgroup)
# Use SageMath for ECC math
```

## Useful Libraries
```bash
pip install pycryptodome gmpy2 sympy owiener
# SageMath for advanced math
```

## Structured Output
```json
{
  "agent": "ctf-crypto",
  "cipher_identified": "",
  "attack_applied": "",
  "decoded_data": "",
  "flag_candidates": [],
  "confidence": 0.0
}
```
