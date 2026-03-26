#!/usr/bin/env python3
"""
toobcrypt.py - Standalone E2EE Payload Encryption Tool for Toobloader

This tool provides a pure-Python, zero-dependency implementation of the
ChaCha20 stream cipher. It is used to encrypt OTA payloads so they can be
stream-decrypted by bare-metal bootloaders (e.g. Toobloader).

Usage:
  python toobcrypt.py --in firmware.bin --out encrypted.bin --key hex_or_file --nonce hex_or_file

Copyright (c) Toobloader 2026.
"""

import argparse
import sys
import os
import struct

def rotl32(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))

def quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotl32(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotl32(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotl32(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotl32(x[b] ^ x[c], 7)

def chacha20_block(key: bytes, nonce: bytes, counter: int):
    """Generates a 64-byte keystream block."""
    # Magic constants: "expand 32-byte k"
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    
    # Pack key into 8 32-bit integers (little-endian)
    k = list(struct.unpack('<8I', key))
    
    # Pack nonce into 3 32-bit integers (little-endian)
    n = list(struct.unpack('<3I', nonce))
    
    # Pack counter and nonce exactly as the C implementation does:
    # state[12] = lower 32-bits of counter
    # state[13] = nonce[0] + upper 32-bits of counter
    # state[14] = nonce[1]
    # state[15] = nonce[2]
    counter_low = counter & 0xffffffff
    counter_high = (counter >> 32) & 0xffffffff
    
    c_n = [
        counter_low,
        (n[0] + counter_high) & 0xffffffff,
        n[1],
        n[2]
    ]

    # Initial state
    state = constants + k + c_n
    working_state = list(state)
    
    for _ in range(10):
        # Column rounds
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)
        # Diagonal rounds
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)
        
    for i in range(16):
        state[i] = (state[i] + working_state[i]) & 0xffffffff
        
    return struct.pack('<16I', *state)

def chacha20_encrypt(data: bytes, key: bytes, nonce: bytes, initial_counter: int = 0) -> bytes:
    """Encrypts/Decrypts arbitrary length data using ChaCha20."""
    out = bytearray()
    counter = initial_counter
    
    for i in range(0, len(data), 64):
        block = chacha20_block(key, nonce, counter)
        chunk = data[i:i+64]
        for j in range(len(chunk)):
            out.append(chunk[j] ^ block[j])
        counter += 1
        
    return bytes(out)

def load_hex_or_file(val: str, expected_len: int, name: str) -> bytes:
    if os.path.isfile(val):
        with open(val, "rb") as f:
            b = f.read(expected_len)
    else:
        try:
            b = bytes.fromhex(val)
        except ValueError:
            print(f"[!] Invalid hex string for {name}.")
            sys.exit(1)
            
    if len(b) != expected_len:
        print(f"[!] Error: {name} must be exactly {expected_len} bytes (got {len(b)}).")
        sys.exit(1)
    return b

def main():
    parser = argparse.ArgumentParser(description="Toobloader Standalone ChaCha20 Encryption Tool")
    parser.add_argument("--in-file", required=True, help="Input firmware binary (.bin)")
    parser.add_argument("--out-file", required=True, help="Output encrypted binary (.bin)")
    parser.add_argument("--key", required=True, help="32-byte FEK (Hex string or filepath)")
    # We default to a zero nonce just like the bootloader expects unless overridden
    parser.add_argument("--nonce", default="000000000000000000000000", help="12-byte Nonce (Hex string or filepath)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.in_file):
        print(f"[!] Input file '{args.in_file}' not found.")
        sys.exit(1)
        
    key_bytes = load_hex_or_file(args.key, 32, "Encryption Key")
    nonce_bytes = load_hex_or_file(args.nonce, 12, "Nonce")
    
    with open(args.in_file, "rb") as f:
        plaintext = f.read()
        
    print(f"[*] Encrypting {len(plaintext)} bytes using ChaCha20-256...")
    ciphertext = chacha20_encrypt(plaintext, key_bytes, nonce_bytes)
    
    with open(args.out_file, "wb") as f:
        f.write(ciphertext)
        
    print(f"[*] SUCCESS: Wrote encrypted payload to '{args.out_file}'")

if __name__ == "__main__":
    main()
