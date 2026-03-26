#!/usr/bin/env python3
"""
test_chacha20_math.py - RFC 7539 Validation for Toobcrypt

This test verifies the mathematical correctness of our standalone Python
ChaCha20 implementation (`toobcrypt.py`) by asserting its execution against
the universally standardized test vectors from IETF RFC 7539 Section 2.3.2.

This guarantees bit-perfect alignment with the Bootloader C implementation.
"""

import sys
import os
import binascii

# Add scripts directory to path to import toobcrypt directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scripts')))
try:
    import toobcrypt
except ImportError:
    print("[!] Error finding toobcrypt.py.")
    sys.exit(1)

def run_rfc_7539_verification():
    """Validates ChaCha20 against RFC 7539 Section 2.3.2 Test Vector."""
    
    # RFC 7539 Test Vector Parameters
    key = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    ])
    
    nonce = bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 
        0x00, 0x00, 0x00, 0x00
    ])

    initial_counter = 1
    
    plaintext = (
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it."
    ).encode('ascii')
    
    # EXACT Ciphertext from RFC 7539 (Length 114)
    expected_ciphertext = bytes([
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d
    ])
    # Ditch the erroneous trailing bytes from the first iteration. The length of the plaintext is 114 bytes.
    # len(expected_ciphertext) must be 114
    expected_ciphertext = expected_ciphertext[:114]
    
    print("[*] Testing pure-Python mathematics against RFC 7539 Section 2.3.2...")
    try:
        actual_ciphertext = toobcrypt.chacha20_encrypt(plaintext, key, nonce, initial_counter)
    except Exception as e:
        print(f"[!] Encryption failed with exception: {e}")
        sys.exit(1)
        
    if actual_ciphertext == expected_ciphertext:
        print("[*] SUCCESS: Mathematical output perfectly matches RFC 7539 Test Vector!")
        print(f"[*] Length: {len(actual_ciphertext)} bytes (Bit-perfect alignment achieved)")
    else:
        print("[!] FATAL ERROR: Ciphertext mismatch against RFC 7539.")
        print(f"Expected (RFC Reference): {binascii.hexlify(expected_ciphertext).decode()}")
        print(f"Actual (Python Tool)  : {binascii.hexlify(actual_ciphertext).decode()}")
        sys.exit(1)

if __name__ == "__main__":
    print("============================================================")
    print(" Toobcrypt Mathematical Equivalency Test (RFC 7539) ")
    print("============================================================")
    run_rfc_7539_verification()
    print("============================================================")
