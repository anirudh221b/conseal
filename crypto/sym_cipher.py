"""
AES-256-GCM Symmetric File & Data Encryption/Decryption.
Uses cryptography primitives for authenticated encryption with associated data.
"""
import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_symmetric_key() -> bytes:
    """Generate a random 256-bit (32-byte) AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_aes_gcm(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext bytes using AES-256-GCM.
    
    Args:
        key: 32-byte AES key.
        plaintext: Data to encrypt.
        associated_data: Optional authenticated data.
        
    Returns:
        Tuple[bytes, bytes]: (nonce_12bytes, ciphertext_with_tag)
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce standard for AES-GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt ciphertext bytes using AES-256-GCM.
    
    Args:
        key: 32-byte AES key.
        nonce: 12-byte nonce used during encryption.
        ciphertext: Ciphertext payload (includes 16-byte authentication tag).
        associated_data: Optional authenticated data.
        
    Returns:
        bytes: Decrypted plaintext bytes.
    """
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return plaintext
