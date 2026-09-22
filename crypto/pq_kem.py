"""
ML-KEM-768 (FIPS 203) Key Encapsulation Mechanism wrapper.
Uses pqcrypto native implementation.
"""
from typing import Tuple
from pqcrypto.kem import ml_kem_768


def generate_kem_keypair() -> Tuple[bytes, bytes]:
    """
    Generate an ML-KEM-768 public and secret key pair.
    
    Returns:
        Tuple[bytes, bytes]: (public_key, secret_key)
    """
    pk, sk = ml_kem_768.keygen()
    return pk, sk


def encaps_kem(public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsulate a random shared secret using the recipient's ML-KEM-768 public key.
    
    Args:
        public_key: Recipient's ML-KEM-768 public key bytes.
        
    Returns:
        Tuple[bytes, bytes]: (ciphertext, shared_secret_32bytes)
    """
    ciphertext, shared_secret = ml_kem_768.encaps(public_key)
    return ciphertext, shared_secret


def decaps_kem(secret_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate a shared secret from ciphertext using the recipient's ML-KEM-768 secret key.
    
    Args:
        secret_key: Recipient's ML-KEM-768 secret key bytes.
        ciphertext: Encapsulated KEM ciphertext.
        
    Returns:
        bytes: The recovered 32-byte shared secret.
    """
    shared_secret = ml_kem_768.decaps(secret_key, ciphertext)
    return shared_secret
