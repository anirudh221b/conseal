"""
ML-DSA-65 (FIPS 204) Post-Quantum Digital Signature wrapper.
Uses pqcrypto native implementation.
"""
from typing import Tuple
from pqcrypto.sign import ml_dsa_65
from pqcrypto import InvalidSignatureError


def generate_dsa_keypair() -> Tuple[bytes, bytes]:
    """
    Generate an ML-DSA-65 public and secret key pair.
    
    Returns:
        Tuple[bytes, bytes]: (public_key, secret_key)
    """
    pk, sk = ml_dsa_65.keygen()
    return pk, sk


def sign_dsa(secret_key: bytes, message: bytes) -> bytes:
    """
    Sign a message using an ML-DSA-65 secret key.
    
    Args:
        secret_key: Signer's ML-DSA-65 secret key.
        message: Canonical byte sequence to sign.
        
    Returns:
        bytes: Signature bytes.
    """
    signature = ml_dsa_65.sign(secret_key, message)
    return signature


def verify_dsa(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify an ML-DSA-65 signature over a message using a public key.
    
    Args:
        public_key: Signer's ML-DSA-65 public key.
        message: Canonical byte sequence that was signed.
        signature: Signature bytes to verify.
        
    Returns:
        bool: True if signature is valid, False otherwise.
    """
    try:
        ml_dsa_65.verify(public_key, message, signature)
        return True
    except (InvalidSignatureError, ValueError, Exception):
        return False
