"""
Unit tests for crypto wrappers and identity CA.
"""
import pytest
from crypto import (
    generate_kem_keypair,
    encaps_kem,
    decaps_kem,
    generate_dsa_keypair,
    sign_dsa,
    verify_dsa,
    generate_symmetric_key,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
)
from identity.ca import CertificateAuthority


def test_ml_kem_flow():
    pk, sk = generate_kem_keypair()
    ct, shared_secret = encaps_kem(pk)
    recovered_secret = decaps_kem(sk, ct)
    assert shared_secret == recovered_secret
    assert len(shared_secret) == 32


def test_ml_dsa_flow():
    pk, sk = generate_dsa_keypair()
    msg = b"Forensic Decryption Log Entry"
    sig = sign_dsa(sk, msg)
    assert verify_dsa(pk, msg, sig) is True
    assert verify_dsa(pk, b"Tampered Message", sig) is False


def test_aes_gcm_flow():
    key = generate_symmetric_key()
    plaintext = b"Top Secret Document Content"
    nonce, ciphertext = encrypt_aes_gcm(key, plaintext)
    decrypted = decrypt_aes_gcm(key, nonce, ciphertext)
    assert decrypted == plaintext


def test_ca_certificate_flow():
    ca = CertificateAuthority()
    cert, keys = ca.issue_certificate("Alice Smith", "CERT-ALICE-001")
    assert cert["recipient_id"] == "Alice Smith"
    assert cert["cert_id"] == "CERT-ALICE-001"
    assert ca.verify_certificate(cert) is True
    
    # Test tampered cert
    tampered_cert = cert.copy()
    tampered_cert["recipient_id"] = "Eve Mallory"
    assert ca.verify_certificate(tampered_cert) is False
