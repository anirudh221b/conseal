"""
Watermark Payload formatting & Reed-Solomon Error Correction Code (ECC).
Payload structure:
  watermark_id (16 bytes / 128 bits) || integrity_tag (8 bytes / 64 bits HMAC)
Wrapped in Reed-Solomon ECC for noise and perturbation resistance.
"""
import hmac
import hashlib
from typing import Tuple, Optional
from reedsolo import RSCodec, ReedSolomonError


SYSTEM_SALT = b"CONSEAL-FORENSIC-WATERMARK-SALT-V1"


def derive_watermark_id(
    document_hash: str,
    recipient_cert_id: str,
    session_id: str,
    nonce: bytes
) -> bytes:
    """
    Derive 128-bit (16-byte) watermark ID via HKDF-SHA256.
    
    watermark_id = HKDF-SHA256(
        document_hash || recipient_cert_id || session_id || nonce,
        system_salt
    )[:16]
    """
    info = f"{document_hash}:{recipient_cert_id}:{session_id}".encode("utf-8") + nonce
    hkdf = hmac.new(SYSTEM_SALT, info, hashlib.sha256).digest()
    return hkdf[:16]


def compute_integrity_tag(watermark_id: bytes, document_hash: str) -> bytes:
    """Compute 8-byte HMAC-SHA256 tag over watermark_id and document_hash."""
    data = watermark_id + document_hash.encode("utf-8")
    tag = hmac.new(SYSTEM_SALT, data, hashlib.sha256).digest()
    return tag[:8]


def encode_watermark_payload(watermark_id: bytes, document_hash: str, ecc_symbols: int = 16) -> bytes:
    """
    Encode watermark_id and HMAC integrity tag into an ECC-protected byte stream.
    Total raw payload = 16 bytes (id) + 8 bytes (tag) = 24 bytes.
    With 16 ECC symbols, total encoded payload = 40 bytes (320 bits).
    """
    if len(watermark_id) != 16:
        raise ValueError("watermark_id must be exactly 16 bytes")
        
    tag = compute_integrity_tag(watermark_id, document_hash)
    raw_payload = watermark_id + tag  # 24 bytes
    
    rs = RSCodec(ecc_symbols)
    encoded_payload = rs.encode(raw_payload)
    return bytes(encoded_payload)


def decode_watermark_payload(encoded_payload: bytes, document_hash: str, ecc_symbols: int = 16) -> Tuple[Optional[bytes], bool]:
    """
    Decode Reed-Solomon encoded payload, correct errors, and check HMAC integrity tag.
    
    Returns:
        Tuple[Optional[bytes], bool]: (watermark_id, integrity_valid)
    """
    rs = RSCodec(ecc_symbols)
    try:
        decoded_raw, _, _ = rs.decode(encoded_payload)
        decoded_raw = bytes(decoded_raw)
    except ReedSolomonError:
        return None, False

    if len(decoded_raw) < 24:
        return None, False

    watermark_id = decoded_raw[:16]
    extracted_tag = decoded_raw[16:24]
    expected_tag = compute_integrity_tag(watermark_id, document_hash)

    integrity_valid = hmac.compare_digest(extracted_tag, expected_tag)
    return watermark_id, integrity_valid
