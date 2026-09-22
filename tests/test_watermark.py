"""
Unit tests for Stage 2 watermark encoding, embedding, and forensic extraction.
"""
import pytest
import fitz
import hashlib
import os
from watermark import (
    derive_watermark_id,
    encode_watermark_payload,
    decode_watermark_payload,
    embed_watermark_typeB,
    extract_watermark,
)


def create_sample_pdf() -> bytes:
    """Create a sample single-page text PDF for testing."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)
    # Write enough text words to store payload bits
    text = "CONFIDENTIAL FORENSIC FINGERPRINTING SYSTEM SECURITY TEST DOCUMENT " * 25
    page.insert_textbox(fitz.Rect(50, 50, 550, 750), text, fontsize=12)
    pdf_bytes = doc.write()
    doc.close()
    return pdf_bytes


def test_payload_ecc():
    doc_hash = hashlib.sha256(b"sample_pdf_content").hexdigest()
    watermark_id = derive_watermark_id(doc_hash, "CERT-ALICE-001", "session-123", os.urandom(8))
    
    encoded = encode_watermark_payload(watermark_id, doc_hash)
    decoded_id, valid = decode_watermark_payload(encoded, doc_hash)
    
    assert valid is True
    assert decoded_id == watermark_id

    # Corrupt 4 bytes in the payload (Reed-Solomon should recover)
    corrupted = bytearray(encoded)
    corrupted[5] ^= 0xFF
    corrupted[10] ^= 0xAA
    corrupted[15] ^= 0x55
    corrupted[20] ^= 0x12
    
    recovered_id, valid_recovered = decode_watermark_payload(bytes(corrupted), doc_hash)
    assert valid_recovered is True
    assert recovered_id == watermark_id


def test_watermark_typeB_embed_extract():
    pdf_bytes = create_sample_pdf()
    doc_hash = hashlib.sha256(pdf_bytes).hexdigest()
    watermark_id = derive_watermark_id(doc_hash, "CERT-BOB-001", "session-456", b"12345678")
    
    payload = encode_watermark_payload(watermark_id, doc_hash)
    watermarked_pdf = embed_watermark_typeB(pdf_bytes, payload)
    
    extracted_id, valid, method = extract_watermark(pdf_bytes, watermarked_pdf, doc_hash)
    assert valid is True
    assert extracted_id == watermark_id
    assert method == "TypeB-DCT"
