"""
Forensic Watermark Extractor (Non-blind comparison against original document).
Extracts bits via DCT differential analysis and text alignment diffs,
locates SYNC_MARKER, and decodes Reed-Solomon payload.
"""
import fitz
import numpy as np
from PIL import Image
from typing import Tuple, Optional, List
from watermark.payload import decode_watermark_payload
from watermark.embed_typeA import SYNC_MARKER, bits_to_bytes
from watermark.embed_typeB import dct2d


def extract_bits_from_dct(leaked_pdf_bytes: bytes) -> List[int]:
    """Extract raw bitstream from PDF page image 8x8 DCT coefficients."""
    bits = []
    doc = fitz.open(stream=leaked_pdf_bytes, filetype="pdf")

    for page in doc:
        pix = page.get_pixmap(dpi=150)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        y_channel = img.convert("YCbCr").split()[0]
        y_np = np.array(y_channel, dtype=np.float32)

        h, w = y_np.shape
        for r in range(0, h - 7, 8):
            for c in range(0, w - 7, 8):
                block = y_np[r:r+8, c:c+8]
                dct_block = dct2d(block)
                diff = dct_block[4, 3] - dct_block[3, 4]
                bit = 1 if diff > 0 else 0
                bits.append(bit)

    doc.close()
    return bits


def extract_watermark(
    original_pdf_bytes: bytes,
    leaked_pdf_bytes: bytes,
    document_hash: str,
    ecc_symbols: int = 16
) -> Tuple[Optional[bytes], bool, str]:
    """
    Extract forensic watermark from a leaked PDF file.
    
    Args:
        original_pdf_bytes: Original unwatermarked PDF file.
        leaked_pdf_bytes: Leaked / suspect PDF file.
        document_hash: Expected document SHA-256 hash.
        ecc_symbols: Reed-Solomon ECC symbol count (default 16).
        
    Returns:
        Tuple[Optional[bytes], bool, str]:
            - watermark_id (16 bytes hex/raw if found, None otherwise)
            - integrity_valid (True if HMAC tag matches)
            - method_used ("TypeB-DCT" or "TypeA-Text")
    """
    # 1. Try Type B DCT spread-spectrum extraction first
    extracted_bits = extract_bits_from_dct(leaked_pdf_bytes)
    
    # Search for SYNC_MARKER in bitstream
    sync_bits = []
    for b in SYNC_MARKER:
        for i in range(7, -1, -1):
            sync_bits.append((b >> i) & 1)
    sync_len = len(sync_bits)
    
    payload_bit_len = (24 + ecc_symbols) * 8  # 40 bytes = 320 bits
    
    found_idx = -1
    for i in range(len(extracted_bits) - sync_len - payload_bit_len + 1):
        if extracted_bits[i:i+sync_len] == sync_bits:
            found_idx = i
            break
            
    if found_idx != -1:
        payload_bits = extracted_bits[found_idx + sync_len : found_idx + sync_len + payload_bit_len]
        payload_bytes = bits_to_bytes(payload_bits)
        
        w_id, valid = decode_watermark_payload(payload_bytes, document_hash, ecc_symbols=ecc_symbols)
        if w_id and valid:
            return w_id, True, "TypeB-DCT"

    # 2. Try text word shift non-blind extraction (Type A)
    orig_doc = fitz.open(stream=original_pdf_bytes, filetype="pdf")
    leak_doc = fitz.open(stream=leaked_pdf_bytes, filetype="pdf")
    
    text_bits = []
    try:
        for page_num in range(min(len(orig_doc), len(leak_doc))):
            orig_words = sorted(orig_doc[page_num].get_text("words"), key=lambda w: (round(w[1], 1), w[0]))
            leak_words = sorted(leak_doc[page_num].get_text("words"), key=lambda w: (round(w[1], 1), w[0]))
            
            for ow, lw in zip(orig_words, leak_words):
                diff_x = lw[0] - ow[0]
                # If shifted positive -> 1, negative -> 0
                bit = 1 if diff_x > 0 else 0
                text_bits.append(bit)
                
        # Search SYNC_MARKER in text bits
        for i in range(len(text_bits) - sync_len - payload_bit_len + 1):
            if text_bits[i:i+sync_len] == sync_bits:
                payload_bits = text_bits[i + sync_len : i + sync_len + payload_bit_len]
                payload_bytes = bits_to_bytes(payload_bits)
                w_id, valid = decode_watermark_payload(payload_bytes, document_hash, ecc_symbols=ecc_symbols)
                if w_id and valid:
                    return w_id, True, "TypeA-Text"
    except Exception:
        pass
    finally:
        orig_doc.close()
        leak_doc.close()

    return None, False, "None"
