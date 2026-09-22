"""
Type A Watermarking: Micro glyph/word-spacing perturbation for text-heavy PDFs.
Uses PyMuPDF (fitz) to modify word positioning imperceptibly according to watermark payload bits.
"""
import fitz
import numpy as np
from typing import Tuple, List


SYNC_MARKER = b"\xA5\x5A\x3C"  # 24-bit sync frame


def bytes_to_bits(data: bytes) -> List[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: List[int]) -> bytes:
    bytes_list = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) < 8:
            break
        val = 0
        for b in byte_bits:
            val = (val << 1) | b
        bytes_list.append(val)
    return bytes(bytes_list)


def embed_watermark_typeA(pdf_bytes: bytes, payload_bytes: bytes, delta_pt: float = 0.35) -> bytes:
    """
    Embed watermark payload into a text PDF via micro horizontal word-spacing shifts.
    
    Args:
        pdf_bytes: Original PDF input bytes.
        payload_bytes: Encoded Reed-Solomon payload bytes.
        delta_pt: Shift magnitude in points (0.35pt is visually imperceptible to humans).
        
    Returns:
        bytes: Watermarked PDF output bytes.
    """
    full_payload = SYNC_MARKER + payload_bytes
    bits = bytes_to_bits(full_payload)
    bit_len = len(bits)
    
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    bit_idx = 0
    
    for page in doc:
        # Extract words: (x0, y0, x1, y1, word, block_no, line_no, word_no)
        words = page.get_text("words")
        if not words:
            continue
            
        # Re-render page with perturbed word positions
        # Create a drawing canvas overlay or recreate text layer cleanly
        # PyMuPDF allows page.insert_text or redrawing
        # To make shifts precise, we create a clean copy page where words are drawn with micro-offset
        rect = page.rect
        new_doc_page = doc.new_page(width=rect.width, height=rect.height)
        
        # Sort words by line (y0) then x0
        words = sorted(words, key=lambda w: (round(w[1], 1), w[0]))
        
        cumulative_shift = 0.0
        last_y = None
        
        for w in words:
            x0, y0, x1, y1, word_text, block_no, line_no, word_no = w[:8]
            
            if last_y is None or abs(y0 - last_y) > 3.0:
                cumulative_shift = 0.0
                last_y = y0
                
            bit = bits[bit_idx % bit_len]
            bit_idx += 1
            
            shift = delta_pt if bit == 1 else -delta_pt
            cumulative_shift += shift
            
            target_x = x0 + cumulative_shift
            target_y = y1  # Baseline y
            
            # Insert text at shifted coordinate
            new_doc_page.insert_text(
                fitz.Point(target_x, target_y),
                word_text,
                fontsize=y1 - y0,
                render_mode=0
            )
            
        # Delete original page
        doc.delete_page(page.number - 1)

    out_bytes = doc.write()
    doc.close()
    return out_bytes
