"""
Type B Watermarking: Spread-spectrum DCT domain embedding for image/scanned PDFs.
Modifies mid-frequency 2D DCT coefficients in 8x8 image blocks.
Robust to JPEG compression, screenshots, noise, and rasterization.
"""
import io
import fitz
import numpy as np
from PIL import Image
from scipy.fftpack import dct, idct
from typing import List, Tuple
from watermark.embed_typeA import SYNC_MARKER, bytes_to_bits


def dct2d(block: np.ndarray) -> np.ndarray:
    return dct(dct(block.T, norm='ortho').T, norm='ortho')


def idct2d(block: np.ndarray) -> np.ndarray:
    return idct(idct(block.T, norm='ortho').T, norm='ortho')


def embed_watermark_typeB(pdf_bytes: bytes, payload_bytes: bytes, alpha: float = 25.0) -> bytes:
    """
    Embed watermark payload into image/scanned PDF via 8x8 DCT coefficient differential encoding.
    
    Args:
        pdf_bytes: Original PDF input bytes.
        payload_bytes: Encoded Reed-Solomon payload bytes.
        alpha: Embedding strength factor. Higher = more robust, lower = higher visual fidelity.
        
    Returns:
        bytes: Watermarked PDF output bytes.
    """
    full_payload = SYNC_MARKER + payload_bytes
    bits = bytes_to_bits(full_payload)
    bit_len = len(bits)
    
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    out_doc = fitz.open()
    bit_idx = 0

    for page in doc:
        # Render page to PIL RGB image at 150 DPI
        pix = page.get_pixmap(dpi=150)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        
        # Convert to YCbCr
        ycbcr = img.convert("YCbCr")
        y_channel, cb, cr = ycbcr.split()
        y_np = np.array(y_channel, dtype=np.float32)

        h, w = y_np.shape
        # Process 8x8 blocks
        for r in range(0, h - 7, 8):
            for c in range(0, w - 7, 8):
                block = y_np[r:r+8, c:c+8]
                dct_block = dct2d(block)

                bit = bits[bit_idx % bit_len]
                bit_idx += 1

                # Use mid-frequency coefficient pair (4, 3) and (3, 4)
                v1 = dct_block[4, 3]
                v2 = dct_block[3, 4]

                if bit == 1:
                    if v1 - v2 < alpha:
                        dct_block[4, 3] = (v1 + v2 + alpha) / 2.0
                        dct_block[3, 4] = (v1 + v2 - alpha) / 2.0
                else:
                    if v2 - v1 < alpha:
                        dct_block[3, 4] = (v1 + v2 + alpha) / 2.0
                        dct_block[4, 3] = (v1 + v2 - alpha) / 2.0

                y_np[r:r+8, c:c+8] = idct2d(dct_block)

        # Clip values to valid 0-255 uint8
        y_np = np.clip(y_np, 0, 255).astype(np.uint8)
        watermarked_y = Image.fromarray(y_np, mode="L")
        
        # Recombine YCbCr and convert to RGB
        watermarked_img = Image.merge("YCbCr", (watermarked_y, cb, cr)).convert("RGB")
        
        # Save image to bytes
        img_buffer = io.BytesIO()
        watermarked_img.save(img_buffer, format="JPEG", quality=95)
        img_bytes = img_buffer.getvalue()

        # Insert page into output PDF
        out_page = out_doc.new_page(width=page.rect.width, height=page.rect.height)
        out_page.insert_image(out_page.rect, stream=img_bytes)

    out_bytes = out_doc.write()
    out_doc.close()
    doc.close()
    return out_bytes
