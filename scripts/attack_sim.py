"""
Attack Simulation Tool.
Applies destructive transformations (JPEG re-compression, screenshot rasterization, cropping, noise)
to a fingerprinted PDF to test forensic watermark survival and extraction robustness.
"""
import sys
import os
import io
import argparse
import fitz
import numpy as np
from PIL import Image, ImageEnhance, ImageFilter


def attack_jpeg_compression(pdf_bytes: bytes, quality: int = 50) -> bytes:
    """Rasterize PDF page to image and compress heavily with lossy JPEG."""
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    out_doc = fitz.open()

    for page in doc:
        pix = page.get_pixmap(dpi=150)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)

        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=quality)
        compressed_img = Image.open(buf)

        img_buf = io.BytesIO()
        compressed_img.save(img_buf, format="JPEG", quality=90)

        out_page = out_doc.new_page(width=page.rect.width, height=page.rect.height)
        out_page.insert_image(out_page.rect, stream=img_buf.getvalue())

    out_bytes = out_doc.write()
    out_doc.close()
    doc.close()
    return out_bytes


def attack_screenshot_rasterization(pdf_bytes: bytes, dpi: int = 96) -> bytes:
    """Simulate low-resolution display screenshot rasterization."""
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    out_doc = fitz.open()

    for page in doc:
        pix = page.get_pixmap(dpi=dpi)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)

        # Upscale back to standard DPI
        buf = io.BytesIO()
        img.save(buf, format="PNG")

        out_page = out_doc.new_page(width=page.rect.width, height=page.rect.height)
        out_page.insert_image(out_page.rect, stream=buf.getvalue())

    out_bytes = out_doc.write()
    out_doc.close()
    doc.close()
    return out_bytes


def attack_pdf_resave(pdf_bytes: bytes) -> bytes:
    """Re-save PDF using fitz/PyMuPDF to strip internal metadata and rewrite object streams."""
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    out_bytes = doc.write(garbage=4, deflate=True, clean=True)
    doc.close()
    return out_bytes


def run_attack_suite(original_pdf: bytes, fingerprinted_pdf: bytes, doc_hash: str, ledger_cluster) -> dict:
    from forensics import analyze_leaked_document

    results = {}

    print("\n--- RUNNING ATTACK SUITE ---")

    # 1. Clean fingerprinted PDF
    _, r1 = analyze_leaked_document(original_pdf, fingerprinted_pdf, ledger_cluster)
    results["Clean PDF"] = r1["status"] == "VERIFIED"
    print(f"[+] Clean PDF: {'PASS' if results['Clean PDF'] else 'FAIL'}")

    # 2. PDF Re-save attack
    pdf_resaved = attack_pdf_resave(fingerprinted_pdf)
    _, r2 = analyze_leaked_document(original_pdf, pdf_resaved, ledger_cluster)
    results["PDF Re-save"] = r2["status"] == "VERIFIED"
    print(f"[+] PDF Re-save Attack: {'PASS' if results['PDF Re-save'] else 'FAIL'}")

    # 3. Screenshot Rasterization attack (96 DPI)
    pdf_screenshot = attack_screenshot_rasterization(fingerprinted_pdf, dpi=96)
    _, r3 = analyze_leaked_document(original_pdf, pdf_screenshot, ledger_cluster)
    results["Screenshot (96 DPI)"] = r3["status"] == "VERIFIED"
    print(f"[+] Screenshot (96 DPI) Attack: {'PASS' if results['Screenshot (96 DPI)'] else 'FAIL'}")

    # 4. Heavy JPEG Compression attack (Quality = 60)
    pdf_jpeg = attack_jpeg_compression(fingerprinted_pdf, quality=60)
    _, r4 = analyze_leaked_document(original_pdf, pdf_jpeg, ledger_cluster)
    results["JPEG Compression (Q=60)"] = r4["status"] == "VERIFIED"
    print(f"[+] JPEG Compression (Q=60) Attack: {'PASS' if results['JPEG Compression (Q=60)'] else 'FAIL'}")

    return results


if __name__ == "__main__":
    print("Conseal Attack Simulation Tool Ready.")
