# CONSEAL — Cryptographically Verifiable Forensic Document Fingerprinting

> **One-liner:** Every recipient gets a visually identical but forensically unique copy of a PDF document. Decryption is authenticated with the recipient's post-quantum signature (ML-DSA-65) and logged on an offline tamper-evident permissioned ledger (2-of-3 quorum consensus). A leaked copy can be traced back to the exact recipient with cryptographic proof.

---

## 🛡️ Key Features

- **Post-Quantum Cryptography (FIPS 203 & FIPS 204)**
  - Key Encapsulation: **ML-KEM-768** for asymmetric key exchange.
  - Digital Signatures: **ML-DSA-65** for canonical decryption event signing.
  - Symmetric Cipher: **AES-256-GCM** for authenticated file encryption.
- **Offline PKI & Certificate Authority**
  - Self-contained Root CA issuing signed certificates binding recipient identities to ML-KEM and ML-DSA public keys.
- **Dual Watermarking Engine**
  - **Type A (Text PDFs):** Imperceptible character micro glyph-spacing & word coordinate perturbations (`PyMuPDF`).
  - **Type B (Image/Scanned PDFs):** 2D Discrete Cosine Transform (DCT) mid-frequency spread-spectrum coefficient embedding (`scipy.fftpack`).
  - **Payload Integrity:** 128-bit HKDF `watermark_id` + 64-bit HMAC integrity tag wrapped in **Reed-Solomon Error Correction** (`reedsolo`) for noise and distortion survival.
- **Offline Permissioned Quorum Ledger**
  - Append-only cryptographic hash chain replicated across ≥3 independent nodes with 2-of-3 signature quorum agreement and automated malicious node tamper detection.
- **Non-Blind Forensic Analyzer & Report Generator**
  - Extracts watermark payloads from suspect leaked PDFs, queries ledger cluster quorum, verifies ML-DSA signatures, and outputs canonical **Forensic Decryption Reports**.
- **Interactive Web UI & Attack Simulator**
  - Modern dark-mode web application dashboard and automated attack suite testing against PDF re-saving, low-DPI screenshot rasterization, and lossy JPEG compression.

---

## 📐 System Architecture

```
Sender → Encrypt (ML-KEM-768 + AES-256-GCM) → Recipient Decrypts
                                                     │
                                        Watermark Engine (session-unique)
                                                     │
                                    ML-DSA-65 sign decryption record
                                                     │
                                    Offline permissioned DLT (2-of-3 Quorum)
                                                     │
                                        Recipient gets watermarked PDF

Leak found → Forensic Extractor → Watermark ID → Ledger lookup →
             ML-DSA verify → Canonical report (recipient + cryptographic proof)
```

---

## 📁 Repository Structure

```
.
├── identity/          # Offline CA, PQ certificate issuance (ML-KEM-768 + ML-DSA-65)
├── crypto/            # ML-KEM-768, ML-DSA-65, and AES-256-GCM wrappers
├── watermark/         # Payload ECC, Type A (Text), Type B (DCT Image), Non-blind Extractor
├── ledger/            # Append-only ledger nodes & 2-of-3 quorum consensus client
├── gateway/           # Gateway orchestrator & FastAPI REST service
├── forensics/         # Forensic analyzer & canonical report generator
├── scripts/           # Attack simulation suite (compression, screenshot, crop, re-save)
├── frontend/          # Single-page Web UI application dashboard
├── tests/             # Pytest test suite across all modules
└── main.py            # Entry point for running the web server
```

---

## 🚀 Quick Start

### 1. Prerequisites & Virtual Environment

Ensure Python 3.10+ is installed:

```bash
# Activate virtual environment
source venv/bin/activate
```

### 2. Run Test Suite

To run all 10 unit and integration tests across crypto, identity, watermarking, ledger, gateway, and attack simulation:

```bash
PYTHONPATH=. ./venv/bin/pytest tests/ -s
```

### 3. Launch Web Server & UI

Start the Gateway API server and UI:

```bash
PYTHONPATH=. ./venv/bin/python main.py
```

Open your browser and navigate to:
```
http://127.0.0.1:8000
```

---

## 📊 Sample Forensic Decryption Report

```
FORENSIC DECRYPTION REPORT
────────────────────────────
Document Hash:        sha256:59920371a0d713bc749a5b847e345984be8dd72a3c8eee3335ab361a4a86275a
Extracted Watermark:  a802b0455f04b819269c16e403ae52b4
Watermark Integrity:  MATCH
Extraction Method:    TypeB-DCT
Matched Event:        540fc77e-1e33-46d7-8145-e4ac477afe33
Recipient Certificate:CERT-BOB_JONES-001
Signature Algorithm:  ML-DSA-65
Signature Verification: VALID
Ledger Nodes Agreeing: 3/3 (QUORUM REACHED)
Decryption Timestamp: 2026-09-22T16:40:34Z
```