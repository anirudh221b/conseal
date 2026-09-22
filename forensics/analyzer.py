"""
Forensic Analyzer for Leaked Document Investigation.
Non-blind extraction -> Ledger Cluster Quorum Search -> ML-DSA Signature Verification -> Canonical Report Generation.
"""
import hashlib
import json
import base64
from typing import Dict, Any, Tuple
from watermark import extract_watermark
from ledger import LedgerClusterClient
from crypto.pq_dsa import verify_dsa


def analyze_leaked_document(
    original_pdf_bytes: bytes,
    leaked_pdf_bytes: bytes,
    ledger_cluster: LedgerClusterClient
) -> Tuple[str, Dict[str, Any]]:
    """
    Perform forensic analysis on a leaked document.
    
    Args:
        original_pdf_bytes: Reference original PDF.
        leaked_pdf_bytes: Suspect leaked PDF.
        ledger_cluster: Active LedgerClusterClient instance.
        
    Returns:
        Tuple[str, Dict[str, Any]]:
            - Plaintext formatted forensic report string.
            - Structured dict of analysis metrics and verification result.
    """
    doc_hash = hashlib.sha256(original_pdf_bytes).hexdigest()

    # 1. Non-blind watermark extraction
    w_id_bytes, integrity_valid, method = extract_watermark(original_pdf_bytes, leaked_pdf_bytes, doc_hash)

    if not w_id_bytes or not integrity_valid:
        report_text = f"""
FORENSIC DECRYPTION REPORT
────────────────────────────
Document Hash:        sha256:{doc_hash}
Extracted Watermark:  UNREADABLE / NOT FOUND
Watermark Integrity:  MISMATCH / CORRUPTED
Matched Event:        NONE
Recipient:            UNKNOWN
Signature Algorithm:  ML-DSA-65
Signature Verification: FAILED
Ledger Nodes Agreeing: 0/{len(ledger_cluster.nodes)}
Decryption Timestamp: N/A
"""
        return report_text.strip(), {
            "status": "UNREADABLE",
            "document_hash": doc_hash,
            "watermark_id": None,
            "integrity_valid": False,
            "signature_valid": False
        }

    watermark_hex = w_id_bytes.hex()

    # 2. Query ledger cluster quorum
    block, audit = ledger_cluster.query_watermark_quorum(watermark_hex)

    if not block or not audit["quorum_reached"]:
        report_text = f"""
FORENSIC DECRYPTION REPORT
────────────────────────────
Document Hash:        sha256:{doc_hash}
Extracted Watermark:  {watermark_hex}
Watermark Integrity:  MATCH
Matched Event:        NOT FOUND ON LEDGER QUORUM
Recipient:            UNKNOWN
Signature Algorithm:  ML-DSA-65
Signature Verification: FAILED (No Ledger Record)
Ledger Nodes Agreeing: {audit['agreeing_count']}/{audit['total_nodes']}
Decryption Timestamp: N/A
"""
        return report_text.strip(), {
            "status": "NOT_IN_LEDGER",
            "document_hash": doc_hash,
            "watermark_id": watermark_hex,
            "integrity_valid": True,
            "signature_valid": False,
            "audit": audit
        }

    canonical_record = block["canonical_record"]
    recipient_cert_id = canonical_record.get("recipient_cert_id", "UNKNOWN")
    timestamp = canonical_record.get("timestamp", "UNKNOWN")
    event_id = block.get("tx_id", "UNKNOWN")

    # 3. Verify ML-DSA-65 signature
    sig_b64 = block.get("signature_b64", "")
    pubkey_b64 = block.get("recipient_dsa_pubkey_b64", "")

    canonical_bytes = json.dumps(canonical_record, sort_keys=True).encode("utf-8")
    sig_bytes = base64.b64decode(sig_b64)
    pubkey_bytes = base64.b64decode(pubkey_b64)

    sig_valid = verify_dsa(pubkey_bytes, canonical_bytes, sig_bytes)

    report_text = f"""
FORENSIC DECRYPTION REPORT
────────────────────────────
Document Hash:        sha256:{doc_hash}
Extracted Watermark:  {watermark_hex}
Watermark Integrity:  MATCH
Extraction Method:    {method}
Matched Event:        {event_id}
Recipient Certificate:{recipient_cert_id}
Signature Algorithm:  ML-DSA-65
Signature Verification: {'VALID' if sig_valid else 'INVALID'}
Ledger Nodes Agreeing: {audit['agreeing_count']}/{audit['total_nodes']} ({'QUORUM REACHED' if audit['quorum_reached'] else 'NO QUORUM'})
Decryption Timestamp: {timestamp}
"""

    report_data = {
        "status": "VERIFIED" if sig_valid else "INVALID_SIGNATURE",
        "document_hash": doc_hash,
        "watermark_id": watermark_hex,
        "extraction_method": method,
        "event_id": event_id,
        "recipient_cert_id": recipient_cert_id,
        "timestamp": timestamp,
        "signature_valid": sig_valid,
        "watermark_integrity": True,
        "audit": audit,
        "canonical_record": canonical_record
    }

    return report_text.strip(), report_data
