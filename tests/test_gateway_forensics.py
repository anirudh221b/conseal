"""
End-to-end integration tests for Gateway Orchestrator & Forensic Analyzer.
"""
import pytest
import fitz
from gateway.service import GatewayOrchestrator
from forensics import analyze_leaked_document


def create_sample_pdf() -> bytes:
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)
    text = "CONFIDENTIAL FINANCIAL REPORT - Q4 ACQUISITION STRATEGY " * 30
    page.insert_textbox(fitz.Rect(50, 50, 550, 750), text, fontsize=12)
    pdf_bytes = doc.write()
    doc.close()
    return pdf_bytes


def test_end_to_end_forensic_pipeline():
    orchestrator = GatewayOrchestrator()

    # 1. Register identity
    cert_alice = orchestrator.register_recipient("Alice Smith")
    cert_bob = orchestrator.register_recipient("Bob Jones")

    # 2. Sender encrypts document for Bob
    original_pdf = create_sample_pdf()
    enc_result = orchestrator.encrypt_document(original_pdf, cert_bob["cert_id"])
    doc_hash = enc_result["document_hash"]

    # 3. Bob requests decryption -> fingerprinted PDF generated & signed on ledger
    bobs_pdf, record, ledger_status = orchestrator.process_decryption_request(
        doc_hash,
        cert_bob["cert_id"],
        watermark_type="typeB"
    )

    assert bobs_pdf != original_pdf
    assert ledger_status["quorum_reached"] is True
    assert ledger_status["accepted_count"] == 3
    assert record["recipient_cert_id"] == cert_bob["cert_id"]

    # 4. Forensic analysis of Bob's leaked PDF
    report_text, report_data = analyze_leaked_document(
        original_pdf,
        bobs_pdf,
        orchestrator.ledger_cluster
    )

    print("\n--- GENERATED FORENSIC REPORT ---")
    print(report_text)

    assert report_data["status"] == "VERIFIED"
    assert report_data["recipient_cert_id"] == cert_bob["cert_id"]
    assert report_data["signature_valid"] is True
    assert report_data["audit"]["quorum_reached"] is True
    assert report_data["audit"]["agreeing_count"] == 3


def test_attack_simulation_robustness():
    from scripts.attack_sim import run_attack_suite

    orchestrator = GatewayOrchestrator()
    cert = orchestrator.register_recipient("Charlie Brown")

    original_pdf = create_sample_pdf()
    enc_res = orchestrator.encrypt_document(original_pdf, cert["cert_id"])
    doc_hash = enc_res["document_hash"]

    charlies_pdf, record, ledger_status = orchestrator.process_decryption_request(
        doc_hash,
        cert["cert_id"],
        watermark_type="typeB"
    )

    attack_results = run_attack_suite(original_pdf, charlies_pdf, doc_hash, orchestrator.ledger_cluster)
    assert attack_results["Clean PDF"] is True
    assert attack_results["PDF Re-save"] is True

