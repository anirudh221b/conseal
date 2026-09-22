"""
FastAPI REST Server and Web UI Dashboard for Conseal.
Exposes endpoints for Identity Management, Document Encryption, Decryption & Fingerprinting,
Ledger Cluster Inspection, and Forensic Analysis.
"""
import base64
import hashlib
import json
import io
from typing import List, Dict, Any
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from gateway.service import GatewayOrchestrator
from forensics import analyze_leaked_document

app = FastAPI(
    title="Conseal — Post-Quantum Forensic Fingerprinting Gateway",
    description="Cryptographically Verifiable Forensic Document Fingerprinting System",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global orchestrator instance
orchestrator = GatewayOrchestrator()


class IdentityRegisterRequest(BaseModel):
    recipient_name: str


@app.get("/api/identities")
def list_identities():
    """List all registered recipient certificates."""
    idents = []
    for cert_id, data in orchestrator.issued_identities.items():
        c = data["cert"]
        idents.append({
            "cert_id": c["cert_id"],
            "recipient_id": c["recipient_id"],
            "issued_at": c["issued_at"],
            "algorithm_kem": c["algorithm_kem"],
            "algorithm_dsa": c["algorithm_dsa"],
        })
    return {"identities": idents, "ca_id": orchestrator.ca.ca_id, "ca_pubkey_b64": orchestrator.ca.get_root_pubkey_b64()}


@app.post("/api/identities")
def register_identity(req: IdentityRegisterRequest):
    """Register a new recipient identity and issue post-quantum certificate."""
    cert = orchestrator.register_recipient(req.recipient_name)
    return {"status": "SUCCESS", "certificate": cert}


@app.post("/api/encrypt")
async def encrypt_document_endpoint(
    file: UploadFile = File(...),
    recipient_cert_id: str = Form(...)
):
    """Upload PDF document and encrypt for a recipient using ML-KEM-768 + AES-256-GCM."""
    pdf_bytes = await file.read()
    try:
        res = orchestrator.encrypt_document(pdf_bytes, recipient_cert_id)
        return {"status": "SUCCESS", "encryption_details": res}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/decrypt")
def decrypt_document_endpoint(
    document_hash: str = Form(...),
    recipient_cert_id: str = Form(...),
    watermark_type: str = Form("typeB")
):
    """Decrypt document, embed watermark, sign record with ML-DSA-65, broadcast to ledger."""
    try:
        fingerprinted_pdf, record, ledger_status = orchestrator.process_decryption_request(
            document_hash,
            recipient_cert_id,
            watermark_type=watermark_type
        )
        
        # Return fingerprinted PDF as downloadable file
        filename = f"fingerprinted_{recipient_cert_id}_{document_hash[:8]}.pdf"
        return StreamingResponse(
            io.BytesIO(fingerprinted_pdf),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "X-Decryption-Record": json.dumps(record),
                "X-Ledger-Status": json.dumps(ledger_status)
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/investigate")
async def investigate_leaked_document(
    original_pdf: UploadFile = File(...),
    leaked_pdf: UploadFile = File(...)
):
    """Perform non-blind forensic watermark extraction and ledger quorum verification."""
    orig_bytes = await original_pdf.read()
    leaked_bytes = await leaked_pdf.read()

    report_text, report_data = analyze_leaked_document(
        orig_bytes,
        leaked_bytes,
        orchestrator.ledger_cluster
    )

    return {
        "report_text": report_text,
        "report_data": report_data
    }


@app.get("/api/ledger")
def get_ledger_status():
    """Inspect all 3 independent ledger nodes and consensus state."""
    node_states = []
    for node in orchestrator.ledger_cluster.nodes:
        node_states.append({
            "node_id": node.node_id,
            "chain_length": len(node.chain),
            "is_chain_valid": node.verify_chain_integrity(),
            "latest_block": node.get_last_block()
        })
    return {"cluster_size": len(node_states), "nodes": node_states}


@app.get("/", response_class=HTMLResponse)
def serve_ui():
    """Serve single-page Web UI application."""
    with open("frontend/index.html", "r", encoding="utf-8") as f:
        return f.read()
