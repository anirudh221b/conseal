"""
Single Ledger Node Server.
Maintains an append-only cryptographic hash chain of signed decryption records.
Verifies post-quantum ML-DSA-65 signatures before recording blocks.
Exposes REST endpoints for submit, query, and block verification.
"""
import json
import hashlib
import uuid
import base64
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from crypto.pq_dsa import verify_dsa


class TransactionSubmission(BaseModel):
    canonical_record: Dict[str, Any]
    signature_b64: str
    recipient_dsa_pubkey_b64: str


class LedgerNode:
    def __init__(self, node_id: str = "NODE-1", db_path: Optional[str] = None):
        self.node_id = node_id
        self.chain: List[Dict[str, Any]] = []
        self._genesis_block()

    def _genesis_block(self):
        genesis = {
            "block_index": 0,
            "tx_id": "GENESIS-BLOCK",
            "prev_block_hash": "0" * 64,
            "event_hash": "0" * 64,
            "canonical_record": {"event": "GENESIS"},
            "signature_b64": "",
            "recipient_dsa_pubkey_b64": "",
            "block_hash": hashlib.sha256(b"GENESIS").hexdigest()
        }
        self.chain.append(genesis)

    def get_last_block(self) -> Dict[str, Any]:
        return self.chain[-1]

    def add_transaction(self, canonical_record: Dict[str, Any], signature_b64: str, recipient_dsa_pubkey_b64: str) -> Dict[str, Any]:
        # 1. Verify ML-DSA-65 signature on canonical JSON record bytes
        import copy
        record_copy = copy.deepcopy(canonical_record)
        canonical_bytes = json.dumps(record_copy, sort_keys=True).encode("utf-8")
        sig_bytes = base64.b64decode(signature_b64)
        pubkey_bytes = base64.b64decode(recipient_dsa_pubkey_b64)

        if not verify_dsa(pubkey_bytes, canonical_bytes, sig_bytes):
            raise ValueError("Invalid ML-DSA-65 signature on decryption record")

        # 2. Compute record event hash
        event_hash = hashlib.sha256(canonical_bytes).hexdigest()

        # 3. Create block
        prev_block = self.get_last_block()
        block_index = len(self.chain)
        prev_hash = prev_block["block_hash"]
        tx_id = str(uuid.uuid4())

        block_content = f"{block_index}:{prev_hash}:{event_hash}:{signature_b64}".encode("utf-8")
        block_hash = hashlib.sha256(block_content).hexdigest()

        block = {
            "block_index": block_index,
            "tx_id": tx_id,
            "prev_block_hash": prev_hash,
            "event_hash": event_hash,
            "canonical_record": record_copy,
            "signature_b64": signature_b64,
            "recipient_dsa_pubkey_b64": recipient_dsa_pubkey_b64,
            "block_hash": block_hash
        }

        self.chain.append(block)
        return block

    def verify_chain_integrity(self) -> bool:
        """Verify the integrity of the entire hash chain."""
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]

            if curr["prev_block_hash"] != prev["block_hash"]:
                return False

            # Verify block hash
            block_content = f"{curr['block_index']}:{curr['prev_block_hash']}:{curr['event_hash']}:{curr['signature_b64']}".encode("utf-8")
            expected_hash = hashlib.sha256(block_content).hexdigest()
            if curr["block_hash"] != expected_hash:
                return False

            # Verify signature
            canonical_bytes = json.dumps(curr["canonical_record"], sort_keys=True).encode("utf-8")
            sig_bytes = base64.b64decode(curr["signature_b64"])
            pubkey_bytes = base64.b64decode(curr["recipient_dsa_pubkey_b64"])
            if not verify_dsa(pubkey_bytes, canonical_bytes, sig_bytes):
                return False

        return True

    def query_by_watermark_id(self, watermark_id: str) -> Optional[Dict[str, Any]]:
        for block in reversed(self.chain):
            rec = block.get("canonical_record", {})
            if rec.get("watermark_id") == watermark_id:
                return block
        return None


def create_node_app(node: LedgerNode) -> FastAPI:
    app = FastAPI(title=f"Ledger Node {node.node_id}")

    @app.post("/submit")
    def submit_tx(tx: TransactionSubmission):
        try:
            block = node.add_transaction(tx.canonical_record, tx.signature_b64, tx.recipient_dsa_pubkey_b64)
            return {"status": "SUCCESS", "block": block}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/query/{watermark_id}")
    def query_watermark(watermark_id: str):
        block = node.query_by_watermark_id(watermark_id)
        if not block:
            raise HTTPException(status_code=404, detail="Watermark ID not found on ledger")
        return {"status": "FOUND", "node_id": node.node_id, "block": block}

    @app.get("/chain")
    def get_chain():
        valid = node.verify_chain_integrity()
        return {"node_id": node.node_id, "is_valid": valid, "length": len(node.chain), "chain": node.chain}

    return app
