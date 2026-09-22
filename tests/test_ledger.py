"""
Unit tests for Stage 3 permissioned ledger nodes & quorum consensus.
"""
import pytest
import base64
import json
from crypto import generate_dsa_keypair, sign_dsa
from ledger import LedgerNode, LedgerClusterClient


def test_single_node_hash_chain():
    node = LedgerNode("NODE-TEST")
    pk, sk = generate_dsa_keypair()

    canonical_record = {
        "event": "DOCUMENT_DECRYPT",
        "document_hash": "sha256:1234567890abcdef",
        "recipient_cert_id": "CERT-ALICE-001",
        "session_id": "session-xyz",
        "watermark_id": "aabbccdd11223344",
        "timestamp": "2026-09-22T21:30:00Z",
        "watermark_algorithm": "v1-typeB",
        "event_version": "1.0"
    }

    canonical_bytes = json.dumps(canonical_record, sort_keys=True).encode("utf-8")
    sig = sign_dsa(sk, canonical_bytes)

    sig_b64 = base64.b64encode(sig).decode("utf-8")
    pk_b64 = base64.b64encode(pk).decode("utf-8")

    block = node.add_transaction(canonical_record, sig_b64, pk_b64)
    assert block["block_index"] == 1
    assert node.verify_chain_integrity() is True

    # Test query
    retrieved = node.query_by_watermark_id("aabbccdd11223344")
    assert retrieved is not None
    assert retrieved["block_hash"] == block["block_hash"]


def test_cluster_quorum_and_tamper_detection():
    n1 = LedgerNode("NODE-1")
    n2 = LedgerNode("NODE-2")
    n3 = LedgerNode("NODE-3")
    client = LedgerClusterClient([n1, n2, n3])

    pk, sk = generate_dsa_keypair()
    canonical_record = {
        "event": "DOCUMENT_DECRYPT",
        "document_hash": "sha256:9999999999",
        "recipient_cert_id": "CERT-BOB-001",
        "session_id": "sess-99",
        "watermark_id": "1122334455667788",
        "timestamp": "2026-09-22T21:35:00Z",
        "watermark_algorithm": "v1-typeB",
        "event_version": "1.0"
    }
    canonical_bytes = json.dumps(canonical_record, sort_keys=True).encode("utf-8")
    sig = sign_dsa(sk, canonical_bytes)

    sig_b64 = base64.b64encode(sig).decode("utf-8")
    pk_b64 = base64.b64encode(pk).decode("utf-8")

    broadcast_res = client.broadcast_transaction(canonical_record, sig_b64, pk_b64)
    assert broadcast_res["quorum_reached"] is True
    assert broadcast_res["accepted_count"] == 3

    # Query before tampering
    winning_block, audit = client.query_watermark_quorum("1122334455667788")
    assert winning_block is not None
    assert audit["quorum_reached"] is True
    assert audit["agreeing_count"] == 3

    # Simulating malicious tamper on Node 3
    n3.chain[1]["canonical_record"]["recipient_cert_id"] = "CERT-EVE-MALICIOUS"

    # Query after tampering on Node 3
    winning_block, audit = client.query_watermark_quorum("1122334455667788")
    assert winning_block is not None
    assert audit["quorum_reached"] is True
    assert audit["agreeing_count"] == 2
    assert "NODE-3" in audit["disagreeing_nodes"]
