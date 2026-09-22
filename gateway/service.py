"""
Gateway Service orchestrating the complete post-quantum document pipeline:
Encrypt (ML-KEM-768 + AES-GCM) -> Decrypt -> Embed Watermark -> Sign Decryption Event (ML-DSA-65) -> Record on Ledger Quorum.
"""
import base64
import hashlib
import json
import os
import time
import uuid
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from pydantic import BaseModel

from crypto import (
    encaps_kem,
    decaps_kem,
    generate_symmetric_key,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    sign_dsa,
    verify_dsa,
)
from identity.ca import CertificateAuthority
from watermark import (
    derive_watermark_id,
    encode_watermark_payload,
    embed_watermark_typeB,
    embed_watermark_typeA,
)
from ledger import LedgerClusterClient, LedgerNode


class GatewayOrchestrator:
    def __init__(self):
        self.ca = CertificateAuthority()
        self.ledger_cluster = LedgerClusterClient()
        self.issued_identities: Dict[str, Dict[str, Any]] = {}  # cert_id -> {cert, keys}
        self.encrypted_documents: Dict[str, Dict[str, Any]] = {}  # doc_hash -> metadata

    def register_recipient(self, recipient_name: str) -> Dict[str, Any]:
        cert, keys = self.ca.issue_certificate(recipient_name)
        cert_id = cert["cert_id"]
        self.issued_identities[cert_id] = {
            "cert": cert,
            "keys": keys
        }
        return cert

    def encrypt_document(self, pdf_bytes: bytes, recipient_cert_id: str) -> Dict[str, Any]:
        if recipient_cert_id not in self.issued_identities:
            raise ValueError(f"Recipient certificate {recipient_cert_id} not found")

        identity = self.issued_identities[recipient_cert_id]
        kem_pk = identity["keys"]["kem_pk"]

        doc_hash = hashlib.sha256(pdf_bytes).hexdigest()

        # Generate ephemeral symmetric AES key
        sym_key = generate_symmetric_key()
        nonce, ciphertext = encrypt_aes_gcm(sym_key, pdf_bytes)

        # Encapsulate AES key using recipient's ML-KEM-768 pubkey
        kem_ciphertext, shared_secret = encaps_kem(kem_pk)

        # Encrypt symmetric key with KEM shared secret
        sym_key_nonce, encrypted_sym_key = encrypt_aes_gcm(shared_secret[:32], sym_key)

        doc_meta = {
            "document_hash": doc_hash,
            "recipient_cert_id": recipient_cert_id,
            "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
            "kem_ciphertext_b64": base64.b64encode(kem_ciphertext).decode("utf-8"),
            "sym_key_nonce_b64": base64.b64encode(sym_key_nonce).decode("utf-8"),
            "encrypted_sym_key_b64": base64.b64encode(encrypted_sym_key).decode("utf-8"),
            "original_pdf_bytes": pdf_bytes  # Kept in-memory for non-blind comparison
        }

        self.encrypted_documents[doc_hash] = doc_meta
        return {
            "document_hash": doc_hash,
            "recipient_cert_id": recipient_cert_id,
            "ciphertext_size": len(ciphertext)
        }

    def process_decryption_request(
        self,
        doc_hash: str,
        recipient_cert_id: str,
        watermark_type: str = "typeB"
    ) -> Tuple[bytes, Dict[str, Any], Dict[str, Any]]:
        """
        Decrypt document, embed recipient-unique watermark, sign record with ML-DSA-65, broadcast to ledger.
        """
        if doc_hash not in self.encrypted_documents:
            raise ValueError(f"Document {doc_hash} not found")

        if recipient_cert_id not in self.issued_identities:
            raise ValueError(f"Recipient identity {recipient_cert_id} not registered")

        doc_meta = self.encrypted_documents[doc_hash]
        identity = self.issued_identities[recipient_cert_id]
        kem_sk = identity["keys"]["kem_sk"]
        dsa_sk = identity["keys"]["dsa_sk"]
        dsa_pk = identity["keys"]["dsa_pk"]

        # 1. Recover AES key via ML-KEM-768 decapsulation
        kem_ciphertext = base64.b64decode(doc_meta["kem_ciphertext_b64"])
        shared_secret = decaps_kem(kem_sk, kem_ciphertext)

        sym_key_nonce = base64.b64decode(doc_meta["sym_key_nonce_b64"])
        encrypted_sym_key = base64.b64decode(doc_meta["encrypted_sym_key_b64"])
        sym_key = decrypt_aes_gcm(shared_secret[:32], sym_key_nonce, encrypted_sym_key)

        # 2. Decrypt PDF file
        nonce = base64.b64decode(doc_meta["nonce_b64"])
        ciphertext = base64.b64decode(doc_meta["ciphertext_b64"])
        decrypted_pdf = decrypt_aes_gcm(sym_key, nonce, ciphertext)

        # 3. Derive session-unique watermark ID
        session_id = str(uuid.uuid4())
        random_nonce = os.urandom(8)
        watermark_id = derive_watermark_id(doc_hash, recipient_cert_id, session_id, random_nonce)
        watermark_id_hex = watermark_id.hex()

        # 4. Encode & Embed watermark into PDF
        encoded_payload = encode_watermark_payload(watermark_id, doc_hash)
        if watermark_type == "typeA":
            fingerprinted_pdf = embed_watermark_typeA(decrypted_pdf, encoded_payload)
        else:
            fingerprinted_pdf = embed_watermark_typeB(decrypted_pdf, encoded_payload)

        # 5. Build canonical decryption record
        canonical_record = {
            "event": "DOCUMENT_DECRYPT",
            "document_hash": f"sha256:{doc_hash}",
            "recipient_cert_id": recipient_cert_id,
            "session_id": session_id,
            "watermark_id": watermark_id_hex,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "watermark_algorithm": f"v1-{watermark_type}",
            "event_version": "1.0"
        }

        # 6. Recipient signs record with ML-DSA-65 secret key
        canonical_bytes = json.dumps(canonical_record, sort_keys=True).encode("utf-8")
        signature = sign_dsa(dsa_sk, canonical_bytes)

        sig_b64 = base64.b64encode(signature).decode("utf-8")
        pubkey_b64 = base64.b64encode(dsa_pk).decode("utf-8")

        # 7. Broadcast to Ledger cluster quorum
        ledger_status = self.ledger_cluster.broadcast_transaction(
            canonical_record,
            sig_b64,
            pubkey_b64
        )

        return fingerprinted_pdf, canonical_record, ledger_status
