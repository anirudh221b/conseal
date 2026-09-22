"""
Offline Certificate Authority (CA) for Post-Quantum Identities.
Issues signed certificates binding Recipient ID <-> ML-KEM Public Key <-> ML-DSA Public Key.
"""
import json
import base64
import time
from typing import Dict, Any, Tuple
from crypto.pq_kem import generate_kem_keypair
from crypto.pq_dsa import generate_dsa_keypair, sign_dsa, verify_dsa


class CertificateAuthority:
    def __init__(self):
        """Initialize CA with a master ML-DSA-65 root signing keypair."""
        self.ca_id = "OFFLINE-ROOT-CA-001"
        self.root_pubkey, self.root_privkey = generate_dsa_keypair()

    def get_root_pubkey_b64(self) -> str:
        return base64.b64encode(self.root_pubkey).decode("utf-8")

    def issue_certificate(self, recipient_id: str, cert_id: str = None) -> Tuple[Dict[str, Any], Dict[str, bytes]]:
        """
        Generate keypairs for recipient and issue a signed identity certificate.
        
        Args:
            recipient_id: Human readable name/email/ID (e.g., 'Alice Smith')
            cert_id: Optional unique certificate ID (e.g., 'CERT-ALICE-0001')
            
        Returns:
            Tuple[Dict[str, Any], Dict[str, bytes]]:
                - cert_data: Signed canonical certificate dict
                - recipient_private_keys: {'kem_sk': bytes, 'dsa_sk': bytes}
        """
        if not cert_id:
            cert_id = f"CERT-{recipient_id.upper().replace(' ', '_')}-001"
            
        kem_pk, kem_sk = generate_kem_keypair()
        dsa_pk, dsa_sk = generate_dsa_keypair()

        cert_payload = {
            "cert_id": cert_id,
            "recipient_id": recipient_id,
            "issuer_id": self.ca_id,
            "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "kem_pubkey_b64": base64.b64encode(kem_pk).decode("utf-8"),
            "dsa_pubkey_b64": base64.b64encode(dsa_pk).decode("utf-8"),
            "algorithm_kem": "ML-KEM-768",
            "algorithm_dsa": "ML-DSA-65",
        }

        # Create canonical representation for signing
        canonical_bytes = json.dumps(cert_payload, sort_keys=True).encode("utf-8")
        ca_sig = sign_dsa(self.root_privkey, canonical_bytes)

        cert_data = cert_payload.copy()
        cert_data["ca_signature_b64"] = base64.b64encode(ca_sig).decode("utf-8")
        cert_data["ca_pubkey_b64"] = self.get_root_pubkey_b64()

        private_keys = {
            "kem_sk": kem_sk,
            "dsa_sk": dsa_sk,
            "kem_pk": kem_pk,
            "dsa_pk": dsa_pk,
        }

        return cert_data, private_keys

    def verify_certificate(self, cert_data: Dict[str, Any]) -> bool:
        """
        Verify the CA's signature on a recipient certificate.
        """
        if "ca_signature_b64" not in cert_data or "ca_pubkey_b64" not in cert_data:
            return False

        sig = base64.b64decode(cert_data["ca_signature_b64"])
        ca_pubkey = base64.b64decode(cert_data["ca_pubkey_b64"])

        # Reconstruct canonical unsigned payload
        payload = {k: v for k, v in cert_data.items() if k not in ("ca_signature_b64", "ca_pubkey_b64")}
        canonical_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

        return verify_dsa(ca_pubkey, canonical_bytes, sig)
