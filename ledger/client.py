"""
Ledger Cluster Client with 2-of-3 Quorum Consensus and Malicious Node Detection.
Broadcasts signed records to a cluster of independent ledger nodes and validates consensus.
"""
from typing import List, Dict, Any, Tuple, Optional
from ledger.node import LedgerNode


class LedgerClusterClient:
    def __init__(self, nodes: List[LedgerNode] = None):
        """
        Initialize cluster client with a list of LedgerNode instances.
        If nodes is None, initializes 3 default independent nodes (Node-1, Node-2, Node-3).
        """
        if nodes is None:
            self.nodes = [
                LedgerNode(node_id="NODE-1"),
                LedgerNode(node_id="NODE-2"),
                LedgerNode(node_id="NODE-3")
            ]
        else:
            self.nodes = nodes

    def broadcast_transaction(
        self,
        canonical_record: Dict[str, Any],
        signature_b64: str,
        recipient_dsa_pubkey_b64: str
    ) -> Dict[str, Any]:
        """
        Submit transaction to all independent nodes in the cluster.
        
        Returns:
            Dict: Status summary with list of accepting nodes.
        """
        successes = []
        failures = []

        for node in self.nodes:
            try:
                block = node.add_transaction(canonical_record, signature_b64, recipient_dsa_pubkey_b64)
                successes.append((node.node_id, block["block_hash"]))
            except Exception as e:
                failures.append((node.node_id, str(e)))

        quorum_reached = len(successes) >= (len(self.nodes) // 2 + 1)
        return {
            "quorum_reached": quorum_reached,
            "accepted_count": len(successes),
            "total_nodes": len(self.nodes),
            "successes": successes,
            "failures": failures
        }

    def query_watermark_quorum(self, watermark_id: str) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        """
        Query all nodes for a watermark_id and evaluate 2-of-3 quorum agreement.
        Detects and flags tampered / compromised nodes.
        
        Returns:
            Tuple[Optional[Dict], Dict]:
                - Verified block matching consensus (or None if no quorum)
                - Quorum audit report details
        """
        node_responses: Dict[str, Optional[Dict[str, Any]]] = {}
        block_hashes: Dict[str, List[str]] = {}  # block_hash -> list of node_ids

        for node in self.nodes:
            # First check if node chain integrity is valid
            is_valid_chain = node.verify_chain_integrity()
            block = node.query_by_watermark_id(watermark_id)

            if not is_valid_chain:
                node_responses[node.node_id] = None
                continue

            node_responses[node.node_id] = block
            if block:
                b_hash = block["block_hash"]
                if b_hash not in block_hashes:
                    block_hashes[b_hash] = []
                block_hashes[b_hash].append(node.node_id)

        # Evaluate consensus
        max_agree_count = 0
        winning_block_hash = None
        for b_hash, node_ids in block_hashes.items():
            if len(node_ids) > max_agree_count:
                max_agree_count = len(node_ids)
                winning_block_hash = b_hash

        required_quorum = (len(self.nodes) // 2) + 1
        quorum_reached = max_agree_count >= required_quorum

        agreeing_nodes = block_hashes.get(winning_block_hash, []) if winning_block_hash else []
        disagreeing_nodes = [n.node_id for n in self.nodes if n.node_id not in agreeing_nodes]

        winning_block = None
        if winning_block_hash:
            for n in self.nodes:
                if n.node_id in agreeing_nodes:
                    winning_block = n.query_by_watermark_id(watermark_id)
                    break

        audit_report = {
            "quorum_reached": quorum_reached,
            "agreeing_count": len(agreeing_nodes),
            "total_nodes": len(self.nodes),
            "agreeing_nodes": agreeing_nodes,
            "disagreeing_nodes": disagreeing_nodes,
            "winning_block_hash": winning_block_hash
        }

        return winning_block, audit_report
