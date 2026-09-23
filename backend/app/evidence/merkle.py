"""Binary Merkle Tree Implementation for Audit Trace Verification.

Provides:
1. Deterministic leaf hashing of canonical serialized events
2. Binary Merkle tree root computation (O(N) construction)
3. Cryptographic inclusion proofs (audit paths) for individual events
4. Verification of inclusion proofs against Merkle root
"""

from typing import List, Dict, Any, Optional, Tuple
import hashlib
import json


def canonical_json_bytes(obj: Any) -> bytes:
    """Serializes an object to deterministic canonical JSON bytes."""
    serialized = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return serialized.encode("utf-8")


def hash_leaf(item: Any) -> str:
    """Computes SHA-256 hash of a leaf item with domain separation prefix 0x00."""
    payload = b"\x00" + canonical_json_bytes(item)
    return hashlib.sha256(payload).hexdigest()


def hash_internal_node(left_hex: str, right_hex: str) -> str:
    """Computes SHA-256 hash of two child nodes with domain separation prefix 0x01."""
    left_bytes = bytes.fromhex(left_hex)
    right_bytes = bytes.fromhex(right_hex)
    payload = b"\x01" + left_bytes + right_bytes
    return hashlib.sha256(payload).hexdigest()


class MerkleTree:
    """Binary Merkle Tree built over an ordered sequence of events or records."""

    def __init__(self, leaves: Optional[List[Any]] = None):
        self.raw_leaves: List[Any] = leaves or []
        self.leaf_hashes: List[str] = [hash_leaf(x) for x in self.raw_leaves]
        self.levels: List[List[str]] = []
        self._build_tree()

    @classmethod
    def compute_root(cls, leaves: Optional[List[Any]] = None) -> str:
        """Convenience classmethod to compute the Merkle root directly from a list of leaves."""
        return cls(leaves).root

    @property
    def leaves(self) -> List[Any]:
        """Returns the raw leaves of the tree."""
        return self.raw_leaves


    def _build_tree(self) -> None:
        """Constructs the tree levels from leaves to root."""
        if not self.leaf_hashes:
            empty_root = hashlib.sha256(b"EMPTY_MERKLE_TREE").hexdigest()
            self.levels = [[empty_root]]
            return

        current_level = list(self.leaf_hashes)
        self.levels = [current_level]

        while len(current_level) > 1:
            next_level: List[str] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Odd number of nodes: duplicate the last node
                    right = left
                parent = hash_internal_node(left, right)
                next_level.append(parent)
            self.levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> str:
        """Returns the hex-encoded root hash of the Merkle tree."""
        if not self.levels or not self.levels[-1]:
            return hashlib.sha256(b"EMPTY_MERKLE_TREE").hexdigest()
        return self.levels[-1][0]

    def get_inclusion_proof(self, index: int) -> List[Dict[str, str]]:
        """Generates an inclusion proof (audit path) for the leaf at `index`.
        
        Returns a list of sibling nodes with their direction ('left' or 'right').
        """
        if index < 0 or index >= len(self.leaf_hashes):
            raise IndexError(f"Leaf index {index} out of bounds (total leaves: {len(self.leaf_hashes)})")

        proof: List[Dict[str, str]] = []
        current_idx = index

        for level_idx in range(len(self.levels) - 1):
            level = self.levels[level_idx]
            if current_idx % 2 == 0:
                # Node is left child; sibling is right child
                if current_idx + 1 < len(level):
                    sibling = level[current_idx + 1]
                else:
                    sibling = level[current_idx]  # Duplicated node
                proof.append({"direction": "right", "hash": sibling})
            else:
                # Node is right child; sibling is left child
                sibling = level[current_idx - 1]
                proof.append({"direction": "left", "hash": sibling})

            current_idx = current_idx // 2

        return proof

    @staticmethod
    def verify_inclusion(item: Any, proof: List[Dict[str, str]], expected_root: str) -> bool:
        """Verifies an inclusion proof for an item against the expected root hash."""
        current_hash = hash_leaf(item)

        for step in proof:
            sibling_hash = step["hash"]
            direction = step["direction"]

            if direction == "right":
                current_hash = hash_internal_node(current_hash, sibling_hash)
            elif direction == "left":
                current_hash = hash_internal_node(sibling_hash, current_hash)
            else:
                return False

        return current_hash.lower() == expected_root.lower()
