"""
TrueState Protocol (TSP) - Core Implementation
Copyright (c) 2025 Vladislav Dunaev. All rights reserved.

This file is part of TrueState Protocol.

TrueState Protocol is dual-licensed:
- AGPL-3.0 for open source projects
- Commercial License for proprietary use

For commercial licensing, contact: dunaevlad@gmail.com
For AGPL-3.0 full text: https://www.gnu.org/licenses/agpl-3.0.html

SPDX-License-Identifier: AGPL-3.0-or-Commercial
"""

import hashlib
from typing import List, Tuple, Union


class MerkleTree:
    """
    Cryptographic Merkle tree implementation for batch verification and tamper-proof commitments.
    Provides efficient cryptographic proofs for membership verification in large datasets,
    enabling stateless validation of artifact integrity within commit chains.
    Key features:
    - Domain-separated hashing (leaf vs internal nodes)
    - Logarithmic proof size relative to tree size
    - Tamper-evident structure with cryptographic binding
    - Support for unbalanced trees (odd number of elements)
    Security properties:
    - Collision resistance via SHA3-256
    - Second-preimage resistance through prefix separation
    - Proof non-malleability with strict verification
    Usage:
    - Build tree from commit list
    - Generate compact membership proofs
    - Verify proofs without full tree reconstruction
    Implementation notes:
    - Leaves use prefix 0x00, internal nodes use 0x01
    - Duplicates last node when odd number at any level
    - Stores complete tree structure for proof generation
    """

    LEAF_PREFIX = b"\x00"
    NODE_PREFIX = b"\x01"

    def __init__(self):
        """
        Initialize empty Merkle tree structure.
        """
        self.tree = None

    def build_root(self, commits: List[str]):
        """
        Build complete Merkle tree from list of commits.
        Args:
            commits: List of commit identifiers to include in tree
        """
        leaves = [self.hash_commit(c) for c in commits]
        self.tree = self.build_tree(leaves) if leaves else []

    @classmethod
    def hash_commit(cls, commit: Union[str, bytes]) -> bytes:
        """
        Hash single commit with leaf prefix for domain separation.
        Args:
            commit: Commit data as string or bytes
        Returns:
            bytes: SHA3-256 hash of prefixed commit
        """
        if isinstance(commit, str):
            commit = commit.encode("utf-8")
        return hashlib.sha3_256(cls.LEAF_PREFIX + commit).digest()

    @classmethod
    def hash_pair(cls, left: bytes, right: bytes) -> bytes:
        """
        Hash a pair of nodes with internal node prefix.
        Args:
            left: Left node hash
            right: Right node hash
        Returns:
            bytes: SHA-256 hash of prefixed node pair
        """
        return hashlib.sha3_256(cls.NODE_PREFIX + left + right).digest()

    def build_tree(self, leaves: List[bytes]) -> List[List[bytes]]:
        """
        Construct complete Merkle tree from leaf hashes.
        Builds tree level by level, pairing nodes and hashing until
        single root remains. Duplicates last node if odd number.
        Args:
            leaves: List of leaf node hashes
        Returns:
            List[List[bytes]]: Complete tree structure (leaves to root)
        """
        tree = [leaves]
        current_level = leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = (
                    current_level[i + 1]
                    if i + 1 < len(current_level)
                    else current_level[i]
                )
                next_level.append(self.hash_pair(left, right))
            tree.append(next_level)
            current_level = next_level
        return tree

    def get_root(self) -> str:
        """
        Get hexadecimal root hash of constructed tree.
        Returns:
            str: Hex-encoded root hash, empty string if no tree
        """
        if not self.tree or not self.tree[-1]:
            return ""
        return self.tree[-1][0].hex()

    def get_proof(self, index: int) -> List[Tuple[bytes, bool]]:
        """
        Generate Merkle proof for element at given index.
        Creates authentication path from leaf to root with sibling
        hashes and position indicators.
        Args:
            index: Zero-based index of element to prove
        Returns:
            List[Tuple[bytes, bool]]: Proof path (hash, is_left_sibling)
        """
        proof: List[Tuple[bytes, bool]] = []
        idx = index
        for level in self.tree[:-1]:
            sibling_idx = idx ^ 1
            if sibling_idx >= len(level):
                sibling_idx = idx
            is_left = sibling_idx < idx
            proof.append((level[sibling_idx], is_left))
            idx //= 2
        return proof

    @classmethod
    def verify_proof(
        cls,
        leaf: str,
        proof: List[Tuple[bytes, bool]],
        root: str,
    ) -> bool:
        """
        Verify Merkle proof for given leaf against root hash.
        Reconstructs root hash from leaf and proof path, comparing
        with expected root.
        Args:
            leaf: Original leaf data to verify
            proof: Authentication path from get_proof()
            root: Expected root hash in hex format
        Returns:
            bool: True if proof is valid
        """
        if isinstance(leaf, str):
            leaf = leaf.encode()
        current_hash = hashlib.sha3_256(cls.LEAF_PREFIX + leaf).digest()
        for sibling_hash, is_left in proof:
            if is_left:
                current_hash = hashlib.sha3_256(
                    cls.NODE_PREFIX + sibling_hash + current_hash
                ).digest()
            else:
                current_hash = hashlib.sha3_256(
                    cls.NODE_PREFIX + current_hash + sibling_hash
                ).digest()
        return current_hash.hex() == root


if __name__ == "__main__":
    pass
