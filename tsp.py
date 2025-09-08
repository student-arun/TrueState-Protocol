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

import json
import logging
import os
import traceback
import tempfile
import time
import hashlib
import portalocker
from typing import Dict, List, Optional, Union
from core.controller import Controller
from core.merkletree import MerkleTree
from core.protocol import TSPProtocol
from core.protocol_session import TSPProtocolSession
from core.prime import Prime
from source.signature import SignatureHandler


class TSP:
    """
    True State Protocol (TSP) - Dual-mode interface for digital artifacts.

    Supports two operating modes:
    1. Stateless mode (persist=False): For ephemeral tokens like WEB_AUTH
       - Creates artifacts without storing in commits.json
       - Verification happens directly from artifact data
       - Maximum performance and scalability

    2. Stateful mode (persist=True): For permanent assets like LICENSE/NFT/CERTIFICATE
       - Creates artifacts and stores in commits.json registry
       - Verification through artifact lookup by ID
       - Full audit trail and uniqueness guarantees

    Key features:
    - Create artifacts with configurable computational difficulty
    - Verify artifacts without external dependencies (stateless mode)
    - Restore artifact state from minimal data
    - Support for designated ownership chains
    - Merkle tree integration for batch verification
    - Atomic commit storage with tamper detection

    Operating modes:
    - 'create': Generate new artifacts with proof-of-work
    - 'verify': Validate existing artifacts
    - 'restore': Reconstruct artifact state
    """

    def __init__(
        self,
        private_key_path: str,
        public_key_path: str,
        key_password: bytes,
        model: str,
        mode: str = "create",
        designated_owner_hash: Optional[bytes] = None,
    ):
        """
        Initialize TSP with cryptographic keys and configuration.
        Args:
            private_key_path: Path to private key PEM file
            public_key_path: Path to public key PEM file
            key_password: Password for private key decryption
            model: Artifact type ('NFT', 'CERTIFICATE', 'LICENSE', 'WEB_AUTH')
            mode: Operation mode ('create', 'verify', 'restore')
            designated_owner_hash: SHA3-256 hash of designated owner's public key
        Raises:
            ValueError: If mode is not supported
        """
        self.controller = Controller(model=model)
        self.signature = SignatureHandler(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            password=key_password,
        )
        self.merkle_tree = MerkleTree()
        self.mode = mode

        # Initialize based on mode
        match mode:
            case "create":
                self._init_create_mode(designated_owner_hash)
            case "verify" | "restore":
                self._init_verify_mode()
            case _:
                raise ValueError(
                    f"Unknown mode: {mode}. Supported modes: 'create', 'verify', 'restore'"
                )

    @staticmethod
    def create_pubkey_hash(pem_public_key: str) -> bytes:
        """
        Create TSP-compatible public key hash from PEM string.
        Converts PEM-formatted public key to raw bytes and computes
        SHA3-256 hash for use as designated_owner_hash.
        Args:
            pem_public_key: PEM string of public key
        Returns:
            bytes: 32-byte SHA3-256 hash for ownership designation
        """
        from cryptography.hazmat.primitives import serialization

        public_key = serialization.load_pem_public_key(pem_public_key.encode())
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return hashlib.sha3_256(public_key_bytes).digest()

    @staticmethod
    def create_pubkey_hash_from_file(public_key_path: str) -> bytes:
        """
        Create TSP-compatible hash from public key file.
        Reads PEM file and computes SHA3-256 hash for ownership.
        Args:
            public_key_path: Path to .pem public key file
        Returns:
            bytes: 32-byte SHA3-256 hash for designated_owner_hash
        """
        with open(public_key_path, "r") as f:
            pem_content = f.read()
        return TSP.create_pubkey_hash(pem_content)

    def _init_create_mode(self, designated_owner_hash: Optional[bytes]):
        """
        Initialize TSP for creating new artifacts.
        Sets up protocol and prime generator for artifact creation.
        Args:
            designated_owner_hash: Optional owner restriction
        """
        pubkey_bytes = self.signature.get_public_bytes()
        self.protocol = TSPProtocol(
            controller=self.controller,
            signature_obj=self.signature,
            signature_public_key_bytes=pubkey_bytes,
            designated_owner_pubkey_hash=designated_owner_hash,
        )
        self.prime = Prime(
            protocol=self.protocol,
            pubkey_bytes=pubkey_bytes,
        )

    def _init_verify_mode(self):
        """
        Initialize TSP for verification/restoration mode.
        Protocol will be instantiated during actual verification.
        """
        self.protocol = None  # Will be set during verification

    def create_artifact(
        self,
        persist: bool = True,
        personalized_for: Optional[bytes] = None,
    ) -> Dict:
        """
        Create new TSP artifact with configurable persistence.

        Args:
            persist: If True, saves to commits.json (stateful). If False, returns data only (stateless)
            personalized_for: Deprecated - use designated_owner_hash in __init__

        Returns:
            Dict: Artifact creation results. Format depends on persist parameter:
                - persist=True: includes artifact_id, merkle_root, merkle_proof (stateful mode)
                - persist=False: includes full artifact_data for embedding in tokens (stateless mode)
        Raises:
            ValueError: If not in 'create' mode
        """
        if self.mode != "create":
            raise ValueError("TSP must be in 'create' mode")

        print(f"Starting TSP Protocol (persist={persist})...")

        # 1. Generate prime number
        print("Mining cryptographic prime...")
        pow_prime = self.prime.generate_prime()
        print(f"Prime generated: {str(pow_prime)[:20]}... ({self.protocol.PRIME_BITS} bits)")

        # 2. Genesis commitment is already created
        genesis_hash = self.protocol.GENESIS_COMMIT_HASH.hex()
        print(f"Genesis hash: {genesis_hash[:16]}...")

        # 3. Create seed commit
        hash_seed = hashlib.sha3_256(self.protocol.seed).hexdigest()
        print(f"Seed commit created: {hash_seed[:16]}...")

        if persist:
            # STATEFUL MODE: Save to commits.json with Merkle tree
            print("Committing artifact to permanent storage...")
            commit_result = self.commit()

            result = {
                "success": True,
                "artifact_id": commit_result["merkle_index"],
                "seed_hash": hash_seed,
                "prime": pow_prime,
                "genesis_hash": genesis_hash,
                "config_hash": self.protocol.config_hash().hex(),
                "combined_hash": self.protocol.combined_hash.hex(),
                "rarity": self.protocol.RARITY_THRESHOLD,
                "merkle_root": commit_result["merkle_root"],
                "merkle_proof": commit_result["merkle_proof"],
                "is_personalized": bool(self.protocol.OWNERSHIP_FLAGS & 0b0010),
                "creation_timestamp": int.from_bytes(self.protocol.seed[24:32], "big"),
                "mode": "stateful"
            }

            print(f"TSP Protocol completed (stateful)!")
            print(f"Artifact ID: {result['artifact_id']}")

        else:
            # STATELESS MODE: Return full artifact data without storage
            print("Creating stateless artifact data...")
            artifact_data = self._create_artifact_data()

            result = {
                "success": True,
                "artifact_data": artifact_data,  # Full data for token embedding
                "seed_hash": hash_seed,
                "prime": pow_prime,
                "genesis_hash": genesis_hash,
                "config_hash": self.protocol.config_hash().hex(),
                "combined_hash": self.protocol.combined_hash.hex(),
                "rarity": self.protocol.RARITY_THRESHOLD,
                "is_personalized": bool(self.protocol.OWNERSHIP_FLAGS & 0b0010),
                "creation_timestamp": int.from_bytes(self.protocol.seed[24:32], "big"),
                "mode": "stateless"
            }

            print(f"TSP Protocol completed (stateless)!")
            print(f"Artifact ready for token embedding")

        print(f"Config Hash: {self.protocol.config_hash().hex()}")
        print(f"Rarity: {self.protocol.RARITY_THRESHOLD}")
        return result

    def verify_artifact(
        self,
        artifact_identifier: Union[int, str, Dict],
        verify_merkle: bool = True,
        verify_chain: bool = False,
        debug_config_hash: bool = False,
    ) -> Dict:
        """
        Perform comprehensive artifact verification with auto-mode detection.

        Args:
            artifact_identifier: Can be:
                - int/str: Artifact ID or config hash (stateful mode via commits.json)
                - Dict: Full artifact data (stateless mode)
            verify_merkle: Whether to verify Merkle tree inclusion
            verify_chain: Whether to verify derivation chain
            debug_config_hash: Print detailed config hash materials

        Returns:
            Dict: Verification results with 'all_valid' summary
        """
        # Auto-detect mode based on input type
        if isinstance(artifact_identifier, dict):
            # Stateless mode: verify from provided data
            print("Auto-detected: Stateless verification mode")
            return self.verify_artifact_from_data(
                artifact_identifier,
                verify_merkle=verify_merkle
            )
        else:
            # Stateful mode: verify via commits.json lookup
            print("Auto-detected: Stateful verification mode")
            return self._verify_artifact_stateful(
                artifact_identifier,
                verify_merkle=verify_merkle,
                verify_chain=verify_chain,
                debug_config_hash=debug_config_hash
            )

    def verify_my_ownership(
        self,
        artifact_identifier: Union[int, str, Dict],
        verify_merkle: bool = True
    ) -> Dict:
        """
        Verify ownership with auto-mode detection.

        Args:
            artifact_identifier: Can be:
                - int/str: Artifact ID or config hash (stateful mode)
                - Dict: Full artifact data (stateless mode)
            verify_merkle: Whether to verify Merkle inclusion

        Returns:
            Dict: Ownership verification results
        """
        # Auto-detect mode based on input type
        if isinstance(artifact_identifier, dict):
            # Stateless mode
            print("Auto-detected: Stateless ownership verification")
            return self.verify_my_ownership_from_data(artifact_identifier)
        else:
            # Stateful mode
            print("Auto-detected: Stateful ownership verification")
            return self._verify_my_ownership_stateful(
                artifact_identifier,
                verify_merkle=verify_merkle
            )

    def verify_artifact_from_data(self, artifact_data: Dict, verify_merkle: bool = False) -> Dict:
        """
        Verify artifact directly from provided data (stateless verification).

        This method enables true stateless verification without requiring commits.json lookup.
        Perfect for WEB_AUTH tokens where all verification data is embedded in the token.

        Args:
            artifact_data: Complete artifact data (from stateless create_artifact or token)
            verify_merkle: Whether to verify Merkle inclusion (usually False for stateless)

        Returns:
            Dict: Comprehensive verification results including:
                - all_valid: Overall verification status
                - pow_valid, signature_valid, genesis_valid, config_hash_valid, prime_valid
                - artifact metadata and timing info
        """
        print(f"Stateless artifact verification...")

        try:
            # Create controller and signature handler for verification
            controller = Controller(artifact_data["model"])
            creator_pubkey = bytes.fromhex(artifact_data["public_key"])
            creator_signature = SignatureHandler.create_verify_only(creator_pubkey)

            # Create TSPProtocolSession for verification
            session = TSPProtocolSession(
                controller=controller,
                signature_obj=creator_signature,
                signature_public_key_bytes=creator_pubkey,
                seed=bytes.fromhex(artifact_data["seed"]),
                signature=bytes.fromhex(artifact_data["signature"]),
                artifact_index=artifact_data.get("artifact_index", 0),
                stored_commit_data=artifact_data,
                expected_combined_hash=bytes.fromhex(artifact_data["combined_hash"]),
                expected_genesis_hash=bytes.fromhex(artifact_data["genesis_hash"]),
                expected_config_hash=bytes.fromhex(artifact_data["config_hash"]),
                designated_owner_hash=(
                    bytes.fromhex(artifact_data["designated_owner"])
                    if artifact_data.get("designated_owner")
                    else None
                ),
                prime=int(artifact_data["prime"]) if artifact_data.get("prime") else None,
            )

            # Perform comprehensive verification
            verification_results = session.verify_all(
                expected_config_hash=bytes.fromhex(artifact_data["config_hash"])
            )

            # Add artifact metadata
            verification_results.update({
                "artifact_index": artifact_data.get("artifact_index", 0),
                "config_hash": artifact_data["config_hash"],
                "creation_timestamp": artifact_data.get("creation_timestamp"),
                "rarity": artifact_data.get("rarity_threshold"),
                "is_personalized": artifact_data.get("is_personalized", False),
                "verification_mode": "stateless"
            })

            # Merkle verification (usually skipped for stateless tokens)
            if verify_merkle and artifact_data.get("merkle_proof"):
                merkle_valid = self._verify_merkle_inclusion_static(artifact_data)
                verification_results["merkle_valid"] = merkle_valid
            else:
                verification_results["merkle_valid"] = True  # N/A for stateless

            print(f"Stateless verification completed!")
            print(f"Overall Valid: {verification_results['all_valid']}")
            print(f"PoW Valid: {verification_results['pow_valid']}")
            print(f"Signature Valid: {verification_results['signature_valid']}")

            return verification_results

        except Exception as e:
            print(f"Stateless verification error: {e}")
            return {
                "success": False,
                "error": str(e),
                "all_valid": False,
                "verification_mode": "stateless"
            }

    def verify_my_ownership_from_data(self, artifact_data: Dict) -> Dict:
        """
        Verify ownership of artifact using current TSP credentials (stateless mode).

        Args:
            artifact_data: Complete artifact data

        Returns:
            Dict: Ownership verification results
        """
        # First verify artifact integrity
        verification = self.verify_artifact_from_data(artifact_data, verify_merkle=False)

        if not verification["all_valid"]:
            return {
                "artifact_valid": False,
                "ownership_valid": False,
                "all_checks_valid": False,
                "error": "Artifact verification failed",
                "verification_mode": "stateless"
            }

        # Check ownership
        my_pubkey = self.signature.get_public_bytes()
        my_hash = hashlib.sha3_256(my_pubkey).digest()

        designated_owner = artifact_data.get("designated_owner")
        if designated_owner:
            ownership_valid = (my_hash == bytes.fromhex(designated_owner))
        else:
            ownership_valid = True  # No ownership restriction

        return {
            "artifact_valid": True,
            "ownership_valid": ownership_valid,
            "my_pubkey": my_pubkey.hex(),
            "creator_pubkey": artifact_data["public_key"],
            "is_personalized": artifact_data.get("is_personalized", False),
            "all_checks_valid": ownership_valid,
            "verification_mode": "stateless"
        }

    def _verify_artifact_stateful(
        self,
        artifact_identifier: Union[int, str],
        verify_merkle: bool = True,
        verify_chain: bool = False,
        debug_config_hash: bool = False,
    ) -> Dict:
        """
        Perform comprehensive artifact verification via commits.json (stateful mode).
        """
        try:
            # 1. Load commit data
            commit_data = self._load_artifact_data(artifact_identifier)
            # 2. Check genesis record consistency
            genesis_record = commit_data.get("genesis_record", "")
            artifact_index = commit_data.get("artifact_index", 0)
            print(f"Verifying artifact:")
            print(f"Artifact Index: {artifact_index}")
            print(f"Genesis Record: {genesis_record}")
            # 3. Restore artifact
            session = self.restore_artifact(artifact_identifier)
            # 4. Debug config hash if requested
            if debug_config_hash:
                computed_hash = session.config_hash()
                expected_hash = bytes.fromhex(commit_data["config_hash"])
                print(f"\nCONFIG HASH DEBUG:")
                print(f"Expected: {expected_hash.hex()}")
                print(f"Computed: {computed_hash.hex()}")
                print(f"Match: {computed_hash == expected_hash}")
                if computed_hash != expected_hash:
                    print("\nConfig hash materials:")
                    materials = session.protocol._get_hash_materials()
                    for i, (name, value) in enumerate(materials):
                        if isinstance(value, bytes):
                            print(f"{i:2d}. {name}: {value.hex()}")
                        else:
                            print(f"{i:2d}. {name}: {value}")
            # 5. Verify artifact integrity
            verification_results = session.verify_all(
                expected_config_hash=bytes.fromhex(commit_data["config_hash"])
            )
            # 6. Verify Merkle tree inclusion
            if verify_merkle:
                merkle_valid = self._verify_merkle_inclusion(commit_data)
                verification_results["merkle_valid"] = merkle_valid
                if not merkle_valid:
                    print(f"Merkle tree verification failed")
                else:
                    print(f"Merkle tree verification passed")
            # 7. Add artifact info
            verification_results.update(
                {
                    "artifact_index": artifact_index,
                    "config_hash": commit_data["config_hash"],
                    "creation_timestamp": commit_data.get("creation_timestamp"),
                    "rarity": commit_data.get("rarity_threshold"),
                    "is_personalized": commit_data.get("is_personalized", False),
                    "verification_mode": "stateful"
                }
            )
            print(f"Artifact verification completed!")
            print(f"Artifact Index: {artifact_index}")
            print(f"Overall Valid: {verification_results['all_valid']}")
            print(f"PoW Valid: {verification_results['pow_valid']}")
            print(f"Signature Valid: {verification_results['signature_valid']}")
            return verification_results
        except Exception as e:
            print(f"Verification error: {e}")
            return {
                "success": False,
                "error": str(e),
                "all_valid": False,
                "verification_mode": "stateful"
            }

    def _verify_my_ownership_stateful(
        self,
        artifact_identifier: Union[int, str],
        verify_merkle: bool = True
    ) -> Dict:
        """
        Verify ownership of artifact using current TSP credentials (stateful mode).
        """
        if self.mode not in ["verify", "restore"]:
            self._init_verify_mode()

        # 1. Load artifact data
        commit_data = self._load_artifact_data(artifact_identifier)
        # 2. Get creator's public key from commits.json
        creator_pubkey = bytes.fromhex(commit_data["public_key"])
        # 3. Create verify-only SignatureHandler for creator
        creator_signature = SignatureHandler.create_verify_only(creator_pubkey)
        # 4. Verify artifact as creator
        session = TSPProtocolSession(
            controller=Controller(commit_data["model"]),
            signature_obj=creator_signature,
            signature_public_key_bytes=creator_pubkey,
            seed=bytes.fromhex(commit_data["seed"]),
            signature=bytes.fromhex(commit_data["signature"]),
            artifact_index=commit_data.get("artifact_index", 0),
            stored_commit_data=commit_data,
            expected_combined_hash=bytes.fromhex(commit_data["combined_hash"]),
            expected_genesis_hash=bytes.fromhex(commit_data["genesis_hash"]),
            expected_config_hash=bytes.fromhex(commit_data["config_hash"]),
            designated_owner_hash=(
                bytes.fromhex(commit_data["designated_owner"])
                if commit_data.get("designated_owner")
                else None
            ),
            prime=int(commit_data["prime"]) if commit_data.get("prime") else None,
        )

        # 5. Check ownership by current instance(self.signature)
        my_pubkey = self.signature.get_public_bytes()
        my_hash = hashlib.sha3_256(my_pubkey).digest()
        ownership_valid = session.verify_ownership(my_pubkey)

        # 6. Comprehensive artifact validation
        artifact_results = session.verify_all()

        # 7. Merkle tree verification
        merkle_valid = True
        if verify_merkle:
            self.debug_merkle_tree_construction(commit_data)
            merkle_valid = self._verify_merkle_inclusion(commit_data)
            print(f"Merkle verification: {'Valid' if merkle_valid else 'Invalid'}")

        self.deep_pow_diagnostic(session, commit_data)
        return {
            "artifact_valid": artifact_results["all_valid"],
            "ownership_valid": ownership_valid,
            "merkle_valid": merkle_valid,
            "my_pubkey": my_pubkey.hex(),
            "creator_pubkey": creator_pubkey.hex(),
            "artifact_index": commit_data.get("artifact_index"),
            "creation_timestamp": commit_data.get("creation_timestamp"),
            "rarity": commit_data.get("rarity_threshold"),
            "is_personalized": commit_data.get("is_personalized", False),
            "pow_valid": artifact_results.get("pow_valid", False),
            "signature_valid": artifact_results["signature_valid"],
            "genesis_valid": artifact_results["genesis_valid"],
            "config_hash_valid": artifact_results["config_hash_valid"],
            "prime_valid": artifact_results.get("prime_valid", True),
            "all_checks_valid": (
                artifact_results["all_valid"]
                and ownership_valid
                and merkle_valid
            ),
            "verification_mode": "stateful"
        }

    def _create_artifact_data(self) -> Dict:
        """
        Create complete artifact data dictionary for stateless mode.

        Returns:
            Dict: All data needed for stateless verification
        """
        prime_bytes = self.protocol.PRIME.to_bytes(
            (self.protocol.PRIME.bit_length() + 7) // 8, "big"
        )
        prime_hash = hashlib.sha3_256(prime_bytes).hexdigest()
        seed_commit = hashlib.sha3_256(self.protocol.seed).hexdigest()

        return {
            # Core identity
            "algo_version": self.controller.get_params()["ALGO_VERSION"],
            "model": self.controller.model,
            "artifact_index": self.protocol.ARTIFACT_INDEX,
            "timestamp": int(time.time()),

            # Cryptographic foundation
            "seed": self.protocol.seed.hex(),
            "seed_commit": seed_commit,
            "public_key": self.signature.get_public_bytes().hex(),
            "signature": self.protocol.SIGNATURE.hex(),

            # Hash integrity
            "config_hash": self.protocol.config_hash().hex(),
            "combined_hash": self.protocol.combined_hash.hex(),
            "genesis_hash": self.protocol.GENESIS_COMMIT_HASH.hex(),
            "genesis_signature": self.protocol.GENESIS_SIGNATURE.hex(),

            # Ownership & personalization
            "designated_owner": (
                self.protocol.DESIGNATED_OWNER_HASH.hex()
                if self.protocol.DESIGNATED_OWNER_HASH
                else None
            ),
            "ownership_flags": self.protocol.OWNERSHIP_FLAGS,
            "is_personalized": bool(self.protocol.OWNERSHIP_FLAGS & 0b0010),

            # Prime & cryptographic proof
            "prime": str(self.protocol.PRIME),
            "prime_hash": prime_hash,
            "prime_nonce": self.protocol.PRIME_NONCE,
            "prime_bits": self.protocol.PRIME_BITS,

            # Proof of work
            "pow_difficulty": self.protocol.POW_DIFFICULTY,
            "base_pow_difficulty": self.controller.get_params()["BASE_POW_DIFFICULTY"],

            # Rarity & game mechanics
            "rarity_threshold": self.protocol.RARITY_THRESHOLD,
            "total_bytes": self.protocol.TOTAL_BYTES,
            "target_bytes": self.protocol.TARGET_BYTES,
            "target_bytes_end": self.protocol.TARGET_BYTES_END,
            "target_interval": self.protocol.TARGET_INTERVAL,
            "max_offset": self.protocol.MAX_OFFSET,

            # Argon2 parameters
            "memory_cost": self.controller.get_params()["MEMORY_COST"],
            "time_cost": self.controller.get_params()["TIME_COST"],
            "parallelism": self.controller.get_params()["PARALLELISM"],
            "hash_len": self.controller.get_params()["HASH_LEN"],
            "salt": self.protocol.per_instance_salt.hex(),

            # Readable metadata
            "genesis_record": self.protocol.genesis_record,
            "creation_timestamp": int.from_bytes(self.protocol.seed[24:32], "big"),
        }

    def restore_artifact(
        self, artifact_identifier: Union[int, str]
    ) -> TSPProtocolSession:
        """
        Restore artifact from permanent storage.
        Reconstructs full artifact state from minimal stored data,
        enabling verification without original creation context.
        Args:
            artifact_identifier: Artifact ID (int) or config hash (str)
        Returns:
            TSPProtocolSession: Restored artifact session
        Raises:
            FileNotFoundError: If commits.json not found
            ValueError: If artifact not found
        """
        commit_data = self._load_artifact_data(artifact_identifier)
        print(f"Restoring artifact:")
        print(f"Artifact Index: {commit_data['artifact_index']}")
        print(f"Expected Genesis: {commit_data['genesis_hash']}")
        print(f"Seed: {commit_data['seed'][:32]}...")
        # Debug: Check if we're using the correct artifact_index
        expected_index = commit_data.get("artifact_index", 0)
        session = TSPProtocolSession(
            controller=Controller(commit_data["model"]),
            signature_obj=self.signature,
            signature_public_key_bytes=bytes.fromhex(commit_data["public_key"]),
            seed=bytes.fromhex(commit_data["seed"]),
            signature=bytes.fromhex(commit_data["signature"]),
            artifact_index=expected_index,  # Use stored artifact_index
            expected_combined_hash=bytes.fromhex(commit_data["combined_hash"]),
            expected_config_hash=bytes.fromhex(commit_data["config_hash"]),
            expected_genesis_hash=bytes.fromhex(commit_data["genesis_hash"]),
            designated_owner_hash=(
                bytes.fromhex(commit_data["designated_owner"])
                if commit_data.get("designated_owner")
                else None
            ),
            prime=int(commit_data["prime"]) if commit_data.get("prime") else None,
            stored_commit_data=commit_data,
        )
        print(f"Computed Genesis: {session.protocol.GENESIS_COMMIT_HASH.hex()}")
        return session

    @staticmethod
    def list_artifacts(
        filter_owner: Optional[str] = None,
        filter_creator: Optional[str] = None
    ) -> List[Dict]:
        """
        List all artifacts with optional filtering.
        Reads commits.json and returns artifact summaries with
        support for creator and owner filtering.
        Args:
            filter_owner: Filter by designated owner hash (hex)
            filter_creator: Filter by creator public key (hex)
        Returns:
            List[Dict]: Artifact summaries with metadata
        """
        if not os.path.exists("commits.json"):
            return []
        with open("commits.json", "r") as f:
            commits_data = json.load(f)

        artifacts = []
        for i, commit in enumerate(commits_data):
            # Apply creator filter
            if filter_creator and commit.get("public_key") != filter_creator:
                continue
            # Apply owner filter
            if filter_owner and commit.get("designated_owner") != filter_owner:
                continue
            artifact_info = {
                "array_index": i,  # Position in commits.json array
                "artifact_index": commit.get(
                    "artifact_index", i
                ),  # Protocol artifact index
                "config_hash": commit["config_hash"],
                "creation_timestamp": commit.get("creation_timestamp"),
                "rarity": commit.get("rarity_threshold"),
                "prime_bits": commit.get("prime_bits"),
                "is_personalized": commit.get("is_personalized", False),
                "creator": (
                    commit.get("public_key", "")[:16] + "..."
                    if commit.get("public_key")
                    else None
                ),
                "owner": (
                    commit.get("designated_owner", "")[:16] + "..."
                    if commit.get("designated_owner")
                    else commit.get("public_key", "")[:16] + "..."
                ),
                "merkle_root": commit.get("merkle_root"),
            }
            artifacts.append(artifact_info)
        return artifacts

    def get_artifact_info(self, artifact_identifier: Union[int, str]) -> Dict:
        """
        Get detailed information about specific artifact.
        Args:
            artifact_identifier: Artifact ID or config hash
        Returns:
            Dict: Complete artifact information
        """
        session = self.restore_artifact(artifact_identifier)
        return session.get_artifact_info()

    @staticmethod
    def _load_artifact_data(identifier: Union[int, str]) -> Dict:
        """
        Load artifact data from commits.json storage.
        Args:
            identifier: Artifact index (int) or config hash (str)
        Returns:
            Dict: Stored artifact data
        Raises:
            FileNotFoundError: If commits.json not found
            ValueError: If artifact not found
        """
        if not os.path.exists("commits.json"):
            raise FileNotFoundError("No commits.json found")

        with open("commits.json", "r") as f:
            commits_data = json.load(f)

        if isinstance(identifier, int):
            # Try to load by artifact_index field first
            for commit in commits_data:
                if commit.get("artifact_index") == identifier:
                    return commit
            # Fallback: load by array index if artifact_index not found
            if 0 <= identifier < len(commits_data):
                return commits_data[identifier]
            raise ValueError(f"Artifact with artifact_index {identifier} not found")
        elif isinstance(identifier, str):
            # Load by config hash
            for commit in commits_data:
                if commit["config_hash"] == identifier:
                    return commit
            raise ValueError(f"Artifact with config hash {identifier} not found")
        else:
            raise ValueError(
                "Identifier must be int (artifact_index) or str (config hash)"
            )

    @staticmethod
    def _verify_merkle_inclusion_static(commit_data: Dict) -> bool:
        """
        Static Merkle tree verification without instance.
        Args:
            commit_data: Stored commit data with proof
        Returns:
            bool: True if Merkle proof valid
        """
        try:
            merkle_tree = MerkleTree()
            merkle_proof = commit_data.get("merkle_proof", [])
            merkle_root = commit_data.get("merkle_root")
            merkle_index = commit_data.get("merkle_index", 0)

            if not merkle_root:
                return False

            # Build leaf data
            leaf_data = f"{commit_data['seed_commit']}|{commit_data['prime_hash']}|{commit_data['config_hash']}|{commit_data['genesis_hash']}|{commit_data['combined_hash']}"
            # Determine tree type by merkle_index and proof presence
            total_artifacts = merkle_index + 1
            if total_artifacts == 1:
                # Single leaf: root should equal hash(leaf)
                expected_root = merkle_tree.hash_commit(leaf_data).hex()
                return expected_root == merkle_root
            else:
                # Multi-leaf: should have proof
                if not merkle_proof:
                    print(
                        f"ERROR: Multi-leaf tree (index {merkle_index}) but no proof!"
                    )
                    return False

                proof_tuples = [
                    (bytes.fromhex(p["hash"]), p["left"]) for p in merkle_proof
                ]
                return merkle_tree.verify_proof(leaf_data, proof_tuples, merkle_root)
        except Exception as e:
            print(f"Static Merkle verification error: {e}")
            return False

    def _verify_merkle_inclusion(self, commit_data: Dict) -> bool:
        """
        Verify artifact inclusion in Merkle tree.
        Reconstructs proof path and validates against stored root,
        handling both single-leaf and multi-leaf tree cases.
        Args:
            commit_data: Stored data with Merkle proof
        Returns:
            bool: True if inclusion verified
        """
        try:
            merkle_proof = commit_data.get("merkle_proof", [])
            merkle_root = commit_data.get("merkle_root")
            merkle_index = commit_data.get("merkle_index", 0)
            print(f"Merkle verification debug:")
            print(f"Proof length: {len(merkle_proof)}")
            print(f"Root: {merkle_root}")
            print(f"Index: {merkle_index}")
            if not merkle_root:
                print("   Error: No merkle root provided")
                return False

            # Reconstruct the leaf data exactly as in commit()
            leaf_data = f"{commit_data['seed_commit']}|{commit_data['prime_hash']}|{commit_data['config_hash']}|{commit_data['genesis_hash']}|{commit_data['combined_hash']}"
            print(f"Leaf data: {leaf_data[:100]}...")
            # Determine the tree type based on the number of artifacts at the time of creation
            total_artifacts_at_creation = merkle_index + 1
            if total_artifacts_at_creation == 1:
                # Single leaf case
                print(" Single leaf case (verified by total count)")
                expected_root = self.merkle_tree.hash_commit(leaf_data).hex()
                print(f" Expected root: {expected_root}")
                print(f"Actual root:   {merkle_root}")
                result = expected_root == merkle_root
                print(f"Match: {result}")
                return result
            else:
                # Multi-leaf case - manual verification
                print(
                    f"Multi-leaf case ({total_artifacts_at_creation} total artifacts)"
                )
                if not merkle_proof:
                    print(f"ERROR: Multi-leaf tree but no proof provided!")
                    return False
                # Convert the proof to the required format
                proof_tuples = [
                    (bytes.fromhex(p["hash"]), p["left"]) for p in merkle_proof
                ]
                print(f"Proof tuples: {len(proof_tuples)} items")
                # Manual verification using same methods as creation
                # 1.Get leaf hash same way as MerkleTree.hash_commit
                current_hash = self.merkle_tree.hash_commit(leaf_data)
                print(f"Initial leaf hash: {current_hash.hex()}")
                # 2.Walk through proof step by step
                for i, (sibling_hash, is_left) in enumerate(proof_tuples):
                    print(
                        f"Step {i}: sibling={sibling_hash.hex()[:16]}..., is_left={is_left}"
                    )
                    print(f"Step {i}: current_before={current_hash.hex()[:16]}...")
                    # Use the same hash_pair function as in the MerkleTree.
                    if is_left:
                        # Sibling left, current right
                        current_hash = self.merkle_tree.hash_pair(
                            sibling_hash, current_hash
                        )
                    else:
                        # Current left, sibling right
                        current_hash = self.merkle_tree.hash_pair(
                            current_hash, sibling_hash
                        )
                    print(f"   Step {i}: current_after={current_hash.hex()[:16]}...")
                # 3.Compare final hash with expected root
                final_hash_hex = current_hash.hex()
                print(f"Final computed hash: {final_hash_hex}")
                print(f"Expected root: {merkle_root}")
                result = final_hash_hex == merkle_root
                print(f"Manual verification result: {result}")
                # Additional diagnostics if mismatch
                if not result:
                    print(f"!!! MISMATCH DETECTED !!!")
                    print(f"Computed: {final_hash_hex}")
                    print(f"Expected: {merkle_root}")
                    # compare it with the original verify_proof for diagnostics
                    try:
                        original_result = self.merkle_tree.verify_proof(
                            leaf_data, proof_tuples, merkle_root
                        )
                        print(f"Original verify_proof result: {original_result}")
                    except Exception as e:
                        print(f"Original verify_proof error: {e}")
                return result
        except Exception as e:
            print(f"Merkle verification error: {e}")
            traceback.print_exc()
            #  In case of error run additional diagnostics
            print("!!! Exception during Merkle verification - running debug !!!")
            try:
                self.debug_merkle_tree_construction(commit_data)
            except Exception as err:
                pass  # Don't crash if debug also fails
            return False

    def commit(self) -> Dict:
        """
        Commit artifact to permanent storage with atomic write.
        Creates comprehensive commit entry with all verification data,
        builds Merkle tree for batch proof, and atomically writes to
        commits.json with file locking.
        Returns:
            Dict: Commit results including:
                - merkle_index: Position in tree
                - merkle_root: Tree root hash
                - merkle_proof: Inclusion proof
                - config_hash: Artifact configuration hash
        Raises:
            IOError: If file operations fail
        """
        commit_file = "commits.json"
        # Initialize file if not exists
        if not os.path.exists(commit_file) or os.stat(commit_file).st_size == 0:
            with open(commit_file, "w") as f:
                json.dump([], f)

        # Data prepare
        prime_bytes = self.protocol.PRIME.to_bytes(
            (self.protocol.PRIME.bit_length() + 7) // 8, "big"
        )
        prime_hash = hashlib.sha3_256(prime_bytes).hexdigest()
        seed_commit = hashlib.sha3_256(self.protocol.seed).hexdigest()
        with portalocker.Lock(commit_file, "r+", timeout=5):
            # Load existing commits
            with open(commit_file, "r") as f:
                try:
                    commits_data = json.load(f)
                except (json.JSONDecodeError, IOError) as e:
                    logging.error(f"Error loading commits: {e}")
                    commits_data = []
            # Build Merkle tree with existing leaves
            leaf_strings = []
            for c in commits_data:
                # Create leaf data as string (MerkleTree.build_root expects List[str])
                leaf_data = f"{c['seed_commit']}|{c['prime_hash']}|{c['config_hash']}|{c['genesis_hash']}|{c['combined_hash']}"
                leaf_strings.append(leaf_data)
            # Add current leaf as string
            current_leaf_data = f"{seed_commit}|{prime_hash}|{self.protocol.config_hash().hex()}|{self.protocol.GENESIS_COMMIT_HASH.hex()}|{self.protocol.combined_hash.hex()}"
            leaf_strings.append(current_leaf_data)
            print(f"Creating Merkle tree:")
            print(f"Current leaf data: {current_leaf_data[:100]}...")
            # Build Merkle tree (expects List[str])
            self.merkle_tree.build_root(leaf_strings)
            idx = len(leaf_strings) - 1
            proof = self.merkle_tree.get_proof(idx)
            # Debug: verify what root we actually get
            computed_root = self.merkle_tree.get_root()
            print(f"Computed root: {computed_root}")
            # Also debug: what would hash_commit give us for current leaf?
            debug_hash = self.merkle_tree.hash_commit(current_leaf_data).hex()
            print(f"Direct hash of leaf: {debug_hash}")
            # Create commit entry
            commit_entry = self._create_commit_entry(
                seed_commit, prime_hash, idx, proof, commits_data
            )
            # Sign commit
            commit_data_str = json.dumps(
                commit_entry, sort_keys=True, separators=(",", ":")
            )
            commit_entry["commit_signature"] = self.signature.sign(
                commit_data_str.encode()
            ).hex()
            # Add to commits
            commits_data.append(commit_entry)
            # Atomic write
            tmp = tempfile.NamedTemporaryFile("w", dir=".", delete=False)
            json.dump(commits_data, tmp, indent=2)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp.close()
            os.replace(tmp.name, commit_file)
            result = {
                "merkle_index": idx,
                "merkle_root": commit_entry["merkle_root"],
                "merkle_proof": commit_entry["merkle_proof"],
                "config_hash": commit_entry["config_hash"],
            }
            print(f"Artifact committed successfully!")
            print(f"Artifact ID: {idx}")
            print(f"Config Hash: {commit_entry['config_hash']}")
            print(f"Merkle Root: {commit_entry['merkle_root']}")
            return result

    def _create_commit_entry(
        self,
        seed_commit: str,
        prime_hash: str,
        idx: int,
        proof: List,
        commits_data: List,
    ) -> Dict:
        """
        Create comprehensive commit entry for storage.
        Assembles all artifact data needed for future verification
        and restoration, including cryptographic proofs and metadata.
        Args:
            seed_commit: SHA3-256 hash of seed
            prime_hash: SHA3-256 hash of prime
            idx: Merkle tree index
            proof: Merkle inclusion proof
            commits_data: Existing commits for chain reference
        Returns:
            Dict: Complete commit entry
        """
        return {
            # Core identity
            "algo_version": self.controller.get_params()["ALGO_VERSION"],
            "model": self.controller.model,
            "artifact_index": self.protocol.ARTIFACT_INDEX,
            "timestamp": int(time.time()),
            # Cryptographic foundation
            "seed": self.protocol.seed.hex(),
            "seed_commit": seed_commit,
            "public_key": self.signature.get_public_bytes().hex(),
            "signature": self.protocol.SIGNATURE.hex(),
            # Hash integrity
            "config_hash": self.protocol.config_hash().hex(),
            "combined_hash": self.protocol.combined_hash.hex(),
            "genesis_hash": self.protocol.GENESIS_COMMIT_HASH.hex(),
            "genesis_signature": self.protocol.GENESIS_SIGNATURE.hex(),
            # Ownership & personalization
            "designated_owner": (
                self.protocol.DESIGNATED_OWNER_HASH.hex()
                if self.protocol.DESIGNATED_OWNER_HASH
                else None
            ),
            "ownership_flags": self.protocol.OWNERSHIP_FLAGS,
            "is_personalized": bool(self.protocol.OWNERSHIP_FLAGS & 0b0010),
            # Prime & cryptographic proof
            "prime": str(self.protocol.PRIME),
            "prime_hash": prime_hash,
            "prime_nonce": self.protocol.PRIME_NONCE,
            "prime_bits": self.protocol.PRIME_BITS,
            # Proof of work
            "pow_difficulty": self.protocol.POW_DIFFICULTY,
            "base_pow_difficulty": self.controller.get_params()["BASE_POW_DIFFICULTY"],
            # Rarity & game mechanics
            "rarity_threshold": self.protocol.RARITY_THRESHOLD,
            "total_bytes": self.protocol.TOTAL_BYTES,
            "target_bytes": self.protocol.TARGET_BYTES,
            "target_bytes_end": self.protocol.TARGET_BYTES_END,
            "target_interval": self.protocol.TARGET_INTERVAL,
            "max_offset": self.protocol.MAX_OFFSET,
            # Argon2 parameters
            "memory_cost": self.controller.get_params()["MEMORY_COST"],
            "time_cost": self.controller.get_params()["TIME_COST"],
            "parallelism": self.controller.get_params()["PARALLELISM"],
            "hash_len": self.controller.get_params()["HASH_LEN"],
            "salt": self.protocol.per_instance_salt.hex(),
            # Merkle tree chain
            "merkle_root": self.merkle_tree.get_root(),
            "merkle_proof": [
                {"hash": h.hex(), "left": is_left} for h, is_left in proof
            ],
            "prev_merkle_root": (
                commits_data[-1].get("merkle_root", "") if commits_data else ""
            ),
            "merkle_index": idx,
            # Readable metadata
            "genesis_record": self.protocol.genesis_record,
            "creation_timestamp": int.from_bytes(self.protocol.seed[24:32], "big"),
        }

    @staticmethod
    def debug_merkle_tree_construction(commit_data: Dict):
        """
        Diagnostic function for Merkle tree debugging.
        Reconstructs tree from commits and compares with stored
        values to identify discrepancies.
        Args:
            commit_data: Stored commit data to debug
        """
        # loading all commits
        with open("commits.json", "r") as f:
            all_commits = json.load(f)

        target_index = commit_data.get("merkle_index", 0)
        print(f"\n=== MERKLE TREE DEBUG ===")
        print(f"Target artifact index: {target_index}")
        print(f"Total commits in file: {len(all_commits)}")
        # building tree same as in commit()
        leaf_strings = []
        for i, c in enumerate(
            all_commits[: target_index + 1]
        ):  # including target_index
            leaf_data = f"{c['seed_commit']}|{c['prime_hash']}|{c['config_hash']}|{c['genesis_hash']}|{c['combined_hash']}"
            leaf_strings.append(leaf_data)
            print(f"Leaf {i}: {leaf_data[:50]}...")
        # building tree
        merkle_tree = MerkleTree()
        merkle_tree.build_root(leaf_strings)
        computed_root = merkle_tree.get_root()
        stored_root = commit_data.get("merkle_root")
        print(f"Computed root: {computed_root}")
        print(f"Stored root: {stored_root}")
        print(f"Roots match: {computed_root == stored_root}")
        # check proof
        if target_index < len(leaf_strings):
            proof = merkle_tree.get_proof(target_index)
            stored_proof = commit_data.get("merkle_proof", [])
            print(f"Computed proof length: {len(proof)}")
            print(f"Stored proof length:   {len(stored_proof)}")
            if proof:
                print("Computed proof:")
                for i, (hash_bytes, is_left) in enumerate(proof):
                    print(f"  {i}: {hash_bytes.hex()} (left: {is_left})")
            if stored_proof:
                print("Stored proof:")
                for i, p in enumerate(stored_proof):
                    print(f"  {i}: {p['hash']} (left: {p['left']})")

    @staticmethod
    def deep_pow_diagnostic(session, commit_data):
        """
        Perform detailed proof-of-work diagnostic for debugging.
        Runs multiple validation tests to identify PoW discrepancies
        including manual verification, stored data comparison, and
        difficulty range testing.
        Args:
            session: TSPProtocolSession instance
            commit_data: Stored commit data dictionary
        Returns:
            bool: PoW validation result
        """
        seed = session.protocol.seed
        difficulty = session.protocol.POW_DIFFICULTY
        params = session.cfg.get_params()
        print(f"\nDEEP PoW DIAGNOSTIC:")
        print(f"Seed: {seed.hex()}")
        print(f"Difficulty: {difficulty}")
        print(f"TSP_POW constant: {params['TSP_POW']}")

        def manual_pow_check(seed_bytes, diff, debug_prefix=""):
            """Manual step-by-step PoW check"""
            print(f"{debug_prefix} Manual PoW check:")
            print(f"{debug_prefix} Input seed: {seed_bytes.hex()}")
            print(f"{debug_prefix} Input difficulty: {diff}")
            # Difficulty params
            lb = diff // 8
            rb = diff % 8
            mask = (0xFF << (8 - rb)) if rb else 0
            print(f"   {debug_prefix}  lb={lb}, rb={rb}, mask={mask:02x}")
            # Making pow_data
            tsp_pow = params["TSP_POW"]
            difficulty_bytes = diff.to_bytes(2, "big")
            pow_data = tsp_pow + seed_bytes + difficulty_bytes
            print(f"{debug_prefix}  TSP_POW: {tsp_pow}")
            print(f"{debug_prefix}  difficulty_bytes: {difficulty_bytes.hex()}")
            print(f"{debug_prefix}  pow_data: {pow_data.hex()}")
            # Triple SHA3-256
            h1 = hashlib.sha3_256(pow_data).digest()
            h2 = hashlib.sha3_256(h1).digest()
            result = hashlib.sha3_256(h2).digest()
            print(f"{debug_prefix}  hash1: {h1.hex()}")
            print(f"{debug_prefix}  hash2: {h2.hex()}")
            print(f"{debug_prefix}  final: {result.hex()}")
            # Check for leading zeros
            violation = 0
            print(f"{debug_prefix}  Checking leading zeros:")
            for i in range(lb):
                byte_val = result[i]
                violation |= byte_val
                print(
                    f"{debug_prefix}    byte[{i}]: {byte_val:02x} (violation: {violation})"
                )
            if rb > 0 and lb < len(result):
                byte_val = result[lb]
                masked = byte_val & mask
                violation |= masked
                print(
                    f"{debug_prefix}    byte[{lb}] & mask: {byte_val:02x} & {mask:02x} = {masked:02x} (violation: {violation})"
                )
            is_valid = violation == 0
            print(f"{debug_prefix} Final violation: {violation}")
            print(f"{debug_prefix} Result: {is_valid}")
            return is_valid

        # Comparative tests
        try:
            print(f"\nTEST 1: Session protocol _check_pow")
            session_result = session.protocol._check_pow(seed, difficulty)
            print(f"Session result: {session_result}")
            print(f"\nTEST 2: Manual implementation")
            manual_result = manual_pow_check(seed, difficulty, "MANUAL: ")
            print(f"\nTEST 3: Stored data comparison")
            stored_seed = bytes.fromhex(commit_data["seed"])
            stored_difficulty = commit_data["pow_difficulty"]
            print(f"Stored seed == protocol seed: {stored_seed == seed}")
            print(
                f"Stored difficulty == protocol difficulty: {stored_difficulty == difficulty}"
            )
            if stored_seed == seed and stored_difficulty == difficulty:
                print(f"✅ Stored data matches protocol data")
            else:
                print(f"❌ Stored data MISMATCH!")
                print(f"Stored seed: {stored_seed.hex()}")
                print(f"Protocol seed: {seed.hex()}")
            print(f"\nTEST 4: Manual check on stored data")
            manual_stored = manual_pow_check(stored_seed, stored_difficulty, "STORED: ")
            print(f"\nTEST 5: Testing different difficulties")
            for test_diff in [1, 2, 3, 4]:
                try:
                    test_session = session.protocol._check_pow(seed, test_diff)
                    test_manual = manual_pow_check(
                        seed, test_diff, f"DIFF{test_diff}: "
                    )
                    match = test_session == test_manual
                    print(
                        f"Difficulty {test_diff}: session={test_session}, manual={test_manual}, match={match}"
                    )
                except Exception as e:
                    print(f"Difficulty {test_diff}: ERROR = {e}")
            # Финальные результаты
            print(f"\nSUMMARY:")
            print(f"Session PoW result: {session_result}")
            print(f"Manual PoW result: {manual_result}")
            print(f"Results match: {session_result == manual_result}")
            print(
                f"Overall diagnosis: {'CONSISTENT' if session_result == manual_result else 'INCONSISTENT'}"
            )
            return session_result
        except Exception as e:
            print(f"   💥 DIAGNOSTIC ERROR: {e}")
            traceback.print_exc()
            return False

    def verify_pow(self) -> bool:
        """
        Verify proof-of-work for current protocol artifact.
        Returns:
            bool: True if PoW constraints satisfied
        """
        # Use protocol.seed instead provided_seed
        return self.protocol._check_pow(
            self.protocol.seed, self.protocol.POW_DIFFICULTY
        )


if __name__ == "__main__":
    pass