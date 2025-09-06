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

import argon2.low_level
import hashlib
import hmac
import time
import struct
import json

from typing import Optional, Dict, Any
from core.prime import Prime
from core.controller import Controller
from source.signature import SignatureHandler


class TSPProtocolSession:
    """
    Validator and reconstructor for existing TSP artifacts.
    Performs comprehensive verification of artifact integrity, including
    proof-of-work validation, signature verification, and parameter consistency
    checks against stored commit data.
    Key features:
    - Stateless artifact reconstruction from seed and signature
    - Multi-layer validation (PoW, signatures, genesis, config)
    - Tamper detection through parameter comparison
    - Session age validation for time-bound artifacts
    - Support for designated ownership verification
    Usage modes:
    - Verification: Validate existing artifacts without private key
    - Restoration: Reconstruct full artifact state from minimal data
    """

    def __init__(
        self,
        controller: Controller,
        signature_obj: SignatureHandler,
        signature_public_key_bytes: bytes,
        seed: bytes,
        signature: bytes,
        artifact_index: int = 0,
        max_age_seconds: Optional[int] = None,
        expected_combined_hash: Optional[bytes] = None,
        expected_genesis_hash: Optional[bytes] = None,
        expected_config_hash: Optional[bytes] = None,
        designated_owner_hash: Optional[bytes] = None,
        prime: Optional[int] = None,
        stored_commit_data: Optional[Dict] = None,  # NEW: stored data for validation
    ):
        """
        Initialize session for artifact verification/restoration.
        Args:
            controller: Configuration controller for model parameters
            signature_obj: Signature handler for verification
            signature_public_key_bytes: Creator's public key
            seed: Artifact seed bytes
            signature: Artifact signature
            artifact_index: Index of artifact in chain
            max_age_seconds: Maximum allowed session age
            expected_combined_hash: Expected combined hash for validation
            expected_genesis_hash: Expected genesis hash for validation
            expected_config_hash: Expected config hash for validation
            designated_owner_hash: Designated owner's public key hash
            prime: Prime number if already computed
            stored_commit_data: Stored commit data for validation
        Raises:
            ValueError: If validation fails at any stage
        """
        self.cfg = controller
        self.signature_obj = signature_obj
        self.PUBLIC_KEY_BYTES = signature_public_key_bytes
        self.provided_seed = seed
        self.provided_signature = signature
        self.provided_artifact_index = artifact_index
        self.provided_prime = prime
        self.stored_commit_data = stored_commit_data  # Store for later use
        print(f"TSPProtocolSession init:")
        print(f"stored_commit_data provided: {stored_commit_data is not None}")
        if stored_commit_data:
            print(f"stored_commit_data keys: {list(stored_commit_data.keys())[:5]}...")
        # Validate inputs
        self._validate_inputs(
            seed, signature, signature_public_key_bytes, max_age_seconds
        )
        # Process designated owner
        self.designated_owner_hash = self._resolve_designated_owner(
            seed, designated_owner_hash
        )
        # Reconstruct protocol state
        self.protocol = self._reconstruct_protocol_state()
        # Validate reconstructed state
        self._validate_reconstruction(
            expected_combined_hash,
            expected_genesis_hash,
            expected_config_hash,
            stored_commit_data,
        )

    def _validate_inputs(
        self,
        seed: bytes,
        signature: bytes,
        pubkey: bytes,
        max_age_seconds: Optional[int],
    ):
        """
        Validate all input parameters for correctness.
        Args:
            seed: Artifact seed to validate
            signature: Signature to validate
            pubkey: Public key to validate
            max_age_seconds: Session age limit
        Raises:
            ValueError: If any input validation fails
        """
        # Validate public key
        if not isinstance(pubkey, bytes) or len(pubkey) < 32 or len(pubkey) > 133:
            raise ValueError(f"Invalid public key length: {len(pubkey)}")
        # Validate seed
        if not isinstance(seed, bytes) or len(seed) < 32:
            raise ValueError(f"Invalid seed length: {len(seed)}")
        # Validate signature
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise ValueError(f"Invalid signature length: {len(signature)}")
        # Validate signature handler consistency
        try:
            handler_pubkey = self.signature_obj.get_public_bytes()
            if handler_pubkey != pubkey:
                raise ValueError("Public key mismatch with signature handler")
        except Exception as e:
            raise ValueError(f"Signature handler validation failed: {e}")
        # Validate session age
        if max_age_seconds is not None:
            self._validate_session_age(seed, max_age_seconds)

    def _resolve_designated_owner(
        self, seed: bytes, provided_owner_hash: Optional[bytes]
    ) -> Optional[bytes]:
        """
        Resolve designated owner from seed and provided hash.
        Extracts embedded owner from personalized seeds and validates
        consistency with provided owner hash.
        Args:
            seed: Artifact seed (may contain owner)
            provided_owner_hash: Explicitly provided owner hash
        Returns:
            Optional[bytes]: Resolved owner hash or None
        Raises:
            ValueError: If owner hashes conflict
        """
        extracted_owner = self._extract_designated_owner_from_seed(seed)
        if provided_owner_hash and extracted_owner:
            if provided_owner_hash != extracted_owner:
                raise ValueError("Designated owner hash mismatch with seed")
            return provided_owner_hash
        elif provided_owner_hash and not extracted_owner:
            raise ValueError(
                "Provided designated_owner_hash but seed is not personalized"
            )
        elif extracted_owner and not provided_owner_hash:
            return extracted_owner
        else:
            return None

    def _reconstruct_protocol_state(self) -> "ReconstructedProtocol":
        """
        Reconstruct protocol state from provided data.
        Creates ReconstructedProtocol instance with all parameters
        computed from seed without requiring proof-of-work.
        Returns:
            ReconstructedProtocol: Reconstructed protocol state
        """
        # Extract stored genesis data if available
        stored_genesis_sig = None
        stored_genesis_hash = None
        if self.stored_commit_data:
            stored_genesis_sig = bytes.fromhex(
                self.stored_commit_data["genesis_signature"]
            )
            stored_genesis_hash = bytes.fromhex(self.stored_commit_data["genesis_hash"])
        return ReconstructedProtocol(
            cfg=self.cfg,
            signature_obj=self.signature_obj,
            public_key_bytes=self.PUBLIC_KEY_BYTES,
            seed=self.provided_seed,
            signature=self.provided_signature,
            artifact_index=self.provided_artifact_index,
            designated_owner_hash=self.designated_owner_hash,
            prime=self.provided_prime,
            stored_genesis_signature=stored_genesis_sig,  # Pass stored data
            stored_genesis_hash=stored_genesis_hash,  # Pass stored data
        )

    def _validate_reconstruction(
        self,
        expected_combined_hash: Optional[bytes],
        expected_genesis_hash: Optional[bytes],
        expected_config_hash: Optional[bytes],
        stored_commit_data: Optional[Dict] = None,
    ):
        """
        Validate reconstructed protocol against expected values.
        Performs comprehensive validation including hash comparison,
        signature verification, and parameter consistency checks.
        Args:
            expected_combined_hash: Expected combined hash
            expected_genesis_hash: Expected genesis hash
            expected_config_hash: Expected config hash
            stored_commit_data: Stored data for parameter validation
        Raises:
            ValueError: If any validation check fails
        """
        # Validate combined hash
        if expected_combined_hash:
            computed = self.protocol.combined_hash
            if computed != expected_combined_hash:
                raise ValueError(
                    f"Combined hash mismatch: "
                    f"computed={computed.hex()}, expected={expected_combined_hash.hex()}"
                )
        # Validate genesis hash
        if expected_genesis_hash:
            computed = self.protocol.GENESIS_COMMIT_HASH
            if computed != expected_genesis_hash:
                raise ValueError(
                    f"Genesis hash mismatch: "
                    f"computed={computed.hex()}, expected={expected_genesis_hash.hex()}"
                )
        # Validate config hash
        if expected_config_hash:
            computed = self.protocol.config_hash()
            if computed != expected_config_hash:
                raise ValueError(
                    f"Config hash mismatch: "
                    f"computed={computed.hex()}, expected={expected_config_hash.hex()}"
                )
        # Validate critical parameters and signatures
        if stored_commit_data:
            print("Validating critical parameters against stored data...")
            self._validate_critical_parameters(stored_commit_data)
            self._validate_commit_signature(stored_commit_data)
            self._validate_genesis_signature(stored_commit_data)
        else:
            print("No stored commit data provided - skipping parameter validation")
        # Validate signature
        if not self.signature_obj.verify(
            self.protocol.combined_hash, self.provided_signature
        ):
            raise ValueError("Signature verification failed - data was tampered with")

    def _validate_critical_parameters(self, stored_data: Dict):
        """
        Validate reconstructed parameters match stored values.
        Detects tampering by comparing all critical protocol parameters
        against stored commit data.
        Args:
            stored_data: Stored commit data with parameters
        Raises:
            ValueError: If parameter mismatch detected (tampering)
        """
        print("🔍 CRITICAL PARAMETERS VALIDATION:")
        errors = []
        # Check critical protocol parameters
        critical_checks = [
            (
                "pow_difficulty",
                self.protocol.POW_DIFFICULTY,
                stored_data.get("pow_difficulty"),
            ),
            (
                "rarity_threshold",
                self.protocol.RARITY_THRESHOLD,
                stored_data.get("rarity_threshold"),
            ),
            ("prime_bits", self.protocol.PRIME_BITS, stored_data.get("prime_bits")),
            ("prime_nonce", self.protocol.PRIME_NONCE, stored_data.get("prime_nonce")),
            ("total_bytes", self.protocol.TOTAL_BYTES, stored_data.get("total_bytes")),
            (
                "target_bytes",
                self.protocol.TARGET_BYTES,
                stored_data.get("target_bytes"),
            ),
            (
                "target_bytes_end",
                self.protocol.TARGET_BYTES_END,
                stored_data.get("target_bytes_end"),
            ),
            (
                "target_interval",
                self.protocol.TARGET_INTERVAL,
                stored_data.get("target_interval"),
            ),
            ("max_offset", self.protocol.MAX_OFFSET, stored_data.get("max_offset")),
        ]
        for param_name, computed_value, stored_value in critical_checks:
            print(
                f"{param_name}: computed={computed_value}, stored={stored_value}, match={computed_value == stored_value}"
            )
            if stored_value is not None and computed_value != stored_value:
                errors.append(
                    f"{param_name}: computed={computed_value}, stored={stored_value}"
                )
        # Check prime if provided
        if stored_data.get("prime") and self.provided_prime:
            stored_prime = int(stored_data["prime"])
            print(
                f"prime: computed={self.provided_prime}, stored={stored_prime}, match={self.provided_prime == stored_prime}"
            )
            if self.provided_prime != stored_prime:
                errors.append(
                    f"prime: computed={self.provided_prime}, stored={stored_prime}"
                )
        # Check salt
        if stored_data.get("salt"):
            stored_salt = bytes.fromhex(stored_data["salt"])
            computed_salt = self.protocol.per_instance_salt
            print(
                f"   salt: computed={computed_salt.hex()}, stored={stored_data['salt']}, match={computed_salt == stored_salt}"
            )
            if computed_salt != stored_salt:
                errors.append(
                    f"salt: computed={computed_salt.hex()}, stored={stored_data['salt']}"
                )
        # Check Argon2 parameters
        params = self.cfg.get_params()
        argon2_checks = [
            ("memory_cost", params["MEMORY_COST"], stored_data.get("memory_cost")),
            ("time_cost", params["TIME_COST"], stored_data.get("time_cost")),
            ("parallelism", params["PARALLELISM"], stored_data.get("parallelism")),
            ("hash_len", params["HASH_LEN"], stored_data.get("hash_len")),
        ]
        for param_name, computed_value, stored_value in argon2_checks:
            print(
                f"   {param_name}: computed={computed_value}, stored={stored_value}, match={computed_value == stored_value}"
            )
            if stored_value is not None and computed_value != stored_value:
                errors.append(
                    f"{param_name}: computed={computed_value}, stored={stored_value}"
                )
        print(f"Total errors found: {len(errors)}")
        if errors:
            raise ValueError(
                f"CRITICAL PARAMETER MISMATCH - DATA TAMPERING DETECTED: {'; '.join(errors)}"
            )

    def _validate_commit_signature(self, stored_data: Dict):
        """
        Validate commit signature against stored data.
        Verifies integrity of commit data structure.
        Args:
            stored_data: Stored commit data with signature
        Raises:
            ValueError: If commit signature invalid
        """
        print("COMMIT SIGNATURE VALIDATION:")
        stored_commit_sig = stored_data.get("commit_signature")
        if not stored_commit_sig:
            print("No commit signature to validate")
            return
        # Recreate commit data without signature for verification
        commit_data_copy = stored_data.copy()
        del commit_data_copy["commit_signature"]
        # Serialize the same way as in commit()
        commit_data_str = json.dumps(
            commit_data_copy, sort_keys=True, separators=(",", ":")
        )
        # Verify signature
        try:
            expected_sig = bytes.fromhex(stored_commit_sig)
            if not self.signature_obj.verify(commit_data_str.encode(), expected_sig):
                raise ValueError(
                    "COMMIT SIGNATURE VERIFICATION FAILED - commit data was tampered!"
                )
            print("Commit signature valid")
        except Exception as e:
            raise ValueError(f"COMMIT SIGNATURE VALIDATION ERROR: {e}")

    def _validate_genesis_signature(self, stored_data: Dict):
        """
        Validate genesis signature matches computed genesis.
        Ensures genesis commitment hasn't been tampered with.
        Args:
            stored_data: Stored data with genesis signature
        Raises:
            ValueError: If genesis signature mismatch
        """
        print("GENESIS SIGNATURE VALIDATION:")
        stored_genesis_sig = stored_data.get("genesis_signature")
        if not stored_genesis_sig:
            print("No genesis signature to validate")
            return
        computed_genesis_sig = self.protocol.GENESIS_SIGNATURE
        if not computed_genesis_sig:
            raise ValueError("GENESIS SIGNATURE NOT COMPUTED")
        stored_sig_bytes = bytes.fromhex(stored_genesis_sig)
        print(f"Stored: {stored_genesis_sig}")
        print(f"Computed: {computed_genesis_sig.hex()}")
        print(f"Match: {computed_genesis_sig == stored_sig_bytes}")
        if computed_genesis_sig != stored_sig_bytes:
            raise ValueError("GENESIS SIGNATURE MISMATCH - genesis data was tampered!")
        print("Genesis signature valid")

    @staticmethod
    def _extract_designated_owner_from_seed(seed: bytes) -> Optional[bytes]:
        """
        Extract designated owner hash from personalized seed.
        Args:
            seed: Seed bytes (may contain owner in last 32 bytes)
        Returns:
            Optional[bytes]: Owner hash if seed is personalized
        """
        if len(seed) > 32:
            # Personalized seed: last 32 bytes = owner hash
            return seed[-32:]
        return None

    @staticmethod
    def _validate_session_age(seed: bytes, max_age_seconds: int):
        """
        Validate session age from timestamp embedded in seed.
        Args:
            seed: Seed containing timestamp
            max_age_seconds: Maximum allowed age
        Raises:
            ValueError: If session expired or timestamp invalid
        """
        session_timestamp = int.from_bytes(seed[24:32], "big")
        current_timestamp = int(time.time())
        # Sanity checks
        if session_timestamp < 1577836800:  # Before 2020
            raise ValueError("Session timestamp too old")
        if session_timestamp > current_timestamp + 3600:  # 1 hour future
            raise ValueError("Session timestamp too far in future")
        session_age = current_timestamp - session_timestamp
        if session_age > max_age_seconds:
            raise ValueError(f"Session expired: {session_age}s > {max_age_seconds}s")
        if session_age < -300:  # Allow 5-min clock skew
            raise ValueError("Session from future")

    # Delegation methods for easy access
    @property
    def seed(self) -> bytes:
        return self.protocol.seed

    @property
    def combined_hash(self) -> bytes:
        return self.protocol.combined_hash

    @property
    def ARTIFACT_INDEX(self) -> int:
        return self.protocol.ARTIFACT_INDEX

    @property
    def PRIME(self) -> Optional[int]:
        return self.protocol.PRIME

    @property
    def POW_DIFFICULTY(self) -> int:
        return self.protocol.POW_DIFFICULTY

    @property
    def RARITY_THRESHOLD(self) -> float:
        return self.protocol.RARITY_THRESHOLD

    def config_hash(self) -> bytes:
        return self.protocol.config_hash()

    def config_hash_hex(self) -> str:
        return self.protocol.config_hash_hex()

    def verify_pow(self) -> bool:
        """
        Verify proof-of-work for the artifact.
        Returns:
            bool: True if PoW valid
        """
        return self.protocol._check_pow(
            self.provided_seed,
            self.protocol.POW_DIFFICULTY,
        )

    def verify_ownership(self, claimed_owner_pubkey: bytes) -> bool:
        """
        Verify ownership of personalized artifact.
        Args:
            claimed_owner_pubkey: Public key claiming ownership
        Returns:
            bool: True if ownership verified
        """
        return self.protocol.verify_designated_ownership(claimed_owner_pubkey)

    def verify_config(self, expected_hash: bytes) -> bool:
        """
        Verify config hash against expected value.
        Args:
            expected_hash: Expected config hash (bytes or hex string)
        Returns:
            bool: True if config hash matches
        """
        if isinstance(expected_hash, str):
            expected_hash = bytes.fromhex(expected_hash)
        return hmac.compare_digest(self.config_hash(), expected_hash)

    def verify_all(
        self, expected_config_hash: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive verification of artifact.
        Validates all aspects: PoW, signatures, genesis, config, prime.
        Args:
            expected_config_hash: Optional expected config hash
        Returns:
            Dict[str, Any]: Verification results with 'all_valid' summary
        """
        results = {}
        # PoW verification
        try:
            # uses protocol seed и protocol difficulty
            results["pow_valid"] = self.protocol._check_pow(
                self.protocol.seed,  # Protocol seed (не provided_seed!)
                self.protocol.POW_DIFFICULTY,  # Protocol difficulty
            )
        except Exception as e:
            results["pow_valid"] = False
            results["pow_error"] = str(e)
        # Signature verification
        try:
            results["signature_valid"] = self.signature_obj.verify(
                self.combined_hash, self.provided_signature
            )
        except Exception as e:
            results["signature_valid"] = False
            results["signature_error"] = str(e)
        # Genesis verification
        try:
            results["genesis_valid"] = self.protocol.GENESIS_COMMIT_HASH is not None
        except Exception as e:
            results["genesis_valid"] = False
            results["genesis_error"] = str(e)
        # Config hash verification
        try:
            if expected_config_hash:
                results["config_hash_valid"] = self.verify_config(expected_config_hash)
            else:
                self.config_hash()
                results["config_hash_valid"] = True
        except Exception as e:
            results["config_hash_valid"] = False
            results["config_hash_error"] = str(e)
        # Prime verification
        if self.provided_prime is not None:
            try:
                results["prime_valid"] = self._verify_prime()
            except Exception as e:
                results["prime_valid"] = False
                results["prime_error"] = str(e)
        else:
            results["prime_valid"] = True
        # Overall validity
        required_checks = [
            "pow_valid",
            "signature_valid",
            "genesis_valid",
            "config_hash_valid",
            "prime_valid",
        ]
        results["all_valid"] = all(
            results.get(check, False) for check in required_checks
        )
        return results

    def _verify_prime(self) -> bool:
        """
        Verify provided prime number satisfies PoW constraints.
        Returns:
            bool: True if prime valid or not provided
        """
        if self.provided_prime is None:
            return True
        # Create Prime verifier (assuming it exists)
        prime_verifier = Prime(self.protocol, self.PUBLIC_KEY_BYTES)
        return prime_verifier.is_prime(self.provided_prime)

    def get_session_timestamp(self) -> int:
        """
        Extract session creation timestamp from seed.
        Returns:
            int: Unix timestamp
        """
        return int.from_bytes(self.provided_seed[24:32], "big")

    def get_session_age(self) -> int:
        """
        Calculate current session age in seconds.
        Returns:
            int: Age in seconds since creation
        """
        return int(time.time()) - self.get_session_timestamp()

    def get_artifact_info(self) -> Dict[str, Any]:
        """
        Get comprehensive artifact information.
        Returns:
            Dict[str, Any]: All artifact parameters and metadata
        """
        return {
            "seed": self.seed.hex(),
            "artifact_index": self.ARTIFACT_INDEX,
            "combined_hash": self.combined_hash.hex(),
            "config_hash": self.config_hash_hex(),
            "pow_difficulty": self.POW_DIFFICULTY,
            "rarity_threshold": self.RARITY_THRESHOLD,
            "prime": self.PRIME,
            "session_timestamp": self.get_session_timestamp(),
            "session_age": self.get_session_age(),
            "designated_owner": (
                self.designated_owner_hash.hex() if self.designated_owner_hash else None
            ),
            "genesis_hash": (
                self.protocol.GENESIS_COMMIT_HASH.hex()
                if self.protocol.GENESIS_COMMIT_HASH
                else None
            ),
        }


class ReconstructedProtocol:
    """
    Reconstructs TSPProtocol state from provided data without PoW generation.
    Composition helper that mimics TSPProtocol interface for verification
    purposes. Computes all parameters deterministically from seed.
    """

    def __init__(
        self,
        cfg: Controller,
        signature_obj: SignatureHandler,
        public_key_bytes: bytes,
        seed: bytes,
        signature: bytes,
        artifact_index: int,
        designated_owner_hash: Optional[bytes] = None,
        prime: Optional[int] = None,
        stored_genesis_signature: Optional[bytes] = None,  # NEW
        stored_genesis_hash: Optional[bytes] = None,  # NEW
    ):
        """
        Initialize reconstructed protocol state.
        Args:
            cfg: Configuration controller
            signature_obj: Signature handler
            public_key_bytes: Creator's public key
            seed: Artifact seed
            signature: Artifact signature
            artifact_index: Position in chain
            designated_owner_hash: Optional owner restriction
            prime: Pre-computed prime if available
            stored_genesis_signature: Genesis signature from storage
            stored_genesis_hash: Genesis hash from storage
        """
        self.cfg = cfg
        self.signature_obj = signature_obj
        self.PUBLIC_KEY_BYTES = public_key_bytes
        self._seed = seed
        self.SIGNATURE = signature
        self.ARTIFACT_INDEX = artifact_index
        self.DESIGNATED_OWNER_HASH = designated_owner_hash
        self.PRIME = prime
        # Store genesis data from commits.json
        self.stored_genesis_signature = stored_genesis_signature
        self.stored_genesis_hash = stored_genesis_hash
        # Compute derived fields
        self.h_pk = hashlib.sha3_256(self.PUBLIC_KEY_BYTES).digest()
        self.BITS_COMPARE = self.h_pk[:1]
        self.BITS_COMPARE_END = self.h_pk[-1:]
        # Extract timestamp and set ownership flags
        self._creation_timestamp = int.from_bytes(seed[24:32], "big")
        self.OWNERSHIP_FLAGS = 0b0000
        self.RESERVED_FLAGS = 0b0010
        if self.DESIGNATED_OWNER_HASH:
            self.OWNERSHIP_FLAGS |= self.RESERVED_FLAGS
        # Compute all protocol parameters
        self._compute_all_parameters()
        # Create genesis commitment
        self._create_genesis_commitment()

    @property
    def seed(self) -> bytes:
        return self._seed

    @property
    def combined_hash(self) -> bytes:
        return self._combined_hash

    def _compute_all_parameters(self):
        """
        Compute all protocol parameters from seed.
        Deterministically derives all cryptographic parameters
        matching original generation process.
        """
        params = self.cfg.get_params()
        base_difficulty = params["BASE_POW_DIFFICULTY"]
        # Use TSPProtocol's compute logic
        computed_fields = self._compute_params(self._seed, base_difficulty)
        # Apply computed fields
        for key, value in computed_fields.items():
            if key == "_seed":
                continue
            setattr(self, key, value)
        # Add missing attributes that TSPProtocol has
        self.TARGET_INTERVAL_BASE = 30
        self.TARGET_INTERVAL_RANGE = 90

    def _compute_params(self, seed: bytes, base_difficulty: int) -> dict:
        """
        Reuse TSPProtocol's parameter computation logic.
        Ensures consistency between generation and reconstruction.
        Args:
            seed: Artifact seed
            base_difficulty: Base PoW difficulty
        Returns:
            dict: All computed parameters
        """
        params = self.cfg.get_params()
        # 1) Compute PRIME_NONCE
        combined0 = params["TSP_NONCE"] + seed + self.ARTIFACT_INDEX.to_bytes(8, "big")
        nonce_hash = hashlib.sha3_256(combined0).digest()
        prime_nonce = int.from_bytes(nonce_hash[:16], "big")
        # 2) Derive salt and compute Argon2
        salt = self._derive_salt_static(seed, self.PUBLIC_KEY_BYTES)
        raw_argon = argon2.low_level.hash_secret_raw(
            secret=seed,
            salt=salt,
            time_cost=params["TIME_COST"],
            memory_cost=params["MEMORY_COST"],
            parallelism=params["PARALLELISM"],
            hash_len=params["HASH_LEN"],
            type=argon2.low_level.Type.ID,
            version=argon2.low_level.ARGON2_VERSION,
        )
        h_digest = hashlib.sha3_256(raw_argon).digest()
        # 3) Temporary hash for parameter derivation
        temp_combined = (
            prime_nonce.to_bytes(16, "big")
            + h_digest
            + base_difficulty.to_bytes(2, "big")
        )
        temp_hash = hashlib.sha3_256(temp_combined).digest()
        # 4) Calculate parameters
        max_offset = (
            int.from_bytes(h_digest[20:24], "big") % params["MAX_OFFSET_MODULUS"]
        ) + params["MAX_OFFSET_MIN"]
        sel_offset = int.from_bytes(temp_hash[4:8], "big") % params["MAX_POW_OFFSET"]
        base_pow = params["BASE_POW_DIFFICULTY"] + sel_offset
        # 5) Rarity selection
        total_weight = sum(params["RARITY_WEIGHTS"].values())
        w_raw = int.from_bytes(h_digest[:4], "big") % params["WEIGHT_DIVIDER"]
        w_val = w_raw / params["WEIGHT_DIVIDER"] * total_weight
        cum = 0
        chosen_thr = max(params["RARITY_WEIGHTS"])
        for thr, wt in sorted(params["RARITY_WEIGHTS"].items()):
            cum += wt
            if w_val <= cum:
                chosen_thr = thr
                break
        copy_params = params["RARITY_PARAMS"][chosen_thr]
        prime_bits = copy_params["prime_bits"]
        pow_difficulty = max(
            params["MIN_DIFFICULTY"],
            min(base_pow + copy_params["pow_extra"], params["MAX_DIFFICULTY"]),
        )
        # 6) Final combined hash
        final_combined = (
            prime_nonce.to_bytes(16, "big")
            + h_digest
            + pow_difficulty.to_bytes(2, "big")
        )
        combined_hash = hashlib.sha3_256(
            params["TSP_COMBINED"] + final_combined
        ).digest()
        # 7) Target parameters
        total_bytes = copy_params["total_bytes"]
        target_bytes = max(1, round(total_bytes / 4))
        target_bytes_end = max(0, total_bytes - target_bytes)
        interval_nonce = int.from_bytes(h_digest[16:20], "big")
        target_interval = 30 + (interval_nonce % 90)  # Same as TSPProtocol
        return {
            "_seed": seed,
            "per_instance_salt": salt,
            "PRIME_NONCE": prime_nonce,
            "POW_DIFFICULTY": pow_difficulty,
            "_combined_hash": combined_hash,
            "MAX_OFFSET": max_offset,
            "RARITY_THRESHOLD": chosen_thr,
            "PRIME_BITS": prime_bits,
            "TOTAL_BYTES": total_bytes,
            "TARGET_BYTES": target_bytes,
            "TARGET_BYTES_END": target_bytes_end,
            "TARGET_INTERVAL": target_interval,
        }

    @staticmethod
    def _derive_salt_static(seed: bytes, public_key: bytes) -> bytes:
        ds = hashlib.sha3_256(seed + public_key).digest()
        return hashlib.shake_128(seed + ds).digest(16)

    def _create_genesis_commitment(self):
        """
        Create or restore genesis commitment.
        Uses stored genesis data if available, otherwise recreates
        (requires private key for signing).
        """
        # Uses stored genesis data if available
        if self.stored_genesis_signature and self.stored_genesis_hash:
            print("Using stored genesis data from commits.json")
            self.GENESIS_SIGNATURE = self.stored_genesis_signature
            self.GENESIS_COMMIT_HASH = self.stored_genesis_hash
            # create genesis_record to show
            genesis_record = self._binary_genesis_record(
                self.PUBLIC_KEY_BYTES,
                self._creation_timestamp,
                self.ARTIFACT_INDEX,
                self.DESIGNATED_OWNER_HASH,
            )
            self.genesis_record = self._format_genesis_for_display(genesis_record)
            return

        # Recreating genesis commitment (requires private key)
        print("Recreating genesis commitment (requires private key)")
        genesis_record = self._binary_genesis_record(
            self.PUBLIC_KEY_BYTES,
            self._creation_timestamp,
            self.ARTIFACT_INDEX,
            self.DESIGNATED_OWNER_HASH,
        )
        self.genesis_record = self._format_genesis_for_display(genesis_record)
        genesis_data = self.cfg.get_params()["TSP_GENESIS"] + genesis_record
        self.GENESIS_SIGNATURE = self.signature_obj.sign(
            genesis_data
        )  # May fail in verify-only mode
        self.GENESIS_COMMIT_HASH = hashlib.sha3_256(genesis_data).digest()

    def _binary_genesis_record(
        self,
        creator_pubkey: bytes,
        timestamp: int,
        index: int,
        owner_hash: Optional[bytes] = None,
    ) -> bytes:
        """
        Create binary genesis record with length prefixes.
        Args:
            creator_pubkey: Creator's public key
            timestamp: Creation timestamp
            index: Artifact index
            owner_hash: Optional owner restriction
        Returns:
            bytes: Binary genesis record
        """
        record = len(creator_pubkey).to_bytes(2, "big") + creator_pubkey
        record += timestamp.to_bytes(8, "big")
        record += index.to_bytes(8, "big")
        if owner_hash:
            record += b"\x01" + owner_hash
        else:
            record += b"\x00"
        return record

    @staticmethod
    def _format_genesis_for_display(binary_record: bytes) -> str:
        """
        Format genesis record for human-readable display.
        Args:
            binary_record: Binary genesis data
        Returns:
            str: Formatted display string
        """
        if len(binary_record) < 18:
            return "Invalid genesis record"
        try:
            offset = 0
            # Parse creator pubkey
            pubkey_len = int.from_bytes(binary_record[offset : offset + 2], "big")
            offset += 2
            creator_hex = binary_record[offset : offset + pubkey_len].hex()
            offset += pubkey_len
            # Parse timestamp and index
            timestamp = int.from_bytes(binary_record[offset : offset + 8], "big")
            offset += 8
            index = int.from_bytes(binary_record[offset : offset + 8], "big")
            offset += 8
            result = f"Genesis|creator={creator_hex[:16]}...|timestamp={timestamp}|index={index}"
            # Parse owner if present
            if offset < len(binary_record):
                has_owner = binary_record[offset] == 1
                if has_owner and len(binary_record) >= offset + 33:
                    owner_hex = binary_record[offset + 1 : offset + 33].hex()
                    result += f"|owner={owner_hex[:16]}..."
            return result
        except Exception:
            return "Invalid genesis record format"

    def verify_designated_ownership(self, claimed_owner_pubkey: bytes) -> bool:
        """
        Verify artifact ownership for designated owner.
        Args:
            claimed_owner_pubkey: Public key claiming ownership
        Returns:
            bool: True if ownership verified
        """
        if not self.DESIGNATED_OWNER_HASH:
            return True
        claimed_hash = hashlib.sha3_256(claimed_owner_pubkey).digest()
        return hmac.compare_digest(claimed_hash, self.DESIGNATED_OWNER_HASH)

    def _check_pow(self, seed: bytes, difficulty: int) -> bool:
        """
        Check proof-of-work with triple SHA3-256.
        Args:
            seed: Seed to verify
            difficulty: Target difficulty
        Returns:
            bool: True if PoW satisfied
        Raises:
            ValueError: If difficulty out of range
        """
        params = self.cfg.get_params()
        mn, mx = params["MIN_DIFFICULTY"], params["MAX_DIFFICULTY"]
        if not (mn <= difficulty <= mx):
            raise ValueError(f"Difficulty {difficulty} out of range [{mn}, {mx}]")
        lb = difficulty // 8
        rb = difficulty % 8
        mask = (0xFF << (8 - rb)) if rb else 0
        pow_data = params["TSP_POW"] + seed + difficulty.to_bytes(2, "big")
        h = hashlib.sha3_256(pow_data).digest()
        h = hashlib.sha3_256(h).digest()
        res = hashlib.sha3_256(h).digest()
        # Check leading zero bytes/bits
        violation = 0
        for i in range(lb):
            violation |= res[i]
        if rb > 0:
            violation |= res[lb] & mask
        return violation == 0

    def config_hash(self) -> bytes:
        """
        Compute configuration hash matching TSPProtocol.
        Returns:
            bytes: SHA3-256 config hash
        """
        h = hashlib.sha3_256()
        h.update(self.cfg.get_params()["TSP_CONFIG"])
        for _, value in self._get_hash_materials():
            h.update(value)
        return h.digest()

    def config_hash_hex(self) -> str:
        return self.config_hash().hex()

    def _get_hash_materials(self):
        """
        Get ordered hash materials for config computation.
        Must match TSPProtocol exactly for verification.
        Returns:
            List[Tuple[str, bytes]]: Ordered parameter pairs
        Raises:
            ValueError: If required parameters missing
        """
        params = self.cfg.get_params()
        # Check salt length
        expected_salt = params["SALT_LENGTH"]
        if (
            self.per_instance_salt is None
            or len(self.per_instance_salt) != expected_salt
        ):
            raise ValueError(
                f"Invalid instance salt length: expected {expected_salt}, got "
                f"{len(self.per_instance_salt) if self.per_instance_salt else 0}"
            )

        materials = []
        # 1) Domain separation constants (must match TSPProtocol order)
        materials.append(("domain_tspcombined", params["TSP_COMBINED"]))
        materials.append(("domain_tspconfig", params["TSP_CONFIG"]))
        materials.append(("domain_tspprime1", params["TSP_PRIME1"]))
        materials.append(("domain_tspprime2", params["TSP_PRIME2"]))
        materials.append(("domain_tsprng", params["TSP_RNG"]))
        materials.append(("domain_tspnor", params["TSP_NOR"]))
        materials.append(("domain_tspnonce", params["TSP_NONCE"]))
        materials.append(("domain_tsppow", params["TSP_POW"]))
        materials.append(("domain_tspgenesis", params["TSP_GENESIS"]))
        # 2) Algorithm version
        materials.append(("algo_version", self._ensure_bytes(params["ALGO_VERSION"])))
        # 3) Artifact index
        materials.append(("artifact_index", self.ARTIFACT_INDEX.to_bytes(8, "big")))
        # 4) Public key and salt
        materials.append(("public_key", self._ensure_bytes(self.PUBLIC_KEY_BYTES, 32)))
        materials.append(
            ("instance_salt", self._ensure_bytes(self.per_instance_salt, expected_salt))
        )
        # 5) Genesis commitment
        if self.GENESIS_COMMIT_HASH is None:
            raise ValueError("Genesis commitment not initialized")
        materials.append(("genesis_commit_hash", self.GENESIS_COMMIT_HASH))
        if self.GENESIS_SIGNATURE is None:
            raise ValueError("Genesis signature not initialized")
        materials.append(("genesis_signature", self.GENESIS_SIGNATURE))
        # 6) Designated owner (if present)
        if self.DESIGNATED_OWNER_HASH:
            materials.append(("designated_owner_hash", self.DESIGNATED_OWNER_HASH))
        materials.append(("ownership_flags", self.OWNERSHIP_FLAGS.to_bytes(1, "big")))
        # 7) PoW parameters
        materials.append(
            ("max_pow_offset", params["MAX_POW_OFFSET"].to_bytes(2, "big"))
        )
        materials.append(
            ("base_pow_difficulty", params["BASE_POW_DIFFICULTY"].to_bytes(2, "big"))
        )
        if self.POW_DIFFICULTY is None:
            raise ValueError("POW_DIFFICULTY not initialized")
        materials.append(("pow_difficulty", self.POW_DIFFICULTY.to_bytes(2, "big")))
        materials.append(
            ("min_difficulty", params["MIN_DIFFICULTY"].to_bytes(1, "big"))
        )
        materials.append(
            ("max_difficulty", params["MAX_DIFFICULTY"].to_bytes(2, "big"))
        )
        # 8) Offset/roll parameters
        materials.append(("hash_len", params["HASH_LEN"].to_bytes(2, "big")))
        materials.append(
            ("max_offset_modulus", params["MAX_OFFSET_MODULUS"].to_bytes(2, "big"))
        )
        materials.append(
            ("max_offset_min", params["MAX_OFFSET_MIN"].to_bytes(2, "big"))
        )
        materials.append(
            ("weight_divider", params["WEIGHT_DIVIDER"].to_bytes(4, "big"))
        )
        # 9) Rarity: binary serialization (must match TSPProtocol exactly)
        rp_bytes = b""
        for thr, rp in sorted(params["RARITY_PARAMS"].items()):
            rp_bytes += struct.pack(">d", thr)  # float64 big-endian
            rp_bytes += rp["prime_bits"].to_bytes(4, "big")
            rp_bytes += rp["pow_extra"].to_bytes(2, "big")
            rp_bytes += rp["total_bytes"].to_bytes(1, "big")
        materials.append(("rarity_params", rp_bytes))
        rw_bytes = b""
        for thr, w in sorted(params["RARITY_WEIGHTS"].items()):
            rw_bytes += struct.pack(">d", thr)  # float64 big-endian
            rw_bytes += w.to_bytes(4, "big")  # uint32
        materials.append(("rarity_weights", rw_bytes))
        if self.RARITY_THRESHOLD is None:
            raise ValueError("RARITY_THRESHOLD not initialized")
        rt_int = int(self.RARITY_THRESHOLD * 1000)
        materials.append(("rarity_threshold", struct.pack(">H", rt_int)))  # uint16 BE
        # 10) Hash PoW data
        if self._combined_hash is None:
            raise ValueError("combined_hash not initialized")
        materials.append(("combined_hash", self._combined_hash))
        materials.append(("bits_compare", self.BITS_COMPARE))
        materials.append(("bits_compare_end", self.BITS_COMPARE_END))
        # 11) Prime data
        if self.PRIME_BITS is None or self.PRIME_NONCE is None:
            raise ValueError("PRIME_BITS or PRIME_NONCE not initialized")
        materials.append(("prime_bits", self.PRIME_BITS.to_bytes(4, "big")))
        materials.append(
            (
                "prime_nonce",
                self.PRIME_NONCE.to_bytes(
                    max(1, (self.PRIME_NONCE.bit_length() + 7) // 8), "big"
                ),
            )
        )
        if self.PRIME is not None:
            materials.append(
                (
                    "prime",
                    self.PRIME.to_bytes(
                        max(1, (self.PRIME.bit_length() + 7) // 8), "big"
                    ),
                )
            )
        else:
            materials.append(("prime", b""))
        # 12) Target parameters
        if (
            self.TARGET_BYTES is None
            or self.TARGET_BYTES_END is None
            or self.TARGET_INTERVAL is None
        ):
            raise ValueError(
                "TARGET_BYTES, TARGET_BYTES_END or TARGET_INTERVAL not initialized"
            )
        materials.append(("target_bytes", self.TARGET_BYTES.to_bytes(2, "big")))
        materials.append(("target_bytes_end", self.TARGET_BYTES_END.to_bytes(2, "big")))
        materials.append(("target_interval", self.TARGET_INTERVAL.to_bytes(4, "big")))
        # 13) Argon2 system parameters
        materials.append(("memory_cost", params["MEMORY_COST"].to_bytes(4, "big")))
        materials.append(("time_cost", params["TIME_COST"].to_bytes(2, "big")))
        materials.append(("parallelism", params["PARALLELISM"].to_bytes(1, "big")))
        # 14) Seed
        materials.append(("seed", self._seed))
        materials.append(("creation_time", self._seed[24:32]))
        # 15) Signature from combined_hash
        if self.SIGNATURE is None:
            raise ValueError("Signature not initialized")
        materials.append(("signature", self.SIGNATURE))
        return materials

    @staticmethod
    def _ensure_bytes(data, expected_len: int = None) -> bytes:
        """
        Convert data to bytes with optional length validation.
        Args:
            data: Input data (bytes or string)
            expected_len: Expected byte length
        Returns:
            bytes: Validated byte data
        Raises:
            TypeError: If data type invalid
            ValueError: If length mismatch
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif not isinstance(data, bytes):
            raise TypeError(f"Expected bytes or str, got {type(data)}")

        if expected_len and len(data) != expected_len:
            raise ValueError(f"Expected {expected_len} bytes, got {len(data)}")
        return data


if __name__ == "__main__":
    pass
