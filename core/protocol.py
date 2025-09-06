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
import time
import struct

from core.controller import Controller
from secrets import token_bytes
from source.signature import SignatureHandler
from typing import List, Tuple


class TSPProtocol:
    """
    Core protocol implementation for Genesis artifact generation.
    Handles proof-of-work seed generation, cryptographic parameter computation,
    and genesis commitment creation. Transfer logic separated to TSPTransfer class.
    Key features:
    - Dual-stage proof-of-work validation (base + adjusted difficulty)
    - Deterministic parameter derivation from seed
    - Designated ownership support with cryptographic binding
    - Genesis commitment with tamper-proof signatures
    - Stateless verification capability
    Protocol flow:
    1. Generate seed via proof-of-work
    2. Compute cryptographic parameters
    3. Create genesis commitment
    4. Sign combined hash
    5. Ready for prime generation
    """

    def __init__(
        self,
        controller: Controller,
        signature_obj: SignatureHandler,
        signature_public_key_bytes: bytes,
        designated_owner_pubkey_hash: bytes = None,
    ):
        """
        Initialize protocol with cryptographic components.
        Args:
            controller: Configuration controller for model parameters
            signature_obj: Signature handler for signing operations
            signature_public_key_bytes: Creator's public key bytes
            designated_owner_pubkey_hash: Optional SHA3-256 hash of designated owner's public key
        Raises:
            ValueError: If designated_owner_pubkey_hash is not 32 bytes
        """
        if designated_owner_pubkey_hash and len(designated_owner_pubkey_hash) != 32:
            raise ValueError(
                "designated_owner_pubkey_hash must be 32 bytes (SHA3-256 hash)"
            )
        self.cfg = controller
        self.signature_obj = signature_obj
        self.PUBLIC_KEY_BYTES = signature_public_key_bytes
        self.h_pk = hashlib.sha3_256(self.PUBLIC_KEY_BYTES).digest()
        self.BITS_COMPARE = self.h_pk[:1]
        self.BITS_COMPARE_END = self.h_pk[-1:]
        self.ARTIFACT_INDEX = 0
        self._seed = None
        self.GENESIS_SIGNATURE = None
        self.genesis_record = None
        self.GENESIS_COMMIT_HASH = None
        # Personalized Artifacts
        self.DESIGNATED_OWNER_HASH = designated_owner_pubkey_hash
        self.OWNERSHIP_FLAGS = 0b0000  # Bit flags for ownership state
        self.RESERVED_FLAGS = 0b0010
        # Protocol parameters
        self.per_instance_salt = None
        self._combined_hash = None
        self.POW_DIFFICULTY = None
        self.MAX_OFFSET = None
        self.RARITY_THRESHOLD = None
        self.PRIME_BITS = None
        self.PRIME_NONCE = None
        self.PRIME = None
        self.TOTAL_BYTES = None
        self.TARGET_BYTES = None
        self.TARGET_BYTES_END = None
        self.TARGET_INTERVAL = None
        self.TARGET_INTERVAL_BASE = 30  # Minimum interval seconds
        self.TARGET_INTERVAL_RANGE = 90  # Additional random range
        self.SIGNATURE = None
        self._creation_timestamp = None
        # Initialize through PoW
        self.init_from_pow()

    @property
    def seed(self) -> bytes:
        """
        Get protocol seed (must be initialized).
        Returns:
            bytes: Cryptographic seed
        Raises:
            ValueError: If seed not initialized
        """
        if self._seed is None:
            raise ValueError("Seed not initialized")
        return self._seed

    @property
    def combined_hash(self) -> bytes:
        """
        Get combined hash with embedded difficulty.
        Returns:
            bytes: SHA3-256 combined hash
        Raises:
            ValueError: If combined hash not initialized
        """
        if self._combined_hash is None:
            raise ValueError("Combined hash not initialized")
        return self._combined_hash

    @combined_hash.setter
    def combined_hash(self, value: bytes | None) -> None:
        """
        Get combined hash with embedded difficulty.
        Returns:
            bytes: SHA3-256 combined hash
        Raises:
            ValueError: If combined hash not initialized
        """
        if value is not None and not isinstance(value, bytes):
            raise TypeError("combined_hash must be bytes or None")
        self._combined_hash = value

    def init_from_pow(self):
        """
        Generate cryptographic seed through proof-of-work mining.
        Iterates through candidate seeds until finding one that satisfies:
        1. Base difficulty proof-of-work check
        2. Computed final difficulty ≥ base difficulty
        3. Final difficulty proof-of-work check
        Sets all protocol parameters upon success.
        Raises:
            RuntimeError: If no valid seed found within MAX_ATTEMPTS
        """
        params = self.cfg.get_params()
        base_diff = params["BASE_POW_DIFFICULTY"]
        max_att = params["MAX_ATTEMPTS"]
        # will be logging instead!
        print(f"Starting PoW generation:")
        print(f"Base difficulty: {base_diff}")
        print(f"Max attempts: {max_att}")
        for attempt in range(max_att):
            ts = int(time.time())
            self._creation_timestamp = ts
            # Generate seed components
            seed_components = [token_bytes(24), ts.to_bytes(8, "big")]
            # Add designated owner to seed if specified
            if self.DESIGNATED_OWNER_HASH:
                seed_components.append(self.DESIGNATED_OWNER_HASH)
                self.OWNERSHIP_FLAGS |= self.RESERVED_FLAGS  # Set reserved bit
            candidate_seed = b"".join(seed_components)
            if (
                attempt < 3 or attempt % 100 == 0
            ):  # Show first few attempts + every 100th
                print(f"Attempt {attempt}: seed={candidate_seed.hex()[:32]}...")
            # 1) Fast PoW check (BASE_POW_DIFFICULTY level)
            base_pow_result = self._check_pow(candidate_seed, base_diff)
            if attempt < 3:
                print(
                    f"Attempt {attempt}: Base PoW (diff={base_diff}): {base_pow_result}"
                )
            if not base_pow_result:
                continue
            # 2) Compute all future fields (without mutating self)
            new_fields = self._compute_params(candidate_seed, base_diff)
            final_difficulty = new_fields["POW_DIFFICULTY"]
            if attempt < 3:
                print(
                    f"Attempt {attempt}: Final difficulty computed: {final_difficulty}"
                )
            # 3) Ensure final difficulty ≥ base_diff and passes final PoW
            if final_difficulty < base_diff:
                if attempt < 3:
                    print(
                        f"Attempt {attempt}: REJECTED - final_diff({final_difficulty}) < base_diff({base_diff})"
                    )
                continue
            # CRITICAL CHECK: Final PoW check
            final_pow_result = self._check_pow(candidate_seed, final_difficulty)
            if attempt < 3 or final_pow_result:  # Always log successful attempts
                print(
                    f"Attempt {attempt}: Final PoW (diff={final_difficulty}): {final_pow_result}"
                )
            if not final_pow_result:
                if attempt < 3:
                    print(f"Attempt {attempt}: REJECTED - Final PoW failed")
                    self._debug_pow_failure(candidate_seed, final_difficulty, attempt)
                continue
            # 4) SUCCESS! Copy computed fields to self
            # will be logging instead!
            print(f"SUCCESS on attempt {attempt}!")
            print(f"Final seed: {candidate_seed.hex()[:32]}...")
            print(f"Final difficulty: {final_difficulty}")
            self._seed = new_fields["_seed"]
            for key, value in new_fields.items():
                if key == "_seed":
                    continue
                setattr(self, key, value)
            # 5) Create Genesis Commitment
            self.create_genesis_commitment()
            # 6) Sign final combined_hash with real difficulty
            self.SIGNATURE = self.signature_obj.sign(self.combined_hash)
            # 7) CRITICAL POST-CREATION CHECK
            self._verify_created_artifact(attempt)
            return
        raise RuntimeError(f"Failed to generate seed after {max_att} attempts")

    def _debug_pow_failure(self, seed: bytes, difficulty: int, attempt: int):
        """
        Detailed diagnostics for failed PoW verification.
        Args:
            seed: Candidate seed that failed
            difficulty: Target difficulty level
            attempt: Current attempt number
        """
        print(f"DEBUGGING PoW failure (attempt {attempt}):")
        params = self.cfg.get_params()
        lb = difficulty // 8
        rb = difficulty % 8
        mask = (0xFF << (8 - rb)) if rb else 0
        print(f"Difficulty params: lb={lb}, rb={rb}, mask=0x{mask:04x}")
        # making pow_data
        pow_data = params["TSP_POW"] + seed + difficulty.to_bytes(2, "big")
        print(f"PoW data length: {len(pow_data)}")
        print(f"PoW data: {pow_data.hex()[:80]}...")
        # getting hash
        h1 = hashlib.sha3_256(pow_data).digest()
        h2 = hashlib.sha3_256(h1).digest()
        result = hashlib.sha3_256(h2).digest()
        print(f"Final hash: {result.hex()}")
        print(f"First byte: 0x{result[0]:02x}")
        # check for violation
        violation = 0
        for i in range(lb):
            violation |= result[i]
        if rb > 0 and lb < len(result):
            violation |= result[lb] & mask
            print(
                f"Byte[{lb}] & mask: 0x{result[lb]:02x} & 0x{mask:04x} = 0x{result[lb] & mask:02x}"
            )
        print(f"Final violation: {violation} (should be 0 for success)")

    def _verify_created_artifact(self, creation_attempt: int):
        """
        Post-creation verification of artifact correctness.
        Ensures created artifact passes its own PoW validation.
        Args:
            creation_attempt: Attempt number that succeeded
        Raises:
            RuntimeError: If created artifact fails verification
        """
        print(f"POST-CREATION VERIFICATION:")
        # final PoW check
        final_verification = self._check_pow(self._seed, self.POW_DIFFICULTY)
        print(f"Final PoW re-check: {final_verification}")
        if not final_verification:
            print(f"CRITICAL BUG DETECTED!")
            print(f"Created artifact fails its own PoW verification!")
            print(f"Seed: {self._seed.hex()}")
            print(f"Difficulty: {self.POW_DIFFICULTY}")
            print(f"Creation attempt: {creation_attempt}")
            # details info
            self._debug_pow_failure(self._seed, self.POW_DIFFICULTY, creation_attempt)
            raise RuntimeError(
                f"CRITICAL BUG: Created artifact with invalid PoW! "
                f"Seed: {self._seed.hex()[:32]}..., Difficulty: {self.POW_DIFFICULTY}"
            )
        # base PoW check
        base_verification = self._check_pow(
            self._seed, self.cfg.get_params()["BASE_POW_DIFFICULTY"]
        )
        print(f"Base PoW re-check: {base_verification}")
        if not base_verification:
            print(f"WARNING: Base PoW verification failed!")
        print(f"Post-creation verification passed!")

    def _compute_params(self, seed: bytes, base_difficulty: int) -> dict:
        """
        Compute all protocol parameters from seed (pure function).
        Deterministically derives all cryptographic parameters including
        final combined_hash with correct difficulty embedded.
        Args:
            seed: Candidate seed bytes
            base_difficulty: Base PoW difficulty level
        Returns:
            dict: All computed protocol parameters
        """
        params = self.cfg.get_params()
        # 1) Compute PRIME_NONCE using current ARTIFACT_INDEX
        combined0 = params["TSP_NONCE"] + seed + self.ARTIFACT_INDEX.to_bytes(8, "big")
        nonce_hash = hashlib.sha3_256(combined0).digest()
        prime_nonce = int.from_bytes(nonce_hash[:16], "big")
        # 2) Derive salt and compute Argon2
        salt = TSPProtocol._derive_salt_static(seed, self.PUBLIC_KEY_BYTES)
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
        # 3) Temporary hash for parameter derivation (with base difficulty)
        temp_combined = (
            prime_nonce.to_bytes(16, "big")
            + h_digest
            + base_difficulty.to_bytes(2, "big")
        )
        temp_hash = hashlib.sha3_256(temp_combined).digest()
        # 4) Calculate MAX_OFFSET from temp_hash
        max_offset = (
            int.from_bytes(h_digest[20:24], "big") % params["MAX_OFFSET_MODULUS"]
        ) + params["MAX_OFFSET_MIN"]
        # 5) Adjust PoW difficulty from temp_hash
        sel_offset = int.from_bytes(temp_hash[4:8], "big") % params["MAX_POW_OFFSET"]
        base_pow = params["BASE_POW_DIFFICULTY"] + sel_offset
        # 6) Select rarity by weights
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
        # 7) Final combined_hash with REAL difficulty
        final_combined = (
            prime_nonce.to_bytes(16, "big")
            + h_digest
            + pow_difficulty.to_bytes(2, "big")  # Use final difficulty!
        )
        combined_hash = hashlib.sha3_256(
            params["TSP_COMBINED"] + final_combined
        ).digest()
        # 8) Byte targets
        total_bytes = copy_params["total_bytes"]
        target_bytes = max(1, round(total_bytes / 4))
        target_bytes_end = max(0, total_bytes - target_bytes)
        # 9) Target interval
        interval_nonce = int.from_bytes(h_digest[16:20], "big")
        target_interval = self.TARGET_INTERVAL_BASE + (
            interval_nonce % self.TARGET_INTERVAL_RANGE
        )
        return {
            "_seed": seed,
            "per_instance_salt": salt,
            "PRIME_NONCE": prime_nonce,
            "POW_DIFFICULTY": pow_difficulty,
            "_combined_hash": combined_hash,  # Contains final difficulty!
            "MAX_OFFSET": max_offset,
            "RARITY_THRESHOLD": chosen_thr,
            "PRIME_BITS": prime_bits,
            "TOTAL_BYTES": total_bytes,
            "TARGET_BYTES": target_bytes,
            "TARGET_BYTES_END": target_bytes_end,
            "TARGET_INTERVAL": target_interval,
        }

    def set_artifact_index(self, index: int):
        """
        Update artifact index and recalculate dependent parameters.
        Recomputes combined_hash, genesis commitment, and signature
        to maintain cryptographic consistency.
        Args:
            index: New artifact index (must be >= 0)
        Raises:
            ValueError: If seed not initialized
            AssertionError: If index is negative
        """
        if self._seed is None:
            raise ValueError("Seed not initialized. Call init_from_pow() first.")
        assert index >= 0
        self.ARTIFACT_INDEX = index
        # Recompute parameters with new index
        params = self.cfg.get_params()
        new_fields = self._compute_params(self._seed, params["BASE_POW_DIFFICULTY"])
        # Update all fields except seed
        for key, value in new_fields.items():
            if key == "_seed":
                continue
            setattr(self, key, value)
        # IMPORTANT: Recreate genesis commitment with new index
        self.create_genesis_commitment()
        # Re-sign with new combined_hash
        self.SIGNATURE = self.signature_obj.sign(self._combined_hash)

    @staticmethod
    def _derive_salt_static(seed: bytes, public_key: bytes) -> bytes:
        """
        Derive instance-specific salt from seed and public key.
        Args:
            seed: Protocol seed
            public_key: Creator's public key
        Returns:
            bytes: 16-byte salt for Argon2
        """
        ds = hashlib.sha3_256(seed + public_key).digest()
        return hashlib.shake_128(seed + ds).digest(16)

    @staticmethod
    def _get_difficulty_params(difficulty: int) -> tuple[int, int, int]:
        """
        Calculate byte and bit parameters for difficulty validation.
        Args:
            difficulty: Target difficulty (leading zero bits)
        Returns:
            tuple: (leading_bytes, remaining_bits, bit_mask)
        """
        lb = difficulty // 8
        rb = difficulty % 8
        mask = (0xFF << (8 - rb)) if rb else 0
        return lb, rb, mask

    def create_commit(self):
        """
        Create simple commit hash from seed.
        Returns:
            str: Hex-encoded SHA3-256 hash of seed
        """
        return hashlib.sha3_256(self.seed).hexdigest()

    def create_genesis_commitment(self):
        """
        Create tamper-proof genesis commitment for artifact.

        Generates binary genesis record with creator, timestamp, index,
        and optional owner. Signs with domain separation.
        """
        if hasattr(self, "_creation_timestamp") and self._creation_timestamp:
            timestamp = self._creation_timestamp
        else:
            timestamp = int.from_bytes(self.seed[24:32], "big")
        # Binary genesis record
        genesis_record = self._binary_genesis_record(
            self.PUBLIC_KEY_BYTES,
            timestamp,
            self.ARTIFACT_INDEX,
            self.DESIGNATED_OWNER_HASH,
        )
        # Readable version (for debugging)
        self.genesis_record = self._format_genesis_for_display(genesis_record)
        # Single domain separation
        genesis_data = self.cfg.get_params()["TSP_GENESIS"] + genesis_record
        self.GENESIS_SIGNATURE = self.signature_obj.sign(genesis_data)
        self.GENESIS_COMMIT_HASH = hashlib.sha3_256(genesis_data).digest()

    @staticmethod
    def _binary_genesis_record(
        creator_pubkey: bytes,
        timestamp: int,
        index: int,
        owner_hash: bytes = None,
    ) -> bytes:
        """
        Build length-prefixed binary genesis record.
        Format prevents separator collisions using length prefixes.
        Args:
            creator_pubkey: Creator's public key bytes
            timestamp: Unix timestamp
            index: Artifact index
            owner_hash: Optional designated owner hash
        Returns:
            bytes: Binary genesis record
        """
        # Length-prefixed creator pubkey
        record = len(creator_pubkey).to_bytes(2, "big") + creator_pubkey
        # Fixed-length fields
        record += timestamp.to_bytes(8, "big")
        record += index.to_bytes(8, "big")
        # Optional owner hash with flag
        if owner_hash:
            record += b"\x01" + owner_hash  # Flag + 32 bytes
        else:
            record += b"\x00"  # No owner flag
        return record

    @staticmethod
    def _format_genesis_for_display(binary_record: bytes) -> str:
        """
        Parse binary genesis record for human-readable display.
        Safe parsing with bounds checking for debugging.
        Args:
            binary_record: Binary genesis data
        Returns:
            str: Formatted display string
        """
        if len(binary_record) < 18:  # Min: 2 + 8 + 8
            return "Invalid genesis record"
        try:
            offset = 0
            # Parse creator pubkey (length-prefixed)
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
        Verify artifact was created for specific owner.
        Args:
            claimed_owner_pubkey: Public key claiming ownership
        Returns:
            bool: True if owner matches or no restriction
        """
        if not self.DESIGNATED_OWNER_HASH:
            return True  # No restriction
        claimed_hash = hashlib.sha3_256(claimed_owner_pubkey).digest()
        return claimed_hash == self.DESIGNATED_OWNER_HASH

    def _check_pow(self, seed: bytes, difficulty: int) -> bool:
        """
        Verify proof-of-work with triple SHA3-256 hashing.
        Checks leading zero bits match difficulty requirement.
        Args:
            seed: Candidate seed to verify
            difficulty: Target difficulty (1-256)
        Returns:
            bool: True if PoW constraint satisfied
        Raises:
            ValueError: If difficulty out of range or seed too short
            TypeError: If seed is not bytes
        """
        params = self.cfg.get_params()
        mn, mx = params["MIN_DIFFICULTY"], params["MAX_DIFFICULTY"]
        if not (mn <= difficulty <= mx):
            raise ValueError(
                f"Difficulty {difficulty} is out of allowed range [{mn}, {mx}]"
            )
        # Normalize input data
        if not isinstance(seed, bytes):
            raise TypeError("Seed must be bytes")
        if len(seed) < 8:  # Minimum reasonable length
            raise ValueError("Seed too short")
        lb, rb, mask = self._get_difficulty_params(difficulty)
        # Domain separation for PoW
        pow_data = params["TSP_POW"] + seed + difficulty.to_bytes(2, "big")
        h = hashlib.sha3_256(pow_data).digest()
        h = hashlib.sha3_256(h).digest()
        res = hashlib.sha3_256(h).digest()
        # Constant-time validation
        violation = 0
        for i in range(lb):
            violation |= res[i]
        if rb > 0:
            violation |= res[lb] & mask
        return violation == 0

    def _get_hash_materials(self) -> List[Tuple[str, bytes]]:
        """
        Assemble ordered materials for config hash computation.
        Collects all protocol parameters in canonical order for
        deterministic hash generation and signature verification.
        Returns:
            List[Tuple[str, bytes]]: Named parameter pairs
        Raises:
            ValueError: If required parameters not initialized
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

        materials: List[Tuple[str, bytes]] = []
        # 1) Domain separation constants
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
        # 9) Rarity: binary serialization
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
        materials.append(("seed", self.seed))
        materials.append(("creation_time", self.seed[24:32]))
        # 15) Signature from combined_hash (now contains final difficulty!)
        if self.SIGNATURE is None:
            raise ValueError("Signature not initialized")
        materials.append(("signature", self.SIGNATURE))
        return materials

    def config_hash(self) -> bytes:
        """
        Compute final artifact configuration hash.
        Canonical hash of all protocol parameters for verification.
        Returns:
            bytes: SHA3-256 config hash
        """
        h = hashlib.sha3_256()
        h.update(self.cfg.get_params()["TSP_CONFIG"])
        for _, value in self._get_hash_materials():
            h.update(value)
        return h.digest()

    def config_hash_hex(self) -> str:
        """
        Get configuration hash in hexadecimal format.
        Returns:
            str: Hex-encoded config hash
        """
        return self.config_hash().hex()

    @staticmethod
    def _ensure_bytes(data: any, expected_len: int = None) -> bytes:
        """
        Convert data to bytes with optional length validation.
        Args:
            data: Input data (bytes or string)
            expected_len: Expected byte length
        Returns:
            bytes: Validated byte data
        Raises:
            TypeError: If data is not bytes or string
            ValueError: If length doesn't match expected
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif not isinstance(data, bytes):
            raise TypeError(f"Expected bytes or str, got {type(data)}")
        if expected_len and len(data) != expected_len:
            raise ValueError(f"Expected {expected_len} bytes, got {len(data)}")
        return data
