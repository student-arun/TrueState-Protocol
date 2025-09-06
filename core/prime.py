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
import time
from Crypto.Util import number
from core.determinerng import DeterministicRNG


class PRNGWrapper:
    """Wrapper for DeterministicRNG compatibility with Crypto.Util.number interface"""

    def __init__(self, rng: DeterministicRNG):
        """
        Initialize wrapper with deterministic RNG instance.
        Args:
            rng: DeterministicRNG instance for cryptographic randomness
        """
        self.rng = rng
        self.offset = 0

    def __call__(self, n: int) -> bytes:
        """
        Generate n random bytes with automatic offset management.
        Args:
            n: Number of bytes to generate
        Returns:
            bytes: Random bytes from deterministic RNG
        """
        result = self.rng(n, self.offset)
        # Shift the offset by the number of blocks used
        self.offset += (n + 31) // 32
        return result


class Prime:
    def __init__(
        self,
        protocol: object,
        pubkey_bytes: bytes,
    ):
        """
        Initialize Prime generator with protocol context and public key.
        Args:
            protocol: TSPProtocol instance with configuration and state
            pubkey_bytes: Public key bytes for cryptographic binding
        """
        self.attempts = 0
        self.protocol = protocol
        self.pubkey_bytes = pubkey_bytes
        self.start_time = time.time()
        # Cache only IMMUTABLE parameters (those not dependent on ARTIFACT_INDEX)
        self._cache_static_params()

    def _cache_static_params(self):
        """
        Cache immutable parameters that don't depend on ARTIFACT_INDEX.
        Caches:
            - seed (immutable)
            - public key (immutable)
            - base configuration parameters
        """
        self.seed = self.protocol.seed

    def generate_prime(self):
        """
        Generate cryptographic prime with dual proof-of-work validation.
        Maintains cryptographic correctness by preserving original protocol
        parameters during generation. Uses deterministic RNG with accumulating
        offset to ensure uniqueness.
        Returns:
            int: Cryptographic prime that satisfies both PoW constraints
        Raises:
            RuntimeError: If prime generation fails after MAX_ATTEMPTS
        """
        # Reset the counters
        self.attempts = 0
        self.start_time = time.time()
        max_attempts = self.protocol.cfg.get_params()["MAX_ATTEMPTS"]
        # will be logging instead!
        print(f"Prime generation starting:")
        print(f"Current ARTIFACT_INDEX: {self.protocol.ARTIFACT_INDEX}")
        print(f"Current POW_DIFFICULTY: {self.protocol.POW_DIFFICULTY}")
        print(f"Current PRIME_BITS: {self.protocol.PRIME_BITS}")
        # Remember the original parameters
        original_artifact_index = self.protocol.ARTIFACT_INDEX
        original_pow_difficulty = self.protocol.POW_DIFFICULTY
        original_prime_bits = self.protocol.PRIME_BITS
        original_prime_nonce = self.protocol.PRIME_NONCE
        # Create the RNG ONCE outside the loop
        base_rng = DeterministicRNG(
            self.seed,  # Cached seed
            original_prime_nonce,  # Fixed nonce
            self.pubkey_bytes,
            self.protocol.cfg.get_params()["TSP_RNG"],
            self.protocol.cfg.get_params()["TSP_NOR"],
        )
        # Create the wrapper once - the offset will accumulate
        rng = PRNGWrapper(base_rng)
        print(f"Using fixed bits: {original_prime_bits}, nonce: {original_prime_nonce}")
        while self.attempts < max_attempts:
            # will be logging instead!
            if self.attempts % 1000 == 0:  # loging every 1000
                print(f"Prime attempt {self.attempts}, RNG offset: {rng.offset}")
            # Use the FIXED parameters from init_from_pow()
            bits = original_prime_bits
            # The RNG is already created, just use it (the offset accumulates automatically)
            if bits <= 512:
                # for certificates, license
                prime = number.getPrime(bits, randfunc=rng)
            else:
                # for NFT or Crypto
                prime = number.getStrongPrime(bits, randfunc=rng)
            if self.is_prime(prime):
                # will be logging instead!
                print(f"Prime found on attempt {self.attempts}!")
                print(f"Prime: {str(prime)[:20]}... ({bits} bits)")
                # IMPORTANT: Ensure that the parameters have not changed
                if (
                    self.protocol.ARTIFACT_INDEX != original_artifact_index
                    or self.protocol.POW_DIFFICULTY != original_pow_difficulty
                ):
                    print(
                        f"WARNING: Protocol parameters changed during prime generation!"
                    )
                    print(
                        f"Original: index={original_artifact_index}, difficulty={original_pow_difficulty}"
                    )
                    print(
                        f"Current:  index={self.protocol.ARTIFACT_INDEX}, difficulty={self.protocol.POW_DIFFICULTY}"
                    )
                    # Restore the original parameters
                    self.protocol.ARTIFACT_INDEX = original_artifact_index
                    self.protocol.POW_DIFFICULTY = original_pow_difficulty
                    self.protocol.PRIME_BITS = original_prime_bits
                    self.protocol.PRIME_NONCE = original_prime_nonce
                    print(f"Restored original parameters")
                self.protocol.PRIME = prime
                return prime
            self.attempts += 1
        raise RuntimeError(f"Prime generation failed after {max_attempts} attempts")

    def is_prime(self, prime: int) -> bool:
        """
        Verify prime validity against dual proof-of-work constraints.
        Performs two-stage validation:
        1. SHA3-256(TSP_PRIME1 + prime_bytes) < difficulty_threshold
        2. SHA3-256(TSP_PRIME2 + pubkey + seed + pow_hash) < difficulty_threshold
        Args:
            prime: Candidate prime number to verify
        Returns:
            bool: True if prime satisfies both PoW constraints
        """
        # Use the current (fixed) parameters
        bits = self.protocol.PRIME_BITS
        pow_difficulty = self.protocol.POW_DIFFICULTY
        expected_prime_len = (bits + 7) // 8
        pow_threshold = 1 << (256 - pow_difficulty)
        try:
            prime_bytes = prime.to_bytes(expected_prime_len, "big")
        except OverflowError:
            return False
        # First PoW: hash(prime_bytes) < threshold
        pow_data_1 = self.protocol.cfg.get_params()["TSP_PRIME1"] + prime_bytes
        pow_hash = hashlib.sha3_256(pow_data_1).digest()
        pow_int = int.from_bytes(pow_hash, "big")
        if pow_int >= pow_threshold:
            return False
        # Second PoW: hash(pubkey + seed + pow_hash) < threshold
        pow_data_2 = (
            self.protocol.cfg.get_params()["TSP_PRIME2"]
            + self.pubkey_bytes
            + self.seed
            + pow_hash
        )
        combined_hash = hashlib.sha3_256(pow_data_2).digest()
        comb_int = int.from_bytes(combined_hash, "big")
        if comb_int >= pow_threshold:
            return False
        return True
