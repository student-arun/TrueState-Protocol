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

import hmac
import hashlib


class DeterministicRNG:
    """
    Cryptographically secure deterministic pseudo-random number generator (CSPRNG)
    based on HMAC-SHA3-256. Generates unique and reproducible data streams.
    Key features:
    - Stateless design (no state preservation between calls)
    - State compromise protection
    - Independent generation of each data block
    - Input parameter normalization for security
    Args:
        seed: Initial entropy (32 bytes or arbitrary length)
        nonce: Unique number (0 ≤ nonce ≤ 2^128-1)
        public_key_bytes: User's public key bytes
        taprng: Domain separator for derive_secret function
        tapnor: Domain separator for seed normalization
    """

    MAX_BYTES_PER_CALL = 2**20  # Maximum data size per call (1 MB)

    @staticmethod
    def _normalize_seed(seed: bytes, tapnor: bytes) -> bytes:
        """
        Normalize seed to 32 bytes using SHA3-256.
        Ensures consistent seed representation across all operations.
        Args:
            seed: Original seed (arbitrary length)
            tapnor: Domain separator (prevents collisions)
        Returns:
            bytes: 32-byte normalized seed
        """
        if len(seed) == 32:
            return seed
        return hashlib.sha3_256(tapnor + seed).digest()

    def __init__(
        self,
        seed: bytes,
        nonce: int,
        public_key_bytes: bytes,
        taprng: bytes,
        tapnor: bytes,
    ):
        """
        Initialize generator with cryptographic parameters.
        Performs:
        1. Seed normalization
        2. Nonce range validation
        3. Master key generation (initial_key)
        Args:
            seed: Initial entropy source
            nonce: Unique value for stream generation
            public_key_bytes: Public key for binding
            taprng: Domain separator for key derivation
            tapnor: Domain separator for normalization
        Raises:
            ValueError: If nonce is outside valid range [0, 2^128-1]
        """
        # Seed normalization (required for consistency)
        normalized_seed = self._normalize_seed(seed, tapnor)
        # Validate nonce range
        if not (0 <= nonce <= 2**128 - 1):
            raise ValueError("Nonce must be in range [0, 2^128-1]")
        # Generate secret for derived keys
        # Uses taprng domain separator for context isolation
        derive_secret = hashlib.sha3_256(
            taprng + normalized_seed + public_key_bytes
        ).digest()
        # Form master key material:
        # - Normalized seed guarantees 32 bytes
        # - Nonce ensures stream uniqueness
        key_material = normalized_seed + nonce.to_bytes(16, "big")
        # Generate immutable master key via HMAC
        # Uses derive_secret as key and key_material as data
        self._initial_key = hmac.new(
            key=derive_secret,
            msg=key_material,
            digestmod=hashlib.sha3_256,
        ).digest()

    def __call__(self, n: int, start_index: int = 0) -> bytes:
        """
        Generate n bytes of pseudo-random data.
        Implementation features:
        - Stateless: no internal state storage
        - Deterministic: same parameters → same output
        - Parallelizable: supports arbitrary start index
        Args:
            n: Number of bytes to generate
            start_index: Starting block index (for sequential generation)
        Returns:
            bytes: Pseudo-random bytes
        Raises:
            ValueError: If n exceeds MAX_BYTES_PER_CALL
        """
        # Check data size constraints
        if n > self.MAX_BYTES_PER_CALL:
            raise ValueError(f"Maximum request size is {self.MAX_BYTES_PER_CALL} bytes")

        output = bytearray()
        # Calculate number of 32-byte blocks (SHA3-256 = 32 bytes)
        total_blocks = (n + 31) // 32  # Round up

        # Generate blocks via HMAC with master key
        for i in range(start_index, start_index + total_blocks):
            # Convert index to 16-byte big-endian format
            data = i.to_bytes(16, "big")
            # Important: each block is generated independently
            block = hmac.new(
                key=self._initial_key, msg=data, digestmod=hashlib.sha3_256
            ).digest()
            output.extend(block)
        # Return exactly n bytes (discard excess from last block)
        return bytes(output[:n])
