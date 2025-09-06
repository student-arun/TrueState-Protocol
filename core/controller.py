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


class Controller:
    """
    Configuration manager for TrueState Protocol artifact types.
    Manages hierarchical configuration parameters for different artifact models,
    providing computational cost and rarity settings based on use case requirements.
    Key features:
    - Model-specific proof-of-work difficulty settings
    - Graduated rarity system with weighted probabilities
    - Memory-hard function parameters (Argon2)
    - Cryptographic constants and domain separators
    Supported models(can be extended):
    - NFT: High-value collectibles (16 difficulty, 4GB memory)
    - CERTIFICATE: Digital certificates (8 difficulty, 512MB memory)
    - LICENSE: Software licenses (4 difficulty, 512MB memory)
    - WEB_AUTH: Authentication tokens (2 difficulty, 64MB memory)
    Configuration hierarchy:
    - BASE_DEFAULTS: Common parameters for all models
    - Model-specific overrides: Custom settings per artifact type
    - TSP_CONSTANTS: Protocol-wide cryptographic domain separators
    """

    ALGO_VERSION = "1.0.0"
    SALT_LENGTH = 16
    WEIGHT_DIVIDER = 6553  # rarity distribution balance

    TSP_CONSTANTS = {
        "TSP_CONFIG": b"TSPCONFIG",
        "TSP_COMBINED": b"TSPCOMBINED",
        "TSP_PRIME1": b"TSPPRIMECHECK1",
        "TSP_PRIME2": b"TSPPRIMECHECK2",
        "TSP_RNG": b"TSPRNG",
        "TSP_NOR": b"TSPNORMALIZE",
        "TSP_NONCE": b"TSPNONCE",
        "TSP_POW": b"TSPPOW",
        "TSP_GENESIS": b"TSPGENESIS",
        "TSP_TRANSFERGENESIS": b"TSPTRANSFERGENESIS",
    }

    BASE_DEFAULTS = {
        "ALGO_VERSION": ALGO_VERSION,
        "HASH_LEN": 16,
        "MAX_OFFSET_MODULUS": 2**16 - 1,
        "MAX_OFFSET_MIN": 1,
        "MAX_DIFFICULTY": 256,
        "METADATA_DIR": "metadata",
        "MIN_DIFFICULTY": 1,
        "PARALLELISM": 2,
        "SALT_LENGTH": SALT_LENGTH,
        "TIME_COST": 3,
        "WEIGHT_DIVIDER": WEIGHT_DIVIDER,
        **TSP_CONSTANTS,
    }

    MODELS = {
        "NFT": {
            "BASE_POW_DIFFICULTY": 16,
            "MAX_ATTEMPTS": 2**32,
            "MAX_POW_OFFSET": 30,
            "MEMORY_COST": 4096,
            "PARALLELISM": 4,
            "RARITY_PARAMS": {
                0.01: {
                    "prime_bits": 1536,
                    "pow_extra": 10,
                    "total_bytes": 6,
                },
                0.02: {
                    "prime_bits": 1280,
                    "pow_extra": 7,
                    "total_bytes": 5,
                },
                0.03: {
                    "prime_bits": 1024,
                    "pow_extra": 4,
                    "total_bytes": 4,
                },
                0.04: {
                    "prime_bits": 768,
                    "pow_extra": 1,
                    "total_bytes": 3,
                },
                0.05: {
                    "prime_bits": 512,
                    "pow_extra": 0,
                    "total_bytes": 1,
                },
            },
            "RARITY_WEIGHTS": {
                0.01: 1,
                0.02: 2,
                0.03: 3,
                0.04: 4,
                0.05: 5,
            },
        },
        "CERTIFICATE": {
            "BASE_POW_DIFFICULTY": 8,
            "MAX_ATTEMPTS": 2**24,
            "MAX_POW_OFFSET": 15,
            "MEMORY_COST": 512,
            "RARITY_PARAMS": {
                0.03: {
                    "prime_bits": 768,
                    "pow_extra": 4,
                    "total_bytes": 4,
                },
                0.04: {
                    "prime_bits": 640,
                    "pow_extra": 2,
                    "total_bytes": 3,
                },
                0.05: {
                    "prime_bits": 384,
                    "pow_extra": 0,
                    "total_bytes": 2,
                },
            },
            "RARITY_WEIGHTS": {
                0.03: 3,
                0.04: 4,
                0.05: 5,
            },
        },
        "LICENSE": {
            "BASE_POW_DIFFICULTY": 4,
            "MAX_ATTEMPTS": 2**20,
            "MAX_POW_OFFSET": 8,
            "MEMORY_COST": 512,
            "RARITY_PARAMS": {
                0.04: {
                    "prime_bits": 384,
                    "pow_extra": 1,
                    "total_bytes": 2,
                },
                0.05: {
                    "prime_bits": 256,
                    "pow_extra": 0,
                    "total_bytes": 1,
                },
            },
            "RARITY_WEIGHTS": {
                0.04: 4,
                0.05: 5,
            },
        },
        "WEB_AUTH": {
            "BASE_POW_DIFFICULTY": 2,
            "MAX_ATTEMPTS": 2**20,
            "MAX_POW_OFFSET": 2,
            "MEMORY_COST": 64,
            "RARITY_PARAMS": {
                0.05: {
                    "prime_bits": 128,
                    "pow_extra": 0,
                    "total_bytes": 1,
                },
            },
            "RARITY_WEIGHTS": {
                0.05: 1,
            },
        },
    }

    def __init__(self, model: str):
        """
        Initialize Controller with specified artifact model configuration.
        Args:
            model: Artifact type ('NFT', 'CERTIFICATE', 'LICENSE', 'WEB_AUTH')
        Raises:
            ValueError: If model is not supported
        """
        if model not in Controller.MODELS:
            raise ValueError(f"Unsupported model: {model}")
        self.model = model

    def get_params(self):
        """
        Get merged configuration parameters for current model.
        Returns:
            dict: Combined BASE_DEFAULTS and model-specific parameters
        """
        return {**Controller.BASE_DEFAULTS, **Controller.MODELS[self.model]}
