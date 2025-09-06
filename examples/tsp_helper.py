"""
TSP Helper Utilities
Copyright (c) 2025 Vladislav Dunaev. All rights reserved.
SPDX-License-Identifier: AGPL-3.0-or-Commercial

This utility module simplifies TSP operations for example applications.
"""

import os
from pathlib import Path

from tsp import TSP


class TSPHelper:
    """
    Helper utilities for simplified TSP operations.
    Provides convenience methods for common TSP tasks including automatic
    path resolution, user key management, and TSP instance creation with
    pre-configured settings.
    Key features:
    - Automatic key path resolution for users
    - Simplified TSP instance creation
    - User hash computation utilities
    - Key existence validation
    """

    def __init__(self, examples_dir="examples"):
        """
        Initialize helper with auto-detection of base directory.
        Searches for examples directory in current path hierarchy,
        creates one if not found.
        Args:
            examples_dir: Examples folder name (default "examples")
        """
        # Find base directory with examples
        current_dir = Path.cwd()
        self.base_dir = None
        # Search up directory hierarchy
        for parent in [current_dir] + list(current_dir.parents):
            potential_examples = parent / examples_dir
            if potential_examples.exists() and potential_examples.is_dir():
                self.base_dir = parent
                break
        if not self.base_dir:
            # Create structure if not found
            self.base_dir = current_dir
            self.examples_dir = self.base_dir / examples_dir
            self.examples_dir.mkdir(exist_ok=True)
            print(f"📁 Created examples directory: {self.examples_dir}")
        else:
            self.examples_dir = self.base_dir / examples_dir
            print(f"📁 Using examples directory: {self.examples_dir}")

    def get_user_paths(self, username):
        """
        Get key file paths for specified user.
        Args:
            username: User name (alice, bob, artur, etc.)
        Returns:
            tuple: (private_key_path, public_key_path)
        """
        user_dir = self.examples_dir / username / ".key"
        private_key = user_dir / "private.pem"
        public_key = user_dir / "public.pem"
        return str(private_key), str(public_key)

    def get_user_password(self, username):
        """
        Get password for user's private key.
        In production, should read from secure storage or .env file.
        Args:
            username: User name
        Returns:
            bytes: Private key password
        """
        # Example passwords (in production - from secure storage)
        passwords = {
            "alice": b"r3^V#z9!kP@bL7wX$u1NmT&gQe4Yf*C0",
            "bob": b"r3^V#z9!Yt@bk7wX$u1NmT&gQe4Yf*C0",
            "artur": b"e3^V#z9!kP@b67wX$u1KjT&gQe4Uf*C0",
        }
        return passwords.get(username, b"default_password")

    def get_user_hash(self, username):
        """
        Automatically compute public key hash for user.
        Args:
            username: Username
        Returns:
            bytes: SHA3-256 hash of user's public key, None if not found
        """
        _, public_key_path = self.get_user_paths(username)
        if not os.path.exists(public_key_path):
            print(f"️Public key not found for {username}: {public_key_path}")
            return None
        return TSP.create_pubkey_hash_from_file(public_key_path)

    def create_tsp(
        self, username, model="WEB_AUTH", mode="create", designated_owner=None
    ):
        """
        Create auto-configured TSP instance for user.
        Handles all path resolution, password management, and owner
        designation automatically.
        Args:
            username: Username for key selection
            model: TSP model type (WEB_AUTH, NFT, LICENSE, CERTIFICATE)
            mode: Operation mode ('create' or 'verify')
            designated_owner: Owner name or hash for personalized artifacts
        Returns:
            TSP: Configured TSP instance ready for use
        """
        private_key_path, public_key_path = self.get_user_paths(username)
        password = self.get_user_password(username)
        # Process designated_owner parameter
        designated_owner_hash = None
        if designated_owner:
            if isinstance(designated_owner, str):
                # If username provided - get hash
                designated_owner_hash = self.get_user_hash(designated_owner)
                if designated_owner_hash:
                    print(
                        f"🔑 {username} → {designated_owner}: {designated_owner_hash.hex()[:16]}..."
                    )
            elif isinstance(designated_owner, bytes):
                # Already a hash
                designated_owner_hash = designated_owner
        return TSP(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            key_password=password,
            model=model,
            mode=mode,
            designated_owner_hash=designated_owner_hash,
        )

    def check_user_keys(self, username):
        """
        Verify existence of user's key files.
        Args:
            username: Username to check
        Returns:
            bool: True if both keys exist
        """
        private_key_path, public_key_path = self.get_user_paths(username)
        private_exists = os.path.exists(private_key_path)
        public_exists = os.path.exists(public_key_path)
        print(f"User-{username}:")
        print(f"Private key:{'✅' if private_exists else '❌'} {private_key_path}")
        print(f"Public key:{'✅' if public_exists else '❌'} {public_key_path}")
        return private_exists and public_exists


if __name__ == "__main__":
    pass
