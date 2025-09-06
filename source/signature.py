#!/usr/bin/env python3
"""
TSP Example - Software Licensing Demo
Copyright (c) 2025 Vladislav Dunaev
Licensed under AGPL-3.0-or-Commercial
"""

import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


class SignatureHandler:
    """
    Ed25519 digital signature handler with verify-only mode support.
    Manages cryptographic signing and verification operations using
    Ed25519 algorithm. Supports both full mode (with private key)
    and verify-only mode for signature validation without private key access.
    Key features:
    - Automatic key generation if not present
    - Encrypted private key storage
    - Verify-only mode for public verification
    - Multiple key export formats (Raw, PEM, DER)
    """

    def __init__(
        self,
        private_key_path: str,
        public_key_path: str,
        password: bytes,
        verify_only: bool = False,  # Support for verify-only mode
    ):
        """
        Initialize signature handler with key paths.
        Args:
            private_key_path: Path to private key PEM file
            public_key_path: Path to public key PEM file
            password: Password for private key encryption
            verify_only: If True, only verification operations allowed
        """
        self.password = password
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.verify_only = verify_only  # Mode flag

        if not verify_only:
            self._ensure_keys_exist()
            self.private_key = self.load_private_key()
        else:
            self.private_key = None  # No private key in verify-only mode

        self.public_key = self.load_public_key()

    @classmethod
    def create_verify_only(cls, public_key_bytes: bytes):
        """
        Create handler for signature verification only (no private key).
        Args:
            public_key_bytes: Public key in Raw format (32 bytes for Ed25519)
        Returns:
            SignatureHandler: Instance in verify-only mode
        Raises:
            ValueError: If public key is not 32 bytes
        """
        # Create instance without calling __init__
        instance = cls.__new__(cls)

        # Set minimal required attributes
        instance.verify_only = True
        instance.private_key = None
        instance.password = None
        instance.private_key_path = None
        instance.public_key_path = None

        # Restore Ed25519PublicKey from raw bytes
        if len(public_key_bytes) != 32:
            raise ValueError(
                f"Ed25519 public key must be 32 bytes, got {len(public_key_bytes)}"
            )

        instance.public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )

        return instance

    @classmethod
    def from_public_key_file(cls, public_key_path: str):
        """
        Create verify-only handler from public key file.
        Args:
            public_key_path: Path to PEM file with public key
        Returns:
            SignatureHandler: Instance in verify-only mode
        Raises:
            TypeError: If key is not Ed25519 type
        """
        instance = cls.__new__(cls)
        instance.verify_only = True
        instance.private_key = None
        instance.password = None
        instance.private_key_path = None
        instance.public_key_path = public_key_path

        # Load only public key
        with open(public_key_path, "rb") as f:
            key_data = f.read()
            instance.public_key = serialization.load_pem_public_key(key_data)
            if not isinstance(instance.public_key, ed25519.Ed25519PublicKey):
                raise TypeError("Invalid public key type, expected Ed25519")

        return instance

    def _ensure_keys_exist(self):
        """
        Generate key pair if not already present.
        Creates Ed25519 key pair with encrypted private key storage
        and appropriate file permissions.
        Raises:
            RuntimeError: If called in verify-only mode
        """
        if self.verify_only:
            raise RuntimeError("Cannot generate keys in verify-only mode")

        if os.path.exists(self.private_key_path) and os.path.exists(
            self.public_key_path
        ):
            return

        private_key = ed25519.Ed25519PrivateKey.generate()

        # Save private key (encrypted)
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(self.password),
        )
        with open(self.private_key_path, "wb") as f:
            f.write(pem_private)
        os.chmod(self.private_key_path, 0o600)

        # Save public key
        public_key = private_key.public_key()
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(self.public_key_path, "wb") as f:
            f.write(pem_public)

    def get_public_bytes(
        self,
        encoding: serialization.Encoding = serialization.Encoding.Raw,
        format: serialization.PublicFormat = serialization.PublicFormat.Raw,
    ) -> bytes:
        """
        Export public key in specified format.
        Args:
            encoding: Output encoding (Raw, DER, PEM)
            format: Key format (Raw, SubjectPublicKeyInfo)
        Returns:
            bytes: Public key in requested format (default: 32-byte raw)
        """
        return self.public_key.public_bytes(encoding=encoding, format=format)

    def get_private_bytes(
        self,
        encoding: serialization.Encoding = serialization.Encoding.Raw,
        format: serialization.PrivateFormat = serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ) -> bytes:
        """
        Export private key in specified format.
        Args:
            encoding: Output encoding (Raw, DER, PEM)
            format: Key format (Raw, PKCS8)
            encryption_algorithm: Optional encryption for exported key
        Returns:
            bytes: Private key in requested format (default: 32-byte raw)
        Raises:
            RuntimeError: If in verify-only mode
        """
        if self.verify_only:
            raise RuntimeError("Cannot access private key in verify-only mode")

        return self.private_key.private_bytes(
            encoding=encoding,
            format=format,
            encryption_algorithm=encryption_algorithm,
        )

    def load_private_key(self) -> ed25519.Ed25519PrivateKey:
        """
        Load private key from encrypted PEM file.
        Returns:
            ed25519.Ed25519PrivateKey: Loaded private key
        Raises:
            RuntimeError: If in verify-only mode
            TypeError: If key is not Ed25519 type
        """
        if self.verify_only:
            raise RuntimeError("Cannot load private key in verify-only mode")

        with open(self.private_key_path, "rb") as f:
            key_data = f.read()
            key = serialization.load_pem_private_key(key_data, password=self.password)
            if not isinstance(key, ed25519.Ed25519PrivateKey):
                raise TypeError("Invalid private key type")
            return key

    def load_public_key(self) -> ed25519.Ed25519PublicKey:
        """
        Load public key from PEM file or return pre-loaded key.
        Supports loading in both normal and verify-only modes.
        Returns:
            ed25519.Ed25519PublicKey: Loaded public key
        Raises:
            TypeError: If key is not Ed25519 type
        """
        # Support loading public key in verify-only mode
        if self.verify_only and self.public_key_path:
            with open(self.public_key_path, "rb") as f:
                key_data = f.read()
                key = serialization.load_pem_public_key(key_data)
                if not isinstance(key, ed25519.Ed25519PublicKey):
                    raise TypeError("Invalid public key type")
                return key
        elif self.verify_only:
            # Public key already set in create_verify_only
            return self.public_key
        else:
            # Normal mode - load from file
            with open(self.public_key_path, "rb") as f:
                key_data = f.read()
                key = serialization.load_pem_public_key(key_data)
                if not isinstance(key, ed25519.Ed25519PublicKey):
                    raise TypeError("Invalid public key type")
                return key

    def sign(self, raw_data: bytes) -> bytes:
        """
        Sign data with private key using Ed25519.
        Args:
            raw_data: Data to sign
        Returns:
            bytes: 64-byte Ed25519 signature
        Raises:
            RuntimeError: If in verify-only mode or private key not loaded
        """
        if self.verify_only:
            raise RuntimeError(
                "Cannot sign in verify-only mode - no private key available"
            )

        if self.private_key is None:
            raise RuntimeError("Private key not loaded")

        return self.private_key.sign(raw_data)

    def verify(self, raw_data: bytes, signature: bytes) -> bool:
        """
        Verify signature using public key.
        Args:
            raw_data: Original data that was signed
            signature: 64-byte Ed25519 signature
        Returns:
            bool: True if signature valid, False otherwise
        """
        try:
            self.public_key.verify(signature, raw_data)
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            # Log unexpected errors for debugging
            print(f"Unexpected verification error: {e}")
            return False

    def can_sign(self) -> bool:
        """
        Check if handler can perform signing operations.
        Returns:
            bool: True if signing available (has private key)
        """
        return not self.verify_only and self.private_key is not None

    def get_key_info(self) -> dict:
        """
        Get key information for debugging purposes.
        Returns:
            dict: Key status and public key info
        """
        public_hex = self.get_public_bytes().hex()

        return {
            "verify_only": self.verify_only,
            "can_sign": self.can_sign(),
            "public_key": public_hex,
            "public_key_short": f"{public_hex[:8]}...{public_hex[-8:]}",
        }


if __name__ == "__main__":
    signer = SignatureHandler(
        private_key_path="/home/sonymag/Develop/room/TAP/artur/.key/private.pem",
        public_key_path="/home/sonymag/Develop/room/TAP/artur/.key/pubkey.pem",
        password=b"e3^V#z9!kP@b67wX$u1KjT&gQe4Uf*C0",
    )
