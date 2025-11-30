"""
============================================================================
CYBERSHEPPARD - Encryption Utilities
============================================================================
Handles encryption/decryption of sensitive data (SSH keys, passwords).
"""

import base64
import os
from cryptography.fernet import Fernet
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class EncryptionManager:
    """
    Manages encryption and decryption of sensitive data.
    Uses Fernet (symmetric encryption) from cryptography library.
    """

    def __init__(self, encryption_key: Optional[str] = None):
        """
        Initialize encryption manager.

        Args:
            encryption_key: Base64-encoded Fernet key (32 bytes).
                          If None, will try to load from environment variable.
        """
        if encryption_key is None:
            encryption_key = os.getenv('ENCRYPTION_KEY')

        if not encryption_key:
            raise ValueError("Encryption key not provided and ENCRYPTION_KEY not set")

        try:
            # Validate and create Fernet instance
            self.fernet = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
        except Exception as e:
            raise ValueError(f"Invalid encryption key: {e}")

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext data.

        Args:
            plaintext: Data to encrypt

        Returns:
            Base64-encoded encrypted data
        """
        try:
            encrypted = self.fernet.encrypt(plaintext.encode('utf-8'))
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt encrypted data.

        Args:
            ciphertext: Base64-encoded encrypted data

        Returns:
            Decrypted plaintext
        """
        try:
            encrypted = base64.b64decode(ciphertext.encode('utf-8'))
            decrypted = self.fernet.decrypt(encrypted)
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise

    @staticmethod
    def generate_key() -> str:
        """
        Generate a new Fernet encryption key.

        Returns:
            Base64-encoded encryption key
        """
        key = Fernet.generate_key()
        return key.decode('utf-8')


# Global encryption manager instance
_encryption_manager: Optional[EncryptionManager] = None


def get_encryption_manager() -> EncryptionManager:
    """
    Get or create global encryption manager instance.

    Returns:
        EncryptionManager instance
    """
    global _encryption_manager
    if _encryption_manager is None:
        _encryption_manager = EncryptionManager()
    return _encryption_manager


def encrypt_data(plaintext: str) -> str:
    """
    Encrypt data using global encryption manager.

    Args:
        plaintext: Data to encrypt

    Returns:
        Encrypted data
    """
    return get_encryption_manager().encrypt(plaintext)


def decrypt_data(ciphertext: str) -> str:
    """
    Decrypt data using global encryption manager.

    Args:
        ciphertext: Encrypted data

    Returns:
        Decrypted plaintext
    """
    return get_encryption_manager().decrypt(ciphertext)
