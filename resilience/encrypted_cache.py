"""
Encrypted local cache for session reports using AES-256-CBC.
Survives network outages and system restarts.
"""

import os
import json
import hmac
import hashlib
from pathlib import Path
from typing import Optional, List
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import structlog

logger = structlog.get_logger(__name__)


class EncryptedCache:
    """
    AES-256-CBC encrypted cache with HMAC integrity verification.
    File format: IV (16 bytes) || HMAC (32 bytes) || Ciphertext
    """

    def __init__(self, cache_dir: str, encryption_key: Optional[bytes] = None):
        """
        Initialize encrypted cache.
        
        Args:
            cache_dir: Directory to store encrypted cache files
            encryption_key: 32-byte AES-256 key (generated if None)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate or use provided encryption key
        if encryption_key is None:
            self.encryption_key = os.urandom(32)  # 256 bits
            logger.warning(
                "generated_ephemeral_encryption_key",
                note="Key will not persist across restarts. Set GHOST_ENCRYPTION_KEY env var for persistence."
            )
        else:
            if len(encryption_key) != 32:
                raise ValueError("Encryption key must be exactly 32 bytes (256 bits)")
            self.encryption_key = encryption_key
        
        self.hmac_key = hashlib.sha256(self.encryption_key + b"hmac_salt").digest()
        logger.info("encrypted_cache_initialized", cache_dir=str(self.cache_dir))

    def _encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext using AES-256-CBC with PKCS7 padding."""
        # Generate random IV
        iv = os.urandom(16)
        
        # Apply PKCS7 padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Calculate HMAC over ciphertext
        h = hmac.new(self.hmac_key, ciphertext, hashlib.sha256)
        hmac_digest = h.digest()
        
        # Return: IV || HMAC || Ciphertext
        return iv + hmac_digest + ciphertext

    def _decrypt(self, encrypted_data: bytes) -> Optional[bytes]:
        """Decrypt ciphertext and verify HMAC integrity."""
        try:
            # Parse: IV (16) || HMAC (32) || Ciphertext
            if len(encrypted_data) < 48:
                logger.error("encrypted_data_too_short", length=len(encrypted_data))
                return None
            
            iv = encrypted_data[:16]
            stored_hmac = encrypted_data[16:48]
            ciphertext = encrypted_data[48:]
            
            # Verify HMAC
            h = hmac.new(self.hmac_key, ciphertext, hashlib.sha256)
            if not hmac.compare_digest(h.digest(), stored_hmac):
                logger.error("hmac_verification_failed", note="Data may be tampered")
                return None
            
            # Decrypt
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_data) + unpadder.finalize()
            
            return plaintext
        
        except Exception as e:
            logger.error("decryption_failed", error=str(e))
            return None

    def cache_report(self, session_id: str, report_data: dict) -> bool:
        """
        Cache a session report with encryption.
        
        Args:
            session_id: Unique session identifier
            report_data: Report dictionary to cache
            
        Returns:
            True if cached successfully, False otherwise
        """
        try:
            # Serialize report to JSON
            json_data = json.dumps(report_data, indent=2)
            plaintext = json_data.encode("utf-8")
            
            # Encrypt
            encrypted_data = self._encrypt(plaintext)
            
            # Write to cache file
            cache_file = self.cache_dir / f"{session_id}.enc"
            cache_file.write_bytes(encrypted_data)
            
            logger.info(
                "report_cached",
                session_id=session_id,
                file=str(cache_file),
                size_bytes=len(encrypted_data)
            )
            return True
        
        except Exception as e:
            logger.error("cache_write_failed", session_id=session_id, error=str(e))
            return False

    def retrieve_report(self, session_id: str) -> Optional[dict]:
        """
        Retrieve and decrypt a cached report.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Report dictionary if found and valid, None otherwise
        """
        try:
            cache_file = self.cache_dir / f"{session_id}.enc"
            
            if not cache_file.exists():
                logger.warning("cache_file_not_found", session_id=session_id)
                return None
            
            # Read encrypted data
            encrypted_data = cache_file.read_bytes()
            
            # Decrypt
            plaintext = self._decrypt(encrypted_data)
            if plaintext is None:
                return None
            
            # Deserialize JSON
            report_data = json.loads(plaintext.decode("utf-8"))
            
            logger.info("report_retrieved", session_id=session_id)
            return report_data
        
        except Exception as e:
            logger.error("cache_read_failed", session_id=session_id, error=str(e))
            return None

    def list_cached_reports(self) -> List[str]:
        """List all cached session IDs."""
        try:
            session_ids = [
                f.stem for f in self.cache_dir.glob("*.enc")
            ]
            logger.info("listed_cached_reports", count=len(session_ids))
            return session_ids
        except Exception as e:
            logger.error("list_cache_failed", error=str(e))
            return []
