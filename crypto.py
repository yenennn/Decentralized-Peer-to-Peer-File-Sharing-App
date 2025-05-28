"""
Enhanced crypto.py with better error handling and debugging capabilities
------------------------------------------------------------------------
•  RSA‑2048 for asymmetric key exchange
•  AES‑256‑CFB with fresh random IV per message/chunk for bulk encryption
•  Enhanced error handling and debugging
•  Thread-safe operations
•  Data integrity verification
"""

import os
import logging
import threading
import hashlib
import hmac
from typing import Tuple, Dict, Any, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)


class CryptoManager:
    """Enhanced crypto manager with better error handling and debugging."""

    def __init__(self):
        # Thread lock for session key operations
        self._lock = threading.RLock()

        # RSA key‑pair (persistent for the whole runtime of the node)
        logger.info("Generating RSA-2048 key pair...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        self.public_key = self.private_key.public_key()
        logger.info("RSA key pair generated successfully")

        # peer_id -> (aes_key: bytes, base_iv: bytes, hmac_key: bytes)
        self.session_keys: Dict[str, Tuple[bytes, bytes, bytes]] = {}

        # Statistics for debugging
        self.encryption_count = 0
        self.decryption_count = 0
        self.error_count = 0

    # RSA helpers
    def get_public_key_pem(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def load_peer_public_key(self, peer_public_key_pem: bytes):
        try:
            return serialization.load_pem_public_key(
                peer_public_key_pem,
                backend=default_backend(),
            )
        except Exception as e:
            logger.error(f"Failed to load peer public key: {e}")
            raise

    @staticmethod
    def generate_session_key() -> Tuple[bytes, bytes, bytes]:
        """Return a fresh (aes_key, iv, hmac_key) tuple for AES‑256."""
        aes_key = os.urandom(32)  # 256-bit AES key
        iv = os.urandom(16)       # 128-bit IV
        hmac_key = os.urandom(32) # 256-bit HMAC key for integrity
        return aes_key, iv, hmac_key

    @staticmethod
    def encrypt_session_key(peer_public_key, session_key: bytes, iv: bytes, hmac_key: bytes) -> bytes:
        """Encrypt the session key package with peer's public key."""
        try:
            package = session_key + iv + hmac_key  # 32 + 16 + 32 = 80 bytes
            encrypted = peer_public_key.encrypt(
                package,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            logger.debug(f"Encrypted session key package: {len(package)} -> {len(encrypted)} bytes")
            return encrypted
        except Exception as e:
            logger.error(f"Failed to encrypt session key: {e}")
            raise

    def decrypt_session_key(self, encrypted_package: bytes) -> Tuple[bytes, bytes, bytes]:
        """Decrypt the session key package."""
        try:
            package = self.private_key.decrypt(
                encrypted_package,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            if len(package) != 80:  # 32 + 16 + 32
                raise ValueError(f"Invalid session key package length: {len(package)}")

            aes_key = package[:32]
            iv = package[32:48]
            hmac_key = package[48:80]

            logger.debug("Successfully decrypted session key package")
            return aes_key, iv, hmac_key

        except Exception as e:
            logger.error(f"Failed to decrypt session key: {e}")
            raise

    def store_peer_session_key(self, peer_id: str, key: bytes, iv: bytes, hmac_key: Optional[bytes] = None):
        """Store session key for a peer with thread safety."""
        with self._lock:
            # Handle backward compatibility
            if hmac_key is None:
                hmac_key = os.urandom(32)
                logger.warning(f"Generated new HMAC key for peer {peer_id} (backward compatibility)")

            self.session_keys[peer_id] = (key, iv, hmac_key)
            logger.info(
                "Stored session key for %s: AES %s… IV %s… HMAC %s…",
                peer_id,
                key.hex()[:8],
                iv.hex()[:8],
                hmac_key.hex()[:8],
            )

    def _get_cipher(self, key: bytes, iv: bytes):
        """Create AES-CFB cipher."""
        try:
            return Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        except Exception as e:
            logger.error(f"Failed to create cipher: {e}")
            raise

    def _compute_hmac(self, hmac_key: bytes, data: bytes) -> bytes:
        """Compute HMAC-SHA256 for data integrity."""
        return hmac.new(hmac_key, data, hashlib.sha256).digest()

    def _verify_hmac(self, hmac_key: bytes, data: bytes, expected_hmac: bytes) -> bool:
        """Verify HMAC for data integrity."""
        computed_hmac = self._compute_hmac(hmac_key, data)
        return hmac.compare_digest(computed_hmac, expected_hmac)

    def encrypt_data(self, peer_id: str, plaintext: bytes) -> bytes:
        """
        Encrypt arbitrary bytes for a given peer with integrity protection.

        Format: iv (16) || ciphertext (variable) || hmac (32)
        Returns: encrypted data with IV and HMAC
        """
        try:
            with self._lock:
                if peer_id not in self.session_keys:
                    raise ValueError(f"No session key for peer {peer_id}")

                aes_key, _, hmac_key = self.session_keys[peer_id]

            # Generate fresh IV for each encryption
            iv = os.urandom(16)

            # Encrypt the data
            encryptor = self._get_cipher(aes_key, iv).encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            # Compute HMAC over IV + ciphertext
            payload = iv + ciphertext
            mac = self._compute_hmac(hmac_key, payload)

            # Final format: iv || ciphertext || hmac
            result = payload + mac

            self.encryption_count += 1

            logger.debug(
                f"Encrypted {len(plaintext)} bytes -> {len(result)} bytes for peer {peer_id} "
                f"(IV: {iv.hex()[:8]}…)"
            )

            return result

        except Exception as e:
            self.error_count += 1
            logger.error(f"Encryption failed for peer {peer_id}: {e}")
            logger.error(f"Plaintext length: {len(plaintext) if plaintext else 'None'}")
            raise

    def decrypt_data(self, peer_id: str, payload: bytes) -> bytes:
        """
        Decrypt and verify integrity of data from a peer.

        Expected format: iv (16) || ciphertext (variable) || hmac (32)
        """
        try:
            with self._lock:
                if peer_id not in self.session_keys:
                    raise ValueError(f"No session key for peer {peer_id}")

                aes_key, _, hmac_key = self.session_keys[peer_id]

            # Validate payload length
            if len(payload) < 48:  # 16 (IV) + 32 (HMAC) minimum
                raise ValueError(f"Payload too short: {len(payload)} bytes (minimum 48)")

            # Extract components
            iv = payload[:16]
            hmac_received = payload[-32:]
            ciphertext = payload[16:-32]

            # Verify HMAC
            payload_to_verify = payload[:-32]  # IV + ciphertext
            if not self._verify_hmac(hmac_key, payload_to_verify, hmac_received):
                raise ValueError("HMAC verification failed - data may be corrupted or tampered with")

            # Decrypt the data
            decryptor = self._get_cipher(aes_key, iv).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            self.decryption_count += 1

            logger.debug(
                f"Decrypted {len(payload)} bytes -> {len(plaintext)} bytes for peer {peer_id} "
                f"(IV: {iv.hex()[:8]}…)"
            )

            return plaintext

        except Exception as e:
            self.error_count += 1
            logger.error(f"Decryption failed for peer {peer_id}: {e}")
            logger.error(f"Payload length: {len(payload) if payload else 'None'}")
            if payload and len(payload) >= 16:
                logger.error(f"IV: {payload[:16].hex()}")
            if payload and len(payload) >= 32:
                logger.error(f"HMAC: {payload[-32:].hex()}")
            raise

    def get_crypto_stats(self) -> Dict[str, Any]:
        """Get encryption/decryption statistics for debugging."""
        return {
            "encryption_count": self.encryption_count,
            "decryption_count": self.decryption_count,
            "error_count": self.error_count,
            "active_sessions": len(self.session_keys),
            "peer_ids": list(self.session_keys.keys())
        }

    def reset_stats(self):
        """Reset statistics counters."""
        self.encryption_count = 0
        self.decryption_count = 0
        self.error_count = 0

    # Legacy compatibility methods
    def encrypt_chunk(self, peer_id: str, chunk: bytes) -> bytes:
        """Legacy alias for encrypt_data."""
        return self.encrypt_data(peer_id, chunk)

    def decrypt_chunk(self, peer_id: str, ciphertext: bytes) -> bytes:
        """Legacy alias for decrypt_data."""
        return self.decrypt_data(peer_id, ciphertext)

    def has_session_key(self, peer_id: str) -> bool:
        """Check if we have a session key for a peer."""
        with self._lock:
            return peer_id in self.session_keys

    def remove_peer_session(self, peer_id: str):
        """Remove session key for a peer."""
        with self._lock:
            if peer_id in self.session_keys:
                del self.session_keys[peer_id]
                logger.info(f"Removed session key for peer {peer_id}")