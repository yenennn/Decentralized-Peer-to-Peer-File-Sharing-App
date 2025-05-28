"""
Backward-compatible crypto.py with improved error handling
---------------------------------------------------------
Maintains the same API as your original crypto but with better error handling.
"""

import os
import logging
import threading
from typing import Tuple, Dict, Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)


class CryptoManager:
    """Manages RSA key exchange and AES session encryption for each peer."""

    def __init__(self):
        # Thread lock for session key operations
        self._lock = threading.RLock()

        # RSA key‑pair (persistent for the whole runtime of the node)
        logger.info("Generating RSA-2048 key pair...")
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend(),
            )
            self.public_key = self.private_key.public_key()
            logger.info("RSA key pair generated successfully")
        except Exception as e:
            logger.error(f"Failed to generate RSA key pair: {e}")
            raise

        # peer_id -> (aes_key: bytes, base_iv: bytes)
        self.session_keys: Dict[str, Tuple[bytes, bytes]] = {}

        # Statistics for debugging
        self.encryption_count = 0
        self.decryption_count = 0
        self.error_count = 0

    def get_public_key_pem(self) -> bytes:
        try:
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception as e:
            logger.error(f"Failed to export public key: {e}")
            raise

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
    def generate_session_key() -> Tuple[bytes, bytes]:
        """Return a fresh (key, iv) pair for AES‑256."""
        try:
            key = os.urandom(32)  # 256-bit AES key
            iv = os.urandom(16)   # 128-bit IV
            logger.debug(f"Generated session key: {key.hex()[:8]}... IV: {iv.hex()[:8]}...")
            return key, iv
        except Exception as e:
            logger.error(f"Failed to generate session key: {e}")
            raise

    @staticmethod
    def encrypt_session_key(peer_public_key, session_key: bytes, iv: bytes) -> bytes:
        try:
            package = session_key + iv
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

    def decrypt_session_key(self, encrypted_package: bytes) -> Tuple[bytes, bytes]:
        try:
            package = self.private_key.decrypt(
                encrypted_package,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            if len(package) != 48:  # 32 + 16
                raise ValueError(f"Invalid session key package length: {len(package)}")

            key = package[:32]
            iv = package[32:48]

            logger.debug("Successfully decrypted session key package")
            return key, iv

        except Exception as e:
            logger.error(f"Failed to decrypt session key: {e}")
            raise

    def store_peer_session_key(self, peer_id: str, key: bytes, iv: bytes):
        """Store session key for a peer with thread safety."""
        try:
            with self._lock:
                self.session_keys[peer_id] = (key, iv)
                logger.info(
                    "Stored session key for %s: %s…  IV %s…",
                    peer_id,
                    key.hex()[:8],
                    iv.hex()[:8],
                )
        except Exception as e:
            logger.error(f"Failed to store session key for peer {peer_id}: {e}")
            raise

    def _get_cipher(self, key: bytes, iv: bytes):
        """AES‑CFB gives us a stream cipher with block size 16 bytes, no padding."""
        try:
            return Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        except Exception as e:
            logger.error(f"Failed to create cipher: {e}")
            raise

    def encrypt_data(self, peer_id: str, plaintext: bytes) -> bytes:
        """
        Encrypt arbitrary bytes for a given peer.

        A new random IV is generated *per payload* and prepended so the receiver
        can decrypt.  Returns: iv || ciphertext (concatenated bytes).
        """
        try:
            with self._lock:
                if peer_id not in self.session_keys:
                    available_peers = list(self.session_keys.keys())
                    logger.error(f"No session key for peer {peer_id}. Available peers: {available_peers}")
                    raise ValueError(f"No session key for peer {peer_id}")

                key, _ = self.session_keys[peer_id]

            # Generate fresh IV for each encryption
            iv = os.urandom(16)
            encryptor = self._get_cipher(key, iv).encryptor()
            ct = encryptor.update(plaintext) + encryptor.finalize()

            result = iv + ct
            self.encryption_count += 1

            logger.debug(f"Encrypted {len(plaintext)} bytes -> {len(result)} bytes for peer {peer_id}")
            return result

        except Exception as e:
            self.error_count += 1
            logger.error(f"Encryption failed for peer {peer_id}: {e}")
            logger.error(f"Plaintext length: {len(plaintext) if plaintext else 'None'}")
            raise

    def decrypt_data(self, peer_id: str, payload: bytes) -> bytes:
        try:
            with self._lock:
                if peer_id not in self.session_keys:
                    available_peers = list(self.session_keys.keys())
                    logger.error(f"No session key for peer {peer_id}. Available peers: {available_peers}")
                    raise ValueError(f"No session key for peer {peer_id}")

                key, _ = self.session_keys[peer_id]

            if len(payload) < 16:
                raise ValueError(f"Payload too short – no IV (length: {len(payload)})")

            iv, ct = payload[:16], payload[16:]
            decryptor = self._get_cipher(key, iv).decryptor()
            plaintext = decryptor.update(ct) + decryptor.finalize()

            self.decryption_count += 1

            logger.debug(f"Decrypted {len(payload)} bytes -> {len(plaintext)} bytes for peer {peer_id}")
            return plaintext

        except Exception as e:
            self.error_count += 1
            logger.error(f"Decryption failed for peer {peer_id}: {e}")
            logger.error(f"Payload length: {len(payload) if payload else 'None'}")
            raise

    def has_session_key(self, peer_id: str) -> bool:
        """Check if we have a session key for a peer."""
        with self._lock:
            return peer_id in self.session_keys

    def get_session_keys_debug(self) -> Dict[str, str]:
        """Get debug info about session keys."""
        with self._lock:
            return {
                peer_id: f"Key: {key.hex()[:8]}... IV: {iv.hex()[:8]}..."
                for peer_id, (key, iv) in self.session_keys.items()
            }

    def get_crypto_stats(self) -> Dict[str, Any]:
        """Get encryption/decryption statistics for debugging."""
        return {
            "encryption_count": self.encryption_count,
            "decryption_count": self.decryption_count,
            "error_count": self.error_count,
            "active_sessions": len(self.session_keys),
            "peer_ids": list(self.session_keys.keys())
        }

    # Legacy compatibility methods
    def encrypt_chunk(self, peer_id: str, chunk: bytes) -> bytes:
        """Legacy alias for encrypt_data."""
        return self.encrypt_data(peer_id, chunk)

    def decrypt_chunk(self, peer_id: str, ciphertext: bytes) -> bytes:
        """Legacy alias for decrypt_data."""
        return self.decrypt_data(peer_id, ciphertext)