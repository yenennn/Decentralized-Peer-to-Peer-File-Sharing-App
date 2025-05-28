"""
crypto.py – finished implementation of the CryptoManager class
--------------------------------------------------------------
•  RSA‑2048 for asymmetric key exchange
•  AES‑256‑CFB with fresh random IV per message/chunk for bulk encryption
•  Simple helper wrappers (`encrypt_data` / `decrypt_data`) used by
   *file_transfer.py* so the whole stack stays plug‑and‑play.

**Security notes**
------------------
*   A new 16‑byte IV is prepended to every encrypted payload.  CFB mode does not
    require padding and keeps ciphertext the same size as plaintext + IV.
*   IV reuse is avoided – critical for stream modes.
*   Session keys are generated with `os.urandom(32)` (true crypto RNG).
*   The logger only prints the first 8 hex chars of keys/IVs so you can debug
    without leaking full secrets.
"""

import os
import logging
from typing import Tuple, Dict, Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)


class CryptoManager:
    """Manages RSA key exchange and AES session encryption for each peer."""

    def __init__(self):
        # ------------------------------------------------------------------
        # RSA key‑pair (persistent for the whole runtime of the node)
        # ------------------------------------------------------------------
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        self.public_key = self.private_key.public_key()

        # peer_id -> (aes_key: bytes, base_iv: bytes)
        self.session_keys: Dict[str, Tuple[bytes, bytes]] = {}

    # ----------------------------------------------------------------------
    # RSA helpers – these run during the handshake (see P2PNode._send_session_key)
    # ----------------------------------------------------------------------
    def get_public_key_pem(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def load_peer_public_key(self, peer_public_key_pem: bytes):
        return serialization.load_pem_public_key(
            peer_public_key_pem,
            backend=default_backend(),
        )

    @staticmethod
    def generate_session_key() -> Tuple[bytes, bytes]:
        """Return a fresh (key, iv) pair for AES‑256."""
        return os.urandom(32), os.urandom(16)

    @staticmethod
    def encrypt_session_key(peer_public_key, session_key: bytes, iv: bytes) -> bytes:
        package = session_key + iv
        return peer_public_key.encrypt(
            package,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def decrypt_session_key(self, encrypted_package: bytes) -> Tuple[bytes, bytes]:
        package = self.private_key.decrypt(
            encrypted_package,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return package[:32], package[32:]

    def store_peer_session_key(self, peer_id: str, key: bytes, iv: bytes):
        self.session_keys[peer_id] = (key, iv)
        logger.info(
            "Stored session key for %s: %s…  IV %s…",
            peer_id,
            key.hex()[:8],
            iv.hex()[:8],
        )

    # ----------------------------------------------------------------------
    # Symmetric crypto helpers – invoked per message or file chunk
    # ----------------------------------------------------------------------
    def _get_cipher(self, key: bytes, iv: bytes):
        # AES‑CFB gives us a stream cipher with block size 16 bytes, no padding.
        return Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    # The following two are the only methods used by file_transfer.py --------
    def encrypt_data(self, peer_id: str, plaintext: bytes) -> bytes:
        """Encrypt arbitrary bytes for a given peer.

        A new random IV is generated *per payload* and prepended so the receiver
        can decrypt.  Returns: iv || ciphertext (concatenated bytes).
        """
        if peer_id not in self.session_keys:
            raise ValueError(f"No session key for peer {peer_id}")

        key, _ = self.session_keys[peer_id]
        iv = os.urandom(16)
        encryptor = self._get_cipher(key, iv).encryptor()
        ct = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ct

    def decrypt_data(self, peer_id: str, payload: bytes) -> bytes:
        if peer_id not in self.session_keys:
            raise ValueError(f"No session key for peer {peer_id}")

        key, _ = self.session_keys[peer_id]
        if len(payload) < 16:
            raise ValueError("Payload too short – no IV")
        iv, ct = payload[:16], payload[16:]
        decryptor = self._get_cipher(key, iv).decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    # ----------------------------------------------------------------------
    # Legacy chunk‑based API (kept for compatibility with old code)
    # ----------------------------------------------------------------------
    def encrypt_chunk(self, peer_id: str, chunk: bytes) -> bytes:  # alias
        return self.encrypt_data(peer_id, chunk)

    def decrypt_chunk(self, peer_id: str, ciphertext: bytes) -> bytes:  # alias
        return self.decrypt_data(peer_id, ciphertext)
