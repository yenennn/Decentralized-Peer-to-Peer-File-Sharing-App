"""
file_transfer.py – Reliable UDP file‑sharing logic for the demo P2P application
-------------------------------------------------------------------------
This module adds a reliability layer on top of UDP so that large files can be
transferred end‑to‑end without corruption or loss.  Core features:

*   **Handshake** – `file_init` / `file_init_ack` announces an incoming file.
*   **Chunking** – files are split into fixed‑size chunks (default 32 KiB).
*   **Per‑chunk ACKs & retries** – every chunk must be acknowledged by the
    receiver (`chunk_ack`).  Un‑ACKed chunks are resent until success or
    `MAX_RETRIES` is exceeded.
*   **Completion handshake** – `file_end` / `file_end_ack` guarantees both
    sides agree the transfer is finished.
*   **Progress callback** – the parent `P2PNode` can display live progress for
    both uploads and downloads.
*   **Thread‑safe** – all shared state is protected by a `threading.Lock`.
*   **Optional AES session encryption** – if `CryptoManager` implements
    `encrypt_data(peer_id, data)` / `decrypt_data(peer_id, data)` they are used
    transparently; otherwise data is sent in plaintext.

Drop the file into the project root and import it from `p2p_node.py` (already
present in the user’s skeleton).
"""

from __future__ import annotations

import json
import hashlib
import logging
import math
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Message type constants – shared by both peers
# ---------------------------------------------------------------------------
FILE_INIT = "file_init"
FILE_INIT_ACK = "file_init_ack"
FILE_CHUNK = "file_chunk"          # JSON header (no binary payload)
CHUNK_ACK = "chunk_ack"
FILE_END = "file_end"
FILE_END_ACK = "file_end_ack"
CHUNK_NAK = "chunk_nak"


class FileTransfer:
    """Adds reliable file‑transfer semantics on top of an existing UDP socket."""

    # Reasonably small so header+payload < 65 507 bytes (maximum UDP datagram)
    DEFAULT_CHUNK_SIZE = 32 * 1024  # 32 KiB
    ACK_TIMEOUT = 2.0               # seconds to wait before resending
    MAX_RETRIES = 5                 # per‑chunk resend attempts

    def __init__(self, sock, crypto_manager):
        self.socket = sock
        self.crypto = crypto_manager
        self.lock = threading.Lock()
        self.transfers: Dict[str, Dict[str, Any]] = {}
        self.save_dir: Path = Path.cwd()
        self.progress_callback: Optional[Callable[[str, int, int], None]] = None

    # ---------------------------------------------------------------------
    # Public helpers used by the parent P2PNode
    # ---------------------------------------------------------------------

    def receive_file(self, save_dir: str, progress_callback: Callable[[str, int, int], None]):
        """Configure where incoming files are stored and how to report progress."""
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)
        self.progress_callback = progress_callback

    # P2PNode calls this when the user wishes to send a file ----------------
    def send_file(self, file_path: str, peer_id: str, peer_addr: Tuple[str, int],
                  progress_callback: Callable[[str, int, int], None]) -> str:
        file_path = str(file_path)
        if not os.path.isfile(file_path):
            raise FileNotFoundError(file_path)

        transfer_id = str(uuid.uuid4())
        file_size = os.path.getsize(file_path)
        total_chunks = math.ceil(file_size / self.DEFAULT_CHUNK_SIZE)

        with self.lock:
            self.transfers[transfer_id] = {
                "direction": "out",
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_size": file_size,
                "total_chunks": total_chunks,
                "chunks_sent": 0,
                "chunks_acked": 0,
                "status": "pending",
                "peer_addr": peer_addr,
                "peer_id": peer_id,
                "ack_events": {},       # chunk_index -> threading.Event
                "start_time": time.time(),
                "progress_cb": progress_callback,
            }

        # Handshake – announce the file first --------------------------------
        init_msg = {
            "type": FILE_INIT,
            "transfer_id": transfer_id,
            "file_name": os.path.basename(file_path),
            "file_size": file_size,
            "chunk_size": self.DEFAULT_CHUNK_SIZE,
            "total_chunks": total_chunks,
        }
        self._send_json(init_msg, peer_addr)

        # Upload thread – runs independently of P2PNode’s main loop ----------
        t = threading.Thread(target=self._upload_worker, args=(transfer_id,), daemon=True)
        t.start()
        return transfer_id

    # P2PNode delegates raw JSON messages here (except FILE_CHUNK header, see below)
    def handle_message(self, data: bytes, addr: Tuple[str, int], peer_id: str):
        try:
            msg = json.loads(data.decode())
        except Exception:
            logger.debug("handle_message: not JSON - ignoring")
            return

        mtype = msg.get("type")
        if mtype == FILE_INIT:
            self._handle_file_init(msg, addr, peer_id)
        elif mtype == FILE_INIT_ACK:
            self._handle_file_init_ack(msg)
        elif mtype == CHUNK_ACK:
            self._handle_chunk_ack(msg)
        elif mtype == CHUNK_NAK:  # Add handler for NAK messages
            self._handle_chunk_nak(msg)
        elif mtype == FILE_END:
            self._handle_file_end(msg, addr)
        elif mtype == FILE_END_ACK:
            self._handle_file_end_ack(msg)
        # (FILE_CHUNK header handled separately by P2PNode → _handle_file_chunk)

    def handle_binary_data(self, *_):
        """Binary datagrams that arrive outside the expected flow are ignored."""
        logger.debug("Received stray binary data – dropping")

    # ---------------------------------------------------------------------
    # Called by P2PNode for *incoming* data path
    # ---------------------------------------------------------------------

    def _handle_file_chunk(self, header: Dict[str, Any], addr: Tuple[str, int], peer_id: str):
        """Store header so the subsequent binary payload can be matched."""
        transfer_id = header["transfer_id"]
        chunk_index = header["chunk_index"]
        with self.lock:
            tf = self.transfers.get(transfer_id)
            if not tf:
                logger.warning(f"Chunk header for unknown transfer {transfer_id}")
                return
            tf["expected_chunk_index"] = chunk_index
            tf["expected_chunk_size"] = header["chunk_size"]
            tf["expected_checksum"] = header.get("checksum", "")  # Store expected checksum
            # actual data arrives via _process_chunk()

    def _handle_chunk_nak(self, msg: Dict[str, Any]):
        """Handle negative acknowledgment for a chunk with bad checksum."""
        transfer_id = msg["transfer_id"]
        chunk_index = msg["chunk_index"]
        with self.lock:
            tf = self.transfers.get(transfer_id)
            if tf and tf["direction"] == "out":
                ev = tf["ack_events"].get(chunk_index)
                if ev and not ev.is_set():
                    tf["current_chunk_status"]["nak"] = True
                    ev.set()

    def _process_chunk(self, transfer_id: str, chunk_index: int, peer_id: str,
                       addr: Tuple[str, int], data: bytes) -> bool:
        """Decrypt & write the chunk, then ACK it back to the sender."""
        with self.lock:
            tf = self.transfers.get(transfer_id)
            if not tf or tf["direction"] != "in":
                logger.warning(f"Data chunk for unknown or outbound transfer {transfer_id}")
                return False

            # Verify checksum
            received_checksum = hashlib.md5(data).hexdigest()
            expected_checksum = tf.get("expected_checksum", "")

            if received_checksum != expected_checksum:
                # Checksum mismatch - send NAK
                logger.warning(f"Checksum mismatch for chunk {chunk_index} (transfer {transfer_id})")
                nak_msg = {
                    "type": CHUNK_NAK,
                    "transfer_id": transfer_id,
                    "chunk_index": chunk_index
                }
                self._send_json(nak_msg, addr)
                return False  # Return False for checksum mismatch

            try:
                plaintext = self._decrypt(peer_id, data)
            except Exception as exc:
                logger.error(f"Decryption failed - aborting transfer {transfer_id}: {exc}")
                tf["status"] = "failed"
                return False

            # Lazy-open file handle on first chunk
            if "file_handle" not in tf:
                dest = self.save_dir / tf["file_name"]
                tf["dest_path"] = dest
                tf["file_handle"] = dest.open("wb")

            fh = tf["file_handle"]
            fh.write(plaintext)
            fh.flush()

            tf["chunks_received"] = tf.get("chunks_received", 0) + 1
            if self.progress_callback:
                self.progress_callback(transfer_id, tf["chunks_received"], tf["total_chunks"])

            # ACK back to sender
            ack_msg = {"type": CHUNK_ACK, "transfer_id": transfer_id, "chunk_index": chunk_index}
            self._send_json(ack_msg, addr)

            # Done?
            if tf["chunks_received"] >= tf["total_chunks"]:
                tf["file_handle"].close()
                tf["status"] = "completed"
                tf["end_time"] = time.time()
                # Let sender know everything arrived OK
                end_ack = {"type": FILE_END_ACK, "transfer_id": transfer_id}
                self._send_json(end_ack, addr)
                logger.info(f"Completed download of {tf['file_name']} ({transfer_id})")

            return True  # Return True for successful processing
    # ---------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------

    def _upload_worker(self, transfer_id: str):
        with self.lock:
            tf = self.transfers[transfer_id]
        path = tf["file_path"]
        peer_addr = tf["peer_addr"]
        total_chunks = tf["total_chunks"]
        retries: Dict[int, int] = {i: 0 for i in range(total_chunks)}

        # Wait for FILE_INIT_ACK before sending chunks
        while True:
            with self.lock:
                if tf.get("init_acked") or tf["status"] == "failed":
                    break
            time.sleep(0.2)

        if tf["status"] == "failed":
            return

        # Send chunks sequentially with checksum verification
        with open(path, "rb") as fh:
            chunk_index = 0
            while chunk_index < total_chunks:
                # Position file pointer at the correct chunk
                fh.seek(chunk_index * self.DEFAULT_CHUNK_SIZE)

                # Read & (optionally) encrypt
                data = fh.read(self.DEFAULT_CHUNK_SIZE)
                ciphertext = self._encrypt(tf["peer_id"], data)

                # Calculate checksum of encrypted data
                checksum = hashlib.md5(ciphertext).hexdigest()

                header = {
                    "type": FILE_CHUNK,
                    "transfer_id": transfer_id,
                    "chunk_index": chunk_index,
                    "chunk_size": len(ciphertext),
                    "total_chunks": total_chunks,
                    "checksum": checksum  # Add checksum to header
                }

                # Retry loop - continues until success or max retries
                success = False
                while retries[chunk_index] < self.MAX_RETRIES and not success:
                    ack_event = threading.Event()
                    with self.lock:
                        tf["ack_events"][chunk_index] = ack_event
                        tf["current_chunk_status"] = {"acked": False, "nak": False}  # Reset status for each attempt

                    # Header then binary payload
                    self._send_json(header, peer_addr)
                    self.socket.sendto(ciphertext, peer_addr)
                    logger.debug(
                        f"Sent chunk {chunk_index + 1}/{total_chunks} for {transfer_id} (checksum: {checksum})")

                    # Wait for ACK/NAK response
                    if ack_event.wait(self.ACK_TIMEOUT):
                        # Check if it was a NAK or an ACK
                        with self.lock:
                            if tf["current_chunk_status"]["nak"]:
                                # Checksum failed at receiver, retry
                                logger.warning(f"Checksum mismatch for chunk {chunk_index} - retransmitting")
                                retries[chunk_index] += 1
                                continue
                            else:
                                # Success - mark chunk successful
                                success = True
                                tf["chunks_sent"] += 1
                                if tf["progress_cb"]:
                                    tf["progress_cb"](transfer_id, tf["chunks_sent"], total_chunks)

                    else:
                        # Timeout - retry
                        retries[chunk_index] += 1
                        logger.warning(
                            f"Resending chunk {chunk_index} (attempt {retries[chunk_index] + 1}) for {transfer_id}")

                if not success:  # exceeded retries
                    logger.error(f"Transfer {transfer_id} failed - giving up on chunk {chunk_index}")
                    with self.lock:
                        tf["status"] = "failed"
                    return

                # Move to next chunk only after current chunk succeeded
                chunk_index += 1

        # All chunks ACKed - send FILE_END
        self._send_json({"type": FILE_END, "transfer_id": transfer_id}, peer_addr)

        # Wait for FILE_END_ACK
        end_deadline = time.time() + self.ACK_TIMEOUT * self.MAX_RETRIES
        while time.time() < end_deadline:
            with self.lock:
                if tf.get("end_acked"):
                    break
            time.sleep(0.25)

        with self.lock:
            if tf.get("end_acked"):
                tf["status"] = "completed"
                tf["end_time"] = time.time()
                dur = tf["end_time"] - tf["start_time"]
                speed = tf["file_size"] / dur / 1024 if dur else 0
                logger.info("Upload of %s completed – %.2f KB/s", tf["file_name"], speed)
            else:
                tf["status"] = "failed"
                logger.error("Transfer %s failed – no FILE_END_ACK", transfer_id)

    # ------------------------- inbound JSON handlers ------------------------
    def _handle_file_init(self, msg: Dict[str, Any], addr: Tuple[str, int], peer_id: str):
        transfer_id = msg["transfer_id"]
        with self.lock:
            if transfer_id in self.transfers:
                logger.debug("FILE_INIT dup for %s – ignoring", transfer_id)
                return
            self.transfers[transfer_id] = {
                "direction": "in",
                "file_name": msg["file_name"],
                "file_size": msg["file_size"],
                "chunk_size": msg["chunk_size"],
                "total_chunks": msg["total_chunks"],
                "chunks_received": 0,
                "status": "receiving",
                "peer_addr": addr,
                "peer_id": peer_id,
                "start_time": time.time(),
            }
        # ACK immediately so sender can start
        ack = {"type": FILE_INIT_ACK, "transfer_id": transfer_id}
        self._send_json(ack, addr)
        logger.info("Incoming file %s (%s bytes) from %s", msg["file_name"], msg["file_size"], peer_id)

    def _handle_file_init_ack(self, msg: Dict[str, Any]):
        transfer_id = msg["transfer_id"]
        with self.lock:
            tf = self.transfers.get(transfer_id)
            if tf and tf["direction"] == "out":
                tf["init_acked"] = True

    def _handle_chunk_ack(self, msg: Dict[str, Any]):
        transfer_id = msg["transfer_id"]
        chunk_index = msg["chunk_index"]
        with self.lock:
            tf = self.transfers.get(transfer_id)
            if tf and tf["direction"] == "out":
                ev = tf["ack_events"].get(chunk_index)
                if ev and not ev.is_set():
                    ev.set()

    def _handle_file_end(self, msg: Dict[str, Any], addr: Tuple[str, int]):
        # Sender thinks it’s done; reply with ACK so it can mark complete
        transfer_id = msg["transfer_id"]
        self._send_json({"type": FILE_END_ACK, "transfer_id": transfer_id}, addr)
        logger.debug("FILE_END received for %s – ACK sent", transfer_id)

    def _handle_file_end_ack(self, msg: Dict[str, Any]):
        transfer_id = msg["transfer_id"]
        with self.lock:
            tf = self.transfers.get(transfer_id)
            if tf and tf["direction"] == "out":
                tf["end_acked"] = True

    # ---------------------------------------------------------------------
    # Utility wrappers
    # ---------------------------------------------------------------------

    def _send_json(self, obj: Dict[str, Any], addr: Tuple[str, int]):
        try:
            self.socket.sendto(json.dumps(obj).encode(), addr)
        except Exception as exc:
            logger.error("UDP send failed: %s", exc)

    def _encrypt(self, peer_id: str, plaintext: bytes) -> bytes:
        if hasattr(self.crypto, "encrypt_data"):
            return self.crypto.encrypt_data(peer_id, plaintext)
        return plaintext

    def _decrypt(self, peer_id: str, ciphertext: bytes) -> bytes:
        if hasattr(self.crypto, "decrypt_data"):
            return self.crypto.decrypt_data(peer_id, ciphertext)
        return ciphertext