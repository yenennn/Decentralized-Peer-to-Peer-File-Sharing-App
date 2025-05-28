"""
Enhanced reliable UDP file transfer with custom reliable UDP implementation.
Uses a proven reliable protocol over your existing UDP socket infrastructure.
"""

from __future__ import annotations

import json
import logging
import math
import os
import threading
import time
import uuid
import struct
import hashlib
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple, Set, List
from collections import defaultdict, deque
import socket

logger = logging.getLogger(__name__)

# Message type constants
FILE_INIT = "file_init"
FILE_INIT_ACK = "file_init_ack"
FILE_CHUNK = "file_chunk"
CHUNK_ACK = "chunk_ack"
FILE_END = "file_end"
FILE_END_ACK = "file_end_ack"
RELIABLE_DATA = "reliable_data"
RELIABLE_ACK = "reliable_ack"


class ReliableUDPManager:
    """
    Simplified reliable UDP implementation with automatic retransmission and ordering.
    Much simpler than the original sliding window but still reliable.
    """

    def __init__(self, socket_obj, timeout: float = 2.0, max_retries: int = 5):
        self.socket = socket_obj
        self.timeout = timeout
        self.max_retries = max_retries
        self.sequence_number = 0
        self.expected_seq = {}  # peer_addr -> expected sequence number
        self.pending_acks = {}  # (peer_addr, seq) -> (data, timestamp, retries)
        self.received_messages = {}  # peer_addr -> {seq: data}
        self.lock = threading.Lock()
        self.running = True

        # Start ACK management thread
        self.ack_thread = threading.Thread(target=self._manage_acks, daemon=True)
        self.ack_thread.start()

    def send_reliable(self, data: bytes, peer_addr: Tuple[str, int]) -> bool:
        """Send data reliably with automatic retransmission"""
        with self.lock:
            seq = self.sequence_number
            self.sequence_number += 1

        # Create reliable message
        message = {
            "type": RELIABLE_DATA,
            "seq": seq,
            "data": data.hex(),  # Convert to hex for JSON safety
            "checksum": hashlib.md5(data).hexdigest()
        }

        message_data = json.dumps(message).encode()

        with self.lock:
            self.pending_acks[(peer_addr, seq)] = {
                "data": message_data,
                "timestamp": time.time(),
                "retries": 0
            }

        try:
            self.socket.sendto(message_data, peer_addr)
            logger.debug(f"Sent reliable message seq={seq} to {peer_addr}")
            return True
        except Exception as e:
            logger.error(f"Failed to send reliable message: {e}")
            with self.lock:
                if (peer_addr, seq) in self.pending_acks:
                    del self.pending_acks[(peer_addr, seq)]
            return False

    def handle_reliable_message(self, data: bytes, peer_addr: Tuple[str, int]) -> Optional[bytes]:
        """Handle incoming reliable messages and return payload if complete"""
        try:
            message = json.loads(data.decode())
        except Exception:
            return None

        msg_type = message.get("type")

        if msg_type == RELIABLE_DATA:
            seq = message.get("seq")
            payload_hex = message.get("data")
            checksum = message.get("checksum")

            if seq is None or payload_hex is None or checksum is None:
                return None

            # Convert hex back to bytes
            try:
                payload = bytes.fromhex(payload_hex)
            except ValueError:
                return None

            # Verify checksum
            if hashlib.md5(payload).hexdigest() != checksum:
                logger.warning(f"Checksum mismatch for seq={seq} from {peer_addr}")
                return None

            # Send ACK
            ack_message = {
                "type": RELIABLE_ACK,
                "seq": seq
            }
            try:
                self.socket.sendto(json.dumps(ack_message).encode(), peer_addr)
            except Exception as e:
                logger.error(f"Failed to send ACK: {e}")

            # Check if this is the expected sequence number
            with self.lock:
                expected = self.expected_seq.get(peer_addr, 0)

                if seq == expected:
                    # This is the next expected message
                    self.expected_seq[peer_addr] = expected + 1

                    # Store and check for any buffered messages we can now deliver
                    if peer_addr not in self.received_messages:
                        self.received_messages[peer_addr] = {}

                    result_payload = payload

                    # Check if we have subsequent messages buffered
                    next_seq = expected + 1
                    while next_seq in self.received_messages[peer_addr]:
                        del self.received_messages[peer_addr][next_seq]
                        next_seq += 1
                        self.expected_seq[peer_addr] = next_seq

                    return result_payload

                elif seq > expected:
                    # Future message - buffer it
                    if peer_addr not in self.received_messages:
                        self.received_messages[peer_addr] = {}
                    self.received_messages[peer_addr][seq] = payload
                    return None
                else:
                    # Old message - just ACK it but don't return data
                    return None

        elif msg_type == RELIABLE_ACK:
            seq = message.get("seq")
            if seq is not None:
                with self.lock:
                    if (peer_addr, seq) in self.pending_acks:
                        del self.pending_acks[(peer_addr, seq)]
                        logger.debug(f"Received ACK for seq={seq} from {peer_addr}")

        return None

    def _manage_acks(self):
        """Manage ACKs and retransmissions"""
        while self.running:
            current_time = time.time()
            to_retransmit = []
            to_remove = []

            with self.lock:
                for (peer_addr, seq), info in self.pending_acks.items():
                    if current_time - info["timestamp"] > self.timeout:
                        if info["retries"] < self.max_retries:
                            to_retransmit.append((peer_addr, seq, info))
                        else:
                            to_remove.append((peer_addr, seq))
                            logger.warning(f"Message seq={seq} to {peer_addr} failed after {self.max_retries} retries")

            # Retransmit messages
            for peer_addr, seq, info in to_retransmit:
                try:
                    self.socket.sendto(info["data"], peer_addr)
                    with self.lock:
                        if (peer_addr, seq) in self.pending_acks:
                            self.pending_acks[(peer_addr, seq)]["timestamp"] = current_time
                            self.pending_acks[(peer_addr, seq)]["retries"] += 1
                    logger.debug(f"Retransmitted seq={seq} to {peer_addr} (retry {info['retries'] + 1})")
                except Exception as e:
                    logger.error(f"Failed to retransmit to {peer_addr}: {e}")

            # Remove failed messages
            with self.lock:
                for key in to_remove:
                    if key in self.pending_acks:
                        del self.pending_acks[key]

            time.sleep(0.1)  # Check every 100ms

    def stop(self):
        """Stop the reliable UDP manager"""
        self.running = False

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about pending ACKs"""
        with self.lock:
            return {
                "pending_acks": len(self.pending_acks),
                "sequence_number": self.sequence_number,
                "peers_tracked": len(self.expected_seq)
            }


class FileTransfer:
    """Enhanced reliable file transfer using simplified reliable UDP"""

    # Configuration
    DEFAULT_CHUNK_SIZE = 32 * 1024  # 32 KiB
    RELIABLE_TIMEOUT = 2.0  # 2 seconds for reliable UDP
    MAX_RETRIES = 5
    PROGRESS_UPDATE_INTERVAL = 1.0

    def __init__(self, sock, crypto_manager):
        self.socket = sock
        self.crypto = crypto_manager
        self.lock = threading.Lock()
        self.transfers: Dict[str, Dict[str, Any]] = {}
        self.save_dir: Path = Path.cwd()
        self.progress_callback: Optional[Callable[[str, int, int], None]] = None

        # Initialize reliable UDP manager
        self.reliable_udp = ReliableUDPManager(sock, self.RELIABLE_TIMEOUT, self.MAX_RETRIES)

        # Message queues for different peers
        self.message_queues: Dict[str, deque] = defaultdict(deque)
        self.queue_lock = threading.Lock()

    def receive_file(self, save_dir: str, progress_callback: Callable[[str, int, int], None]):
        """Configure where incoming files are stored and how to report progress."""
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)
        self.progress_callback = progress_callback

    def send_file(self, file_path: str, peer_id: str, peer_addr: Tuple[str, int],
                  progress_callback: Callable[[str, int, int], None]) -> str:
        """Send a file to a peer using reliable UDP"""
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
                "status": "pending",
                "peer_addr": peer_addr,
                "peer_id": peer_id,
                "start_time": time.time(),
                "progress_cb": progress_callback,
            }

        # Start upload worker thread
        upload_thread = threading.Thread(
            target=self._reliable_upload_worker,
            args=(transfer_id,),
            daemon=True
        )
        upload_thread.start()
        return transfer_id

    def _reliable_upload_worker(self, transfer_id: str):
        """Upload worker using reliable UDP"""
        with self.lock:
            tf = self.transfers[transfer_id]

        peer_addr = tf["peer_addr"]
        peer_id = tf["peer_id"]

        try:
            # Send file initialization
            init_msg = {
                "type": FILE_INIT,
                "transfer_id": transfer_id,
                "file_name": tf["file_name"],
                "file_size": tf["file_size"],
                "chunk_size": self.DEFAULT_CHUNK_SIZE,
                "total_chunks": tf["total_chunks"],
            }

            init_data = json.dumps(init_msg).encode()
            if not self.reliable_udp.send_reliable(init_data, peer_addr):
                raise Exception("Failed to send file initialization")

            # Wait for acknowledgment with timeout
            ack_received = False
            timeout_start = time.time()
            while time.time() - timeout_start < 10.0:  # 10 second timeout
                with self.queue_lock:
                    if peer_id in self.message_queues and self.message_queues[peer_id]:
                        msg_data = self.message_queues[peer_id].popleft()
                        try:
                            msg = json.loads(msg_data.decode())
                            if (msg.get("type") == FILE_INIT_ACK and
                                msg.get("transfer_id") == transfer_id):
                                ack_received = True
                                break
                        except:
                            pass
                time.sleep(0.1)

            if not ack_received:
                raise Exception("No acknowledgment received for file init")

            with self.lock:
                tf["status"] = "uploading"

            # Send file chunks
            last_progress_update = time.time()

            with open(tf["file_path"], "rb") as file_handle:
                for chunk_index in range(tf["total_chunks"]):
                    # Read and encrypt chunk
                    chunk_data = file_handle.read(self.DEFAULT_CHUNK_SIZE)
                    if not chunk_data:
                        break

                    encrypted_data = self._encrypt(peer_id, chunk_data)

                    # Create chunk message
                    chunk_msg = {
                        "type": FILE_CHUNK,
                        "transfer_id": transfer_id,
                        "chunk_index": chunk_index,
                        "chunk_data": encrypted_data.hex(),  # Convert to hex for JSON
                        "total_chunks": tf["total_chunks"],
                    }

                    chunk_msg_data = json.dumps(chunk_msg).encode()

                    if not self.reliable_udp.send_reliable(chunk_msg_data, peer_addr):
                        raise Exception(f"Failed to send chunk {chunk_index}")

                    with self.lock:
                        tf["chunks_sent"] = chunk_index + 1

                    # Update progress
                    now = time.time()
                    if now - last_progress_update > self.PROGRESS_UPDATE_INTERVAL:
                        if tf["progress_cb"]:
                            tf["progress_cb"](transfer_id, chunk_index + 1, tf["total_chunks"])
                        last_progress_update = now

                    # Check for cancellation
                    with self.lock:
                        if tf["status"] == "cancelled":
                            raise Exception("Transfer cancelled")

            # Send completion message
            end_msg = {
                "type": FILE_END,
                "transfer_id": transfer_id,
            }
            end_data = json.dumps(end_msg).encode()
            if not self.reliable_udp.send_reliable(end_data, peer_addr):
                raise Exception("Failed to send completion message")

            with self.lock:
                tf["status"] = "completed"
                tf["end_time"] = time.time()
                duration = tf["end_time"] - tf["start_time"]
                speed = tf["file_size"] / duration / 1024 if duration > 0 else 0
                logger.info(f"Upload of {tf['file_name']} completed - {speed:.2f} KB/s")

        except Exception as e:
            logger.error(f"Upload failed for transfer {transfer_id}: {e}")
            with self.lock:
                tf["status"] = "failed"
                tf["error"] = str(e)

    def handle_message(self, data: bytes, addr: Tuple[str, int], peer_id: str):
        """Handle incoming messages through reliable UDP"""
        # First try to handle as reliable UDP message
        payload = self.reliable_udp.handle_reliable_message(data, addr)

        if payload:
            # Queue the payload for the peer
            with self.queue_lock:
                self.message_queues[peer_id].append(payload)

            # Try to process as file transfer message
            try:
                msg = json.loads(payload.decode())
                mtype = msg.get("type")

                if mtype == FILE_INIT:
                    self._handle_file_init(msg, addr, peer_id)
                elif mtype == FILE_CHUNK:
                    self._handle_file_chunk(msg, addr, peer_id)
                elif mtype == FILE_END:
                    self._handle_file_end(msg, addr, peer_id)

            except Exception as e:
                logger.debug(f"Could not process as file transfer message: {e}")
        else:
            # Try to handle as regular JSON message (non-reliable)
            try:
                msg = json.loads(data.decode())
                mtype = msg.get("type")

                if mtype == FILE_INIT:
                    self._handle_file_init(msg, addr, peer_id)

            except Exception:
                logger.debug("Could not process message")

    def _handle_file_init(self, msg: Dict[str, Any], addr: Tuple[str, int], peer_id: str):
        """Handle file initialization"""
        transfer_id = msg["transfer_id"]

        with self.lock:
            if transfer_id in self.transfers:
                return  # Already handling this transfer

            self.transfers[transfer_id] = {
                "direction": "in",
                "file_name": msg["file_name"],
                "file_size": msg["file_size"],
                "chunk_size": msg["chunk_size"],
                "total_chunks": msg["total_chunks"],
                "chunks_received": 0,
                "received_chunks": {},  # chunk_index -> data
                "status": "receiving",
                "peer_addr": addr,
                "peer_id": peer_id,
                "start_time": time.time(),
            }

        logger.info(f"Incoming file {msg['file_name']} ({msg['file_size']} bytes) from {peer_id}")

        # Send acknowledgment
        ack_msg = {"type": FILE_INIT_ACK, "transfer_id": transfer_id}
        ack_data = json.dumps(ack_msg).encode()
        self.reliable_udp.send_reliable(ack_data, addr)

        # Start download worker
        download_thread = threading.Thread(
            target=self._reliable_download_worker,
            args=(transfer_id,),
            daemon=True
        )
        download_thread.start()

    def _handle_file_chunk(self, msg: Dict[str, Any], addr: Tuple[str, int], peer_id: str):
        """Handle file chunk"""
        transfer_id = msg["transfer_id"]
        chunk_index = msg["chunk_index"]
        chunk_data_hex = msg["chunk_data"]

        with self.lock:
            tf = self.transfers.get(transfer_id)
            if not tf or tf["direction"] != "in":
                return

            # Convert hex back to bytes and decrypt
            try:
                encrypted_data = bytes.fromhex(chunk_data_hex)
                chunk_data = self._decrypt(peer_id, encrypted_data)
                tf["received_chunks"][chunk_index] = chunk_data
                logger.debug(f"Received chunk {chunk_index + 1}/{tf['total_chunks']} for {transfer_id}")
            except Exception as e:
                logger.error(f"Failed to process chunk {chunk_index}: {e}")

    def _handle_file_end(self, msg: Dict[str, Any], addr: Tuple[str, int], peer_id: str):
        """Handle file end"""
        transfer_id = msg["transfer_id"]

        with self.lock:
            tf = self.transfers.get(transfer_id)
            if tf and tf["direction"] == "in":
                tf["end_received"] = True

    def _reliable_download_worker(self, transfer_id: str):
        """Download worker that processes queued messages"""
        with self.lock:
            tf = self.transfers[transfer_id]

        peer_id = tf["peer_id"]
        last_progress_update = time.time()

        try:
            # Open file for writing
            dest_path = self.save_dir / tf["file_name"]

            # Wait for all chunks or end signal
            while True:
                with self.lock:
                    # Check if we have all chunks
                    if len(tf["received_chunks"]) >= tf["total_chunks"]:
                        break

                    # Check if end was received
                    if tf.get("end_received"):
                        break

                    # Check for timeout or failure
                    if time.time() - tf["start_time"] > 300:  # 5 minute timeout
                        raise Exception("Transfer timeout")

                # Process any queued messages for this peer
                with self.queue_lock:
                    if peer_id in self.message_queues:
                        while self.message_queues[peer_id]:
                            msg_data = self.message_queues[peer_id].popleft()
                            try:
                                msg = json.loads(msg_data.decode())
                                if msg.get("transfer_id") == transfer_id:
                                    if msg.get("type") == FILE_CHUNK:
                                        self._handle_file_chunk(msg, tf["peer_addr"], peer_id)
                                    elif msg.get("type") == FILE_END:
                                        self._handle_file_end(msg, tf["peer_addr"], peer_id)
                            except:
                                pass

                # Update progress
                now = time.time()
                if now - last_progress_update > self.PROGRESS_UPDATE_INTERVAL:
                    with self.lock:
                        if self.progress_callback:
                            self.progress_callback(transfer_id, len(tf["received_chunks"]), tf["total_chunks"])
                    last_progress_update = now

                time.sleep(0.1)

            # Write file in order
            with open(dest_path, "wb") as file_handle:
                with self.lock:
                    for i in range(tf["total_chunks"]):
                        if i in tf["received_chunks"]:
                            file_handle.write(tf["received_chunks"][i])
                        else:
                            raise Exception(f"Missing chunk {i}")

            with self.lock:
                tf["status"] = "completed"
                tf["end_time"] = time.time()
                duration = tf["end_time"] - tf["start_time"]
                speed = tf["file_size"] / duration / 1024 if duration > 0 else 0
                logger.info(f"Download of {tf['file_name']} completed - {speed:.2f} KB/s")

        except Exception as e:
            logger.error(f"Download failed for transfer {transfer_id}: {e}")
            with self.lock:
                tf["status"] = "failed"
                tf["error"] = str(e)

    def stop(self):
        """Stop the file transfer manager"""
        if hasattr(self, 'reliable_udp'):
            self.reliable_udp.stop()

    def cancel_transfer(self, transfer_id: str) -> bool:
        """Cancel an ongoing transfer"""
        with self.lock:
            if transfer_id in self.transfers:
                tf = self.transfers[transfer_id]
                if tf["status"] in ["pending", "uploading", "receiving"]:
                    tf["status"] = "cancelled"
                    logger.info(f"Transfer {transfer_id} cancelled")
                    return True
        return False

    # Utility methods
    def _encrypt(self, peer_id: str, plaintext: bytes) -> bytes:
        """Encrypt data using crypto manager"""
        if hasattr(self.crypto, "encrypt_data"):
            return self.crypto.encrypt_data(peer_id, plaintext)
        return plaintext

    def _decrypt(self, peer_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data using crypto manager"""
        if hasattr(self.crypto, "decrypt_data"):
            return self.crypto.decrypt_data(peer_id, ciphertext)
        return ciphertext

    # Legacy compatibility methods
    def handle_binary_data(self, *args):
        """Legacy method for binary data handling"""
        pass

    def _handle_file_chunk(self, *args):
        """Legacy method - now handled by new system"""
        pass

    def _process_chunk(self, *args):
        """Legacy method - now handled by new system"""
        pass

    def get_transfer_status(self, transfer_id: str) -> Dict:
        """Get transfer status - compatible with existing API"""
        with self.lock:
            if transfer_id not in self.transfers:
                return {'status': 'unknown'}

            tf = self.transfers[transfer_id]

            if tf["direction"] == "out":
                completed = tf["chunks_sent"]
            else:
                completed = len(tf.get("received_chunks", {}))

            total = tf["total_chunks"]
            progress = (completed / total * 100) if total > 0 else 0

            result = {
                'transfer_id': transfer_id,
                'file_name': tf['file_name'],
                'file_size': tf['file_size'],
                'status': tf['status'],
                'progress': progress,
            }

            if tf['status'] == 'completed' and 'end_time' in tf:
                duration = tf['end_time'] - tf['start_time']
                result['speed'] = tf['file_size'] / duration / 1024 if duration > 0 else 0

            return result