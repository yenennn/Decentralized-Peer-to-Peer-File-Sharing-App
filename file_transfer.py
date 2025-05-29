"""
Enhanced reliable UDP file transfer with sliding window protocol and selective repeat.
Based on the reference implementation but adapted for the P2P system.
"""

from __future__ import annotations

import json
import logging
import math
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple, Set, List
from collections import defaultdict
import bisect

logger = logging.getLogger(__name__)

# Message type constants
FILE_INIT = "file_init"
FILE_INIT_ACK = "file_init_ack"
FILE_CHUNK = "file_chunk"
CHUNK_ACK = "chunk_ack"
FILE_END = "file_end"
FILE_END_ACK = "file_end_ack"
WINDOW_ACK = "window_ack"  # New: Acknowledge entire window
SELECTIVE_NACK = "selective_nack"  # New: Request specific missing chunks


class SlidingWindow:
    """Manages sliding window for reliable transmission"""

    def __init__(self, window_size: int):
        self.window_size = window_size
        self.base = 0  # First unacknowledged packet
        self.next_seq = 0  # Next packet to send
        self.acked: Set[int] = set()  # Acknowledged packets
        self.sent_time: Dict[int, float] = {}  # When each packet was sent
        self.retry_count: Dict[int, int] = defaultdict(int)

    def can_send(self) -> bool:
        """Check if we can send more packets"""
        return self.next_seq < self.base + self.window_size

    def mark_sent(self, seq_num: int):
        """Mark a packet as sent"""
        self.sent_time[seq_num] = time.time()
        if seq_num >= self.next_seq:
            self.next_seq = seq_num + 1

    def mark_acked(self, seq_num: int):
        """Mark a packet as acknowledged"""
        self.acked.add(seq_num)
        # Slide window if possible
        while self.base in self.acked:
            self.acked.remove(self.base)
            if self.base in self.sent_time:
                del self.sent_time[self.base]
            if self.base in self.retry_count:
                del self.retry_count[self.base]
            self.base += 1

    def get_unacked_packets(self, timeout: float, max_retries: int) -> List[int]:
        """Get packets that need retransmission"""
        now = time.time()
        to_retransmit = []

        for seq_num, sent_time in self.sent_time.items():
            if (seq_num not in self.acked and
                now - sent_time > timeout and
                self.retry_count[seq_num] < max_retries):
                to_retransmit.append(seq_num)

        return to_retransmit

    def increment_retry(self, seq_num: int):
        """Increment retry count for a packet"""
        self.retry_count[seq_num] += 1

    def is_complete(self, total_packets: int) -> bool:
        """Check if all packets have been acknowledged"""
        return self.base >= total_packets


class ReceiveBuffer:
    """Buffer for receiving and reordering packets"""

    def __init__(self, total_chunks: int):
        self.total_chunks = total_chunks
        self.received: Dict[int, bytes] = {}  # chunk_index -> data
        self.received_set: Set[int] = set()
        self.next_expected = 0

    def add_chunk(self, chunk_index: int, data: bytes):
        """Add a received chunk"""
        if chunk_index not in self.received_set:
            self.received[chunk_index] = data
            self.received_set.add(chunk_index)

    def get_contiguous_chunks(self) -> List[Tuple[int, bytes]]:
        """Get chunks that can be written to file (in order)"""
        chunks = []
        while self.next_expected in self.received:
            chunks.append((self.next_expected, self.received[self.next_expected]))
            del self.received[self.next_expected]
            self.received_set.remove(self.next_expected)
            self.next_expected += 1
        return chunks

    def get_missing_chunks(self, up_to: int) -> List[int]:
        """Get list of missing chunk indices up to a certain point"""
        missing = []
        for i in range(min(up_to + 1, self.total_chunks)):
            if i not in self.received_set:
                missing.append(i)
        return missing

    def is_complete(self) -> bool:
        """Check if all chunks have been received"""
        return len(self.received_set) >= self.total_chunks


class FileTransfer:
    """Enhanced reliable file transfer with sliding window protocol"""

    # Enhanced configuration
    DEFAULT_CHUNK_SIZE = 32 * 1024  # 32 KiB
    DEFAULT_WINDOW_SIZE = 16  # Number of packets in flight
    ACK_TIMEOUT = 1.0  # Reduced timeout for faster retransmission
    MAX_RETRIES = 8  # Increased retries
    WINDOW_ACK_INTERVAL = 0.5  # How often to send window acknowledgments

    def __init__(self, sock, crypto_manager):
        self.socket = sock
        self.crypto = crypto_manager
        self.lock = threading.Lock()
        self.transfers: Dict[str, Dict[str, Any]] = {}
        self.save_dir: Path = Path.cwd()
        self.progress_callback: Optional[Callable[[str, int, int], None]] = None

    def receive_file(self, save_dir: str, progress_callback: Callable[[str, int, int], None]):
        """Configure where incoming files are stored and how to report progress."""
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)
        self.progress_callback = progress_callback

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
                "start_time": time.time(),
                "progress_cb": progress_callback,
                "window": SlidingWindow(self.DEFAULT_WINDOW_SIZE),
                "chunk_data": {},  # Cache chunk data for retransmission
            }

        # Send file initialization
        init_msg = {
            "type": FILE_INIT,
            "transfer_id": transfer_id,
            "file_name": os.path.basename(file_path),
            "file_size": file_size,
            "chunk_size": self.DEFAULT_CHUNK_SIZE,
            "total_chunks": total_chunks,
            "window_size": self.DEFAULT_WINDOW_SIZE,
        }
        self._send_json(init_msg, peer_addr)

        # Start upload worker thread
        t = threading.Thread(target=self._enhanced_upload_worker, args=(transfer_id,), daemon=True)
        t.start()
        return transfer_id

    def _enhanced_upload_worker(self, transfer_id: str):
        """Enhanced upload worker with sliding window protocol"""
        with self.lock:
            tf = self.transfers[transfer_id]

        # Wait for FILE_INIT_ACK
        while True:
            with self.lock:
                if tf.get("init_acked") or tf["status"] == "failed":
                    break
            time.sleep(0.1)

        if tf["status"] == "failed":
            return

        # Pre-load all chunks into memory for faster access
        logger.info(f"Pre-loading {tf['total_chunks']} chunks for transfer {transfer_id}")
        chunk_data = {}
        try:
            with open(tf["file_path"], "rb") as fh:
                for i in range(tf["total_chunks"]):
                    data = fh.read(self.DEFAULT_CHUNK_SIZE)
                    encrypted_data = self._encrypt(tf["peer_id"], data)
                    chunk_data[i] = encrypted_data
        except Exception as e:
            logger.error(f"Failed to pre-load chunks: {e}")
            with self.lock:
                tf["status"] = "failed"
            return

        with self.lock:
            tf["chunk_data"] = chunk_data

        window = tf["window"]
        peer_addr = tf["peer_addr"]
        total_chunks = tf["total_chunks"]
        last_progress_update = time.time()

        # Modified transmission loop - only send one chunk at a time
        while not window.is_complete(total_chunks):
            with self.lock:
                if tf["status"] == "failed":
                    break

            # Send only one new packet if window allows
            if window.can_send() and window.next_seq < total_chunks:
                chunk_index = window.next_seq
                self._send_chunk(transfer_id, chunk_index, tf["chunk_data"][chunk_index])
                window.mark_sent(chunk_index)

                with self.lock:
                    tf["chunks_sent"] = max(tf["chunks_sent"], chunk_index + 1)

                # Wait for ACK before sending next chunk
                ack_received = False
                wait_start = time.time()
                while time.time() - wait_start < self.ACK_TIMEOUT:
                    with self.lock:
                        if chunk_index in window.acked or tf["status"] == "failed":
                            ack_received = True
                            break
                    time.sleep(0.01)

                if not ack_received:
                    logger.warning(f"No ACK received for chunk {chunk_index}, will retry")
                    # Let the retransmission logic handle it

            # Rest of the original code for retransmissions...
            time.sleep(0.01)  # Small delay to prevent busy waiting

        # Send completion signal
        if window.is_complete(total_chunks):
            self._send_json({"type": FILE_END, "transfer_id": transfer_id}, peer_addr)

            # Wait for final acknowledgment
            end_deadline = time.time() + self.ACK_TIMEOUT * 3
            while time.time() < end_deadline:
                with self.lock:
                    if tf.get("end_acked"):
                        break
                time.sleep(0.1)

            with self.lock:
                if tf.get("end_acked"):
                    tf["status"] = "completed"
                    tf["end_time"] = time.time()
                    duration = tf["end_time"] - tf["start_time"]
                    speed = tf["file_size"] / duration / 1024 if duration > 0 else 0
                    logger.info(f"Upload of {tf['file_name']} completed - {speed:.2f} KB/s")
                else:
                    tf["status"] = "failed"
                    logger.error(f"Transfer {transfer_id} failed - no FILE_END_ACK")

    def _send_chunk(self, transfer_id: str, chunk_index: int, encrypted_data: bytes):
        """Send a single chunk with header"""
        with self.lock:
            tf = self.transfers[transfer_id]

        header = {
            "type": FILE_CHUNK,
            "transfer_id": transfer_id,
            "chunk_index": chunk_index,
            "chunk_size": len(encrypted_data),
            "total_chunks": tf["total_chunks"],
        }

        try:
            self._send_json(header, tf["peer_addr"])
            self.socket.sendto(encrypted_data, tf["peer_addr"])
            logger.debug(f"Sent chunk {chunk_index}/{tf['total_chunks']} for {transfer_id}")
        except Exception as e:
            logger.error(f"Failed to send chunk {chunk_index}: {e}")

    def handle_message(self, data: bytes, addr: Tuple[str, int], peer_id: str):
        try:
            msg = json.loads(data.decode())
        except Exception:
            logger.debug("handle_message: not JSON – ignoring")
            return

        mtype = msg.get("type")
        if mtype == FILE_INIT:
            self._handle_file_init_enhanced(msg, addr, peer_id)
        elif mtype == FILE_INIT_ACK:
            self._handle_file_init_ack(msg)
        elif mtype == CHUNK_ACK:
            self._handle_chunk_ack_enhanced(msg)
        elif mtype == WINDOW_ACK:
            self._handle_window_ack(msg)
        elif mtype == SELECTIVE_NACK:
            self._handle_selective_nack(msg)
        elif mtype == FILE_END:
            self._handle_file_end(msg, addr)
        elif mtype == FILE_END_ACK:
            self._handle_file_end_ack(msg)
        elif mtype == FILE_CHUNK:
            # Add this missing case to handle chunk headers
            self._handle_file_chunk(msg, addr, peer_id)

    def _handle_file_init_enhanced(self, msg: Dict[str, Any], addr: Tuple[str, int], peer_id: str):
        """Enhanced file init handler with receive buffer setup"""
        transfer_id = msg["transfer_id"]
        with self.lock:
            if transfer_id in self.transfers:
                logger.debug(f"FILE_INIT dup for {transfer_id} – ignoring")
                return

            total_chunks = msg["total_chunks"]
            self.transfers[transfer_id] = {
                "direction": "in",
                "file_name": msg["file_name"],
                "file_size": msg["file_size"],
                "chunk_size": msg["chunk_size"],
                "total_chunks": total_chunks,
                "window_size": msg.get("window_size", self.DEFAULT_WINDOW_SIZE),
                "chunks_received": 0,
                "status": "receiving",
                "peer_addr": addr,
                "peer_id": peer_id,
                "start_time": time.time(),
                "receive_buffer": ReceiveBuffer(total_chunks),
                "last_window_ack": 0,
            }

        # Send acknowledgment
        ack = {"type": FILE_INIT_ACK, "transfer_id": transfer_id}
        self._send_json(ack, addr)
        logger.info(f"Incoming file {msg['file_name']} ({msg['file_size']} bytes) from {peer_id}")

    def _handle_chunk_ack_enhanced(self, msg: Dict[str, Any]):
        """Enhanced chunk ACK handler for sliding window"""
        transfer_id = msg["transfer_id"]
        chunk_index = msg["chunk_index"]

        with self.lock:
            tf = self.transfers.get(transfer_id)
            if tf and tf["direction"] == "out":
                window = tf["window"]
                window.mark_acked(chunk_index)
                tf["chunks_acked"] = window.base

    def _handle_window_ack(self, msg: Dict[str, Any]):
        """Handle window acknowledgment with selective information"""
        transfer_id = msg["transfer_id"]
        acked_chunks = set(msg.get("acked_chunks", []))

        with self.lock:
            tf = self.transfers.get(transfer_id)
            if tf and tf["direction"] == "out":
                window = tf["window"]
                for chunk_index in acked_chunks:
                    window.mark_acked(chunk_index)
                tf["chunks_acked"] = window.base

    def _handle_selective_nack(self, msg: Dict[str, Any]):
        """Handle selective NACK for missing chunks"""
        transfer_id = msg["transfer_id"]
        missing_chunks = msg.get("missing_chunks", [])

        with self.lock:
            tf = self.transfers.get(transfer_id)
            if tf and tf["direction"] == "out":
                window = tf["window"]
                for chunk_index in missing_chunks:
                    if chunk_index in tf["chunk_data"]:
                        logger.info(f"Resending chunk {chunk_index} due to NACK")
                        self._send_chunk(transfer_id, chunk_index, tf["chunk_data"][chunk_index])
                        window.sent_time[chunk_index] = time.time()

    def _handle_file_chunk(self, header: Dict[str, Any], addr: Tuple[str, int], peer_id: str):
        """Store header for incoming chunk"""
        transfer_id = header["transfer_id"]
        chunk_index = header["chunk_index"]

        with self.lock:
            tf = self.transfers.get(transfer_id)
            if not tf:
                logger.warning(f"Chunk header for unknown transfer {transfer_id}")
                return
            tf["expected_chunk_index"] = chunk_index
            tf["expected_chunk_size"] = header["chunk_size"]

    def _process_chunk_enhanced(self, transfer_id: str, chunk_index: int, peer_id: str,
                                addr: Tuple[str, int], data: bytes):
        """Enhanced chunk processing with reordering"""
        with self.lock:
            tf = self.transfers.get(transfer_id)
            if not tf or tf["direction"] != "in":
                logger.warning(f"Data chunk for unknown or outbound transfer {transfer_id}")
                return

            try:
                plaintext = self._decrypt(peer_id, data)
            except Exception as exc:
                logger.error(f"Decryption failed – aborting transfer {transfer_id}: {exc}")
                tf["status"] = "failed"
                return

            # Add to receive buffer
            receive_buffer = tf["receive_buffer"]
            receive_buffer.add_chunk(chunk_index, plaintext)

            # Open file handle if needed
            if "file_handle" not in tf:
                dest = self.save_dir / tf["file_name"]
                tf["dest_path"] = dest
                try:
                    # Make sure to open in binary write mode
                    tf["file_handle"] = open(dest, "wb")
                except Exception as e:
                    logger.error(f"Failed to open file {dest}: {e}")
                    tf["status"] = "failed"
                    return

            # Write contiguous chunks to file
            contiguous_chunks = receive_buffer.get_contiguous_chunks()
            for idx, chunk_data in contiguous_chunks:
                # Make sure we're only writing actual file data, not headers
                tf["file_handle"].write(chunk_data)
                tf["file_handle"].flush()
                tf["chunks_received"] += 1

            # Send individual chunk ACK
            ack_msg = {"type": CHUNK_ACK, "transfer_id": transfer_id, "chunk_index": chunk_index}
            self._send_json(ack_msg, addr)

            # Periodically send window acknowledgment
            now = time.time()
            if now - tf.get('last_window_ack_time', 0) > self.WINDOW_ACK_INTERVAL:
                # Send comprehensive window status
                received_chunks = list(receive_buffer.received_set)
                missing_chunks = receive_buffer.get_missing_chunks(max(received_chunks) if received_chunks else 0)

                window_ack = {
                    "type": WINDOW_ACK,
                    "transfer_id": transfer_id,
                    "acked_chunks": received_chunks,
                }
                self._send_json(window_ack, addr)

                # Send NACK for missing chunks if needed
                if missing_chunks:
                    nack_msg = {
                        "type": SELECTIVE_NACK,
                        "transfer_id": transfer_id,
                        "missing_chunks": missing_chunks,
                    }
                    self._send_json(nack_msg, addr)

                tf['last_window_ack_time'] = now

            # Update progress
            if self.progress_callback:
                self.progress_callback(transfer_id, tf["chunks_received"], tf["total_chunks"])

            # Check completion
            if receive_buffer.is_complete():
                tf["file_handle"].close()
                tf["status"] = "completed"
                tf["end_time"] = time.time()

                # Send final acknowledgment
                end_ack = {"type": FILE_END_ACK, "transfer_id": transfer_id}
                self._send_json(end_ack, addr)
                logger.info(f"Completed download of {tf['file_name']} ({transfer_id})")

    # Keep existing utility methods
    def _handle_file_init_ack(self, msg: Dict[str, Any]):
        transfer_id = msg["transfer_id"]
        with self.lock:
            tf = self.transfers.get(transfer_id)
            if tf and tf["direction"] == "out":
                tf["init_acked"] = True

    def _handle_file_end(self, msg: Dict[str, Any], addr: Tuple[str, int]):
        transfer_id = msg["transfer_id"]
        self._send_json({"type": FILE_END_ACK, "transfer_id": transfer_id}, addr)
        logger.debug(f"FILE_END received for {transfer_id} – ACK sent")

    def _handle_file_end_ack(self, msg: Dict[str, Any]):
        transfer_id = msg["transfer_id"]
        with self.lock:
            tf = self.transfers.get(transfer_id)
            if tf and tf["direction"] == "out":
                tf["end_acked"] = True

    def _send_json(self, obj: Dict[str, Any], addr: Tuple[str, int]):
        try:
            self.socket.sendto(json.dumps(obj).encode(), addr)
        except Exception as exc:
            logger.error(f"UDP send failed: {exc}")

    def _encrypt(self, peer_id: str, plaintext: bytes) -> bytes:
        if hasattr(self.crypto, "encrypt_data"):
            return self.crypto.encrypt_data(peer_id, plaintext)
        return plaintext

    def _decrypt(self, peer_id: str, ciphertext: bytes) -> bytes:
        if hasattr(self.crypto, "decrypt_data"):
            return self.crypto.decrypt_data(peer_id, ciphertext)
        return ciphertext

    def handle_binary_data(self, data: bytes, addr: Tuple[str, int], peer_id: str):
        """Process binary data (actual chunk content)"""
        with self.lock:
            # Find which transfer is expecting data from this peer
            for transfer_id, tf in self.transfers.items():
                if (tf["direction"] == "in" and
                        tf["peer_addr"] == addr and
                        "expected_chunk_index" in tf):

                    # Get expected chunk information
                    chunk_index = tf.pop("expected_chunk_index")
                    expected_size = tf.pop("expected_chunk_size", len(data))

                    # Verify chunk size
                    if len(data) != expected_size:
                        logger.warning(
                            f"Chunk size mismatch for {transfer_id}: expected {expected_size}, got {len(data)}")
                        return

                    # Process this chunk (only the binary data, not header)
                    self._process_chunk(transfer_id, chunk_index, peer_id, addr, data)
                    return

            logger.debug(f"Received unexpected binary data from {addr} – dropping")

    # Add method for processing chunks (called by P2PNode)
    def _process_chunk(self, transfer_id: str, chunk_index: int, peer_id: str,
                      addr: Tuple[str, int], data: bytes):
        """Bridge method to call enhanced chunk processing"""
        self._process_chunk_enhanced(transfer_id, chunk_index, peer_id, addr, data)