"""
Enhanced reliable UDP file transfer with sliding window protocol and selective repeat.
Improved reliability, congestion control, and error handling.
"""

from __future__ import annotations

import json
import logging
import math
import os
import threading
import time
import uuid
import hashlib
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple, Set, List
from collections import defaultdict, deque
import bisect

logger = logging.getLogger(__name__)

# Message type constants
FILE_INIT = "file_init"
FILE_INIT_ACK = "file_init_ack"
FILE_CHUNK = "file_chunk"
CHUNK_ACK = "chunk_ack"
FILE_END = "file_end"
FILE_END_ACK = "file_end_ack"
WINDOW_ACK = "window_ack"
SELECTIVE_NACK = "selective_nack"
HEARTBEAT = "heartbeat"
HEARTBEAT_ACK = "heartbeat_ack"


class CongestionControl:
    """Adaptive congestion control for reliable transmission"""

    def __init__(self, initial_window_size: int = 8):
        self.window_size = initial_window_size
        self.slow_start_threshold = 64
        self.in_slow_start = True
        self.duplicate_acks = 0
        self.last_ack = -1
        self.rtt_samples = deque(maxlen=20)
        self.rto = 1.0  # Retransmission timeout
        self.min_rto = 0.2
        self.max_rto = 60.0

    def on_ack_received(self, ack_num: int, rtt: float):
        """Handle acknowledgment and update window size"""
        self.rtt_samples.append(rtt)
        self._update_rto()

        if ack_num == self.last_ack:
            self.duplicate_acks += 1
            if self.duplicate_acks >= 3:
                # Fast retransmit
                self._handle_fast_retransmit()
        else:
            # New ACK
            self.duplicate_acks = 0
            self.last_ack = ack_num
            self._increase_window()

    def on_timeout(self):
        """Handle timeout event"""
        self.slow_start_threshold = max(self.window_size // 2, 2)
        self.window_size = 1
        self.in_slow_start = True
        self.rto = min(self.rto * 2, self.max_rto)

    def _increase_window(self):
        """Increase window size based on current phase"""
        if self.in_slow_start:
            self.window_size += 1
            if self.window_size >= self.slow_start_threshold:
                self.in_slow_start = False
        else:
            # Congestion avoidance
            self.window_size += 1.0 / self.window_size

        self.window_size = min(self.window_size, 128)  # Cap window size

    def _handle_fast_retransmit(self):
        """Handle fast retransmit scenario"""
        self.slow_start_threshold = max(self.window_size // 2, 2)
        self.window_size = self.slow_start_threshold
        self.in_slow_start = False

    def _update_rto(self):
        """Update retransmission timeout based on RTT samples"""
        if not self.rtt_samples:
            return

        srtt = sum(self.rtt_samples) / len(self.rtt_samples)
        rttvar = sum(abs(rtt - srtt) for rtt in self.rtt_samples) / len(self.rtt_samples)
        self.rto = max(self.min_rto, min(srtt + 4 * rttvar, self.max_rto))


class EnhancedSlidingWindow:
    """Enhanced sliding window with better reliability"""

    def __init__(self, initial_window_size: int):
        self.base = 0
        self.next_seq = 0
        self.acked: Set[int] = set()
        self.sent_time: Dict[int, float] = {}
        self.retry_count: Dict[int, int] = defaultdict(int)
        self.congestion_control = CongestionControl(initial_window_size)
        self.in_flight = set()  # Packets currently in flight

    def can_send(self) -> bool:
        """Check if we can send more packets"""
        return (len(self.in_flight) < int(self.congestion_control.window_size) and
                self.next_seq not in self.acked)

    def mark_sent(self, seq_num: int):
        """Mark a packet as sent"""
        self.sent_time[seq_num] = time.time()
        self.in_flight.add(seq_num)
        if seq_num >= self.next_seq:
            self.next_seq = seq_num + 1

    def mark_acked(self, seq_num: int) -> bool:
        """Mark a packet as acknowledged, return True if window moved"""
        if seq_num in self.acked:
            return False  # Duplicate ACK

        self.acked.add(seq_num)
        self.in_flight.discard(seq_num)

        # Calculate RTT if we have send time
        if seq_num in self.sent_time:
            rtt = time.time() - self.sent_time[seq_num]
            self.congestion_control.on_ack_received(seq_num, rtt)
            del self.sent_time[seq_num]

        window_moved = False
        # Slide window if possible
        while self.base in self.acked:
            self.acked.remove(self.base)
            self.retry_count.pop(self.base, None)
            self.base += 1
            window_moved = True

        return window_moved

    def get_timeout_packets(self, max_retries: int) -> List[int]:
        """Get packets that need retransmission due to timeout"""
        now = time.time()
        rto = self.congestion_control.rto
        to_retransmit = []

        for seq_num in list(self.in_flight):
            if (seq_num in self.sent_time and
                now - self.sent_time[seq_num] > rto and
                self.retry_count[seq_num] < max_retries):
                to_retransmit.append(seq_num)

        if to_retransmit:
            self.congestion_control.on_timeout()

        return to_retransmit

    def increment_retry(self, seq_num: int):
        """Increment retry count for a packet"""
        self.retry_count[seq_num] += 1
        self.sent_time[seq_num] = time.time()  # Reset send time for retransmission

    def is_complete(self, total_packets: int) -> bool:
        """Check if all packets have been acknowledged"""
        return self.base >= total_packets

    def get_stats(self) -> Dict:
        """Get window statistics for debugging"""
        return {
            'base': self.base,
            'next_seq': self.next_seq,
            'window_size': int(self.congestion_control.window_size),
            'in_flight': len(self.in_flight),
            'rto': self.congestion_control.rto,
            'slow_start': self.congestion_control.in_slow_start
        }


class EnhancedReceiveBuffer:
    """Enhanced buffer for receiving and reordering packets"""

    def __init__(self, total_chunks: int):
        self.total_chunks = total_chunks
        self.received: Dict[int, bytes] = {}
        self.received_set: Set[int] = set()
        self.next_expected = 0
        self.checksums: Dict[int, str] = {}  # For integrity checking
        self.last_ack_sent = time.time()

    def add_chunk(self, chunk_index: int, data: bytes, checksum: str = None) -> bool:
        """Add a received chunk with optional integrity check"""
        if chunk_index in self.received_set:
            return False  # Duplicate

        # Verify checksum if provided
        if checksum:
            actual_checksum = hashlib.md5(data).hexdigest()
            if actual_checksum != checksum:
                logger.warning(f"Checksum mismatch for chunk {chunk_index}")
                return False
            self.checksums[chunk_index] = checksum

        self.received[chunk_index] = data
        self.received_set.add(chunk_index)
        return True

    def get_contiguous_chunks(self) -> List[Tuple[int, bytes]]:
        """Get chunks that can be written to file (in order)"""
        chunks = []
        while self.next_expected in self.received:
            chunks.append((self.next_expected, self.received[self.next_expected]))
            del self.received[self.next_expected]
            self.received_set.remove(self.next_expected)
            self.checksums.pop(self.next_expected, None)
            self.next_expected += 1
        return chunks

    def get_missing_chunks(self, up_to: int) -> List[int]:
        """Get list of missing chunk indices up to a certain point"""
        missing = []
        for i in range(min(up_to + 1, self.total_chunks)):
            if i not in self.received_set:
                missing.append(i)
        return missing

    def should_send_ack(self) -> bool:
        """Check if we should send an acknowledgment"""
        return time.time() - self.last_ack_sent > 0.1  # Send ACK every 100ms

    def mark_ack_sent(self):
        """Mark that an ACK was sent"""
        self.last_ack_sent = time.time()

    def is_complete(self) -> bool:
        """Check if all chunks have been received"""
        return len(self.received_set) >= self.total_chunks


class EnhancedFileTransfer:
    """Enhanced reliable file transfer with improved reliability"""

    # Enhanced configuration
    DEFAULT_CHUNK_SIZE = 16 * 1024  # Smaller chunks for better reliability
    DEFAULT_WINDOW_SIZE = 8  # Conservative initial window
    MAX_RETRIES = 10
    HEARTBEAT_INTERVAL = 5.0
    STALE_TRANSFER_TIMEOUT = 300.0  # 5 minutes

    def __init__(self, sock, crypto_manager):
        self.socket = sock
        self.crypto = crypto_manager
        self.lock = threading.RLock()  # Use RLock for nested locking
        self.transfers: Dict[str, Dict[str, Any]] = {}
        self.save_dir: Path = Path.cwd()
        self.progress_callback: Optional[Callable[[str, int, int], None]] = None
        self.running = True

        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_stale_transfers, daemon=True)
        self.cleanup_thread.start()

    def receive_file(self, save_dir: str, progress_callback: Callable[[str, int, int], None]):
        """Configure where incoming files are stored and how to report progress."""
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)
        self.progress_callback = progress_callback

    def send_file(self, file_path: str, peer_id: str, peer_addr: Tuple[str, int],
                  progress_callback: Callable[[str, int, int], None]) -> str:
        """Send a file with enhanced reliability"""
        file_path = str(file_path)
        if not os.path.isfile(file_path):
            raise FileNotFoundError(file_path)

        transfer_id = str(uuid.uuid4())
        file_size = os.path.getsize(file_path)
        total_chunks = math.ceil(file_size / self.DEFAULT_CHUNK_SIZE)

        # Calculate file checksum for integrity
        file_checksum = self._calculate_file_checksum(file_path)

        with self.lock:
            self.transfers[transfer_id] = {
                "direction": "out",
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_size": file_size,
                "file_checksum": file_checksum,
                "total_chunks": total_chunks,
                "chunks_sent": 0,
                "chunks_acked": 0,
                "status": "pending",
                "peer_addr": peer_addr,
                "peer_id": peer_id,
                "start_time": time.time(),
                "last_activity": time.time(),
                "progress_cb": progress_callback,
                "window": EnhancedSlidingWindow(self.DEFAULT_WINDOW_SIZE),
                "chunk_data": {},
                "heartbeat_thread": None,
            }

        # Send file initialization
        init_msg = {
            "type": FILE_INIT,
            "transfer_id": transfer_id,
            "file_name": os.path.basename(file_path),
            "file_size": file_size,
            "file_checksum": file_checksum,
            "chunk_size": self.DEFAULT_CHUNK_SIZE,
            "total_chunks": total_chunks,
            "window_size": self.DEFAULT_WINDOW_SIZE,
        }
        self._send_json(init_msg, peer_addr)

        # Start upload worker thread
        t = threading.Thread(target=self._enhanced_upload_worker, args=(transfer_id,), daemon=True)
        t.start()

        return transfer_id

    def _calculate_file_checksum(self, file_path: str) -> str:
        """Calculate MD5 checksum of entire file"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def _enhanced_upload_worker(self, transfer_id: str):
        """Enhanced upload worker with better error handling and flow control"""
        with self.lock:
            tf = self.transfers[transfer_id]

        # Wait for FILE_INIT_ACK with timeout
        init_deadline = time.time() + 30.0  # 30 second timeout
        while time.time() < init_deadline:
            with self.lock:
                if tf.get("init_acked") or tf["status"] == "failed":
                    break
            time.sleep(0.1)

        if not tf.get("init_acked"):
            logger.error(f"Transfer {transfer_id} failed - no FILE_INIT_ACK received")
            with self.lock:
                tf["status"] = "failed"
            return

        # Pre-load chunks with checksums
        logger.info(f"Pre-loading {tf['total_chunks']} chunks for transfer {transfer_id}")
        chunk_data = {}
        chunk_checksums = {}

        try:
            with open(tf["file_path"], "rb") as fh:
                for i in range(tf["total_chunks"]):
                    data = fh.read(self.DEFAULT_CHUNK_SIZE)
                    checksum = hashlib.md5(data).hexdigest()
                    encrypted_data = self._encrypt(tf["peer_id"], data)
                    chunk_data[i] = encrypted_data
                    chunk_checksums[i] = checksum
        except Exception as e:
            logger.error(f"Failed to pre-load chunks: {e}")
            with self.lock:
                tf["status"] = "failed"
            return

        with self.lock:
            tf["chunk_data"] = chunk_data
            tf["chunk_checksums"] = chunk_checksums

        # Start heartbeat thread
        heartbeat_thread = threading.Thread(
            target=self._heartbeat_worker,
            args=(transfer_id,),
            daemon=True
        )
        heartbeat_thread.start()
        tf["heartbeat_thread"] = heartbeat_thread

        window = tf["window"]
        peer_addr = tf["peer_addr"]
        total_chunks = tf["total_chunks"]
        last_progress_update = time.time()
        consecutive_failures = 0

        # Main transmission loop
        while not window.is_complete(total_chunks) and consecutive_failures < 20:
            with self.lock:
                if tf["status"] == "failed":
                    break
                tf["last_activity"] = time.time()

            progress_made = False

            # Send new packets if window allows
            while window.can_send() and window.next_seq < total_chunks:
                chunk_index = window.next_seq
                if self._send_chunk_with_checksum(transfer_id, chunk_index):
                    window.mark_sent(chunk_index)
                    progress_made = True
                    with self.lock:
                        tf["chunks_sent"] = max(tf["chunks_sent"], chunk_index + 1)
                else:
                    break

            # Handle retransmissions
            to_retransmit = window.get_timeout_packets(self.MAX_RETRIES)
            for chunk_index in to_retransmit:
                if chunk_index < total_chunks:
                    logger.warning(f"Retransmitting chunk {chunk_index} for {transfer_id}")
                    if self._send_chunk_with_checksum(transfer_id, chunk_index):
                        window.increment_retry(chunk_index)
                        progress_made = True

            # Update progress periodically
            now = time.time()
            if now - last_progress_update > 1.0:
                with self.lock:
                    if tf["progress_cb"]:
                        acked_count = window.base
                        tf["progress_cb"](transfer_id, acked_count, total_chunks)
                last_progress_update = now

            # Check for failed retransmissions
            failed_chunks = [
                seq for seq, count in window.retry_count.items()
                if count >= self.MAX_RETRIES and seq not in window.acked
            ]
            if failed_chunks:
                logger.error(f"Transfer {transfer_id} failed - too many retries for chunks: {failed_chunks}")
                with self.lock:
                    tf["status"] = "failed"
                break

            if not progress_made:
                consecutive_failures += 1
                time.sleep(min(0.1 * consecutive_failures, 1.0))  # Exponential backoff
            else:
                consecutive_failures = 0

            time.sleep(0.01)

        # Send completion signal
        if window.is_complete(total_chunks):
            self._send_completion(transfer_id)

    def _send_chunk_with_checksum(self, transfer_id: str, chunk_index: int) -> bool:
        """Send a chunk with checksum for integrity verification"""
        with self.lock:
            tf = self.transfers[transfer_id]
            if chunk_index not in tf["chunk_data"]:
                return False

        header = {
            "type": FILE_CHUNK,
            "transfer_id": transfer_id,
            "chunk_index": chunk_index,
            "chunk_size": len(tf["chunk_data"][chunk_index]),
            "total_chunks": tf["total_chunks"],
            "checksum": tf["chunk_checksums"][chunk_index],
        }

        try:
            self._send_json(header, tf["peer_addr"])
            self.socket.sendto(tf["chunk_data"][chunk_index], tf["peer_addr"])
            logger.debug(f"Sent chunk {chunk_index}/{tf['total_chunks']} for {transfer_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to send chunk {chunk_index}: {e}")
            return False

    def _send_completion(self, transfer_id: str):
        """Send completion signal and wait for acknowledgment"""
        with self.lock:
            tf = self.transfers[transfer_id]

        end_msg = {"type": FILE_END, "transfer_id": transfer_id}

        # Send FILE_END multiple times and wait for acknowledgment
        for attempt in range(5):
            self._send_json(end_msg, tf["peer_addr"])

            # Wait for acknowledgment
            end_deadline = time.time() + 2.0
            while time.time() < end_deadline:
                with self.lock:
                    if tf.get("end_acked"):
                        tf["status"] = "completed"
                        tf["end_time"] = time.time()
                        duration = tf["end_time"] - tf["start_time"]
                        speed = tf["file_size"] / duration / 1024 if duration > 0 else 0
                        logger.info(f"Upload of {tf['file_name']} completed - {speed:.2f} KB/s")
                        return
                time.sleep(0.1)

        # Timeout waiting for final ACK
        with self.lock:
            tf["status"] = "failed"
            logger.error(f"Transfer {transfer_id} failed - no FILE_END_ACK")

    def _heartbeat_worker(self, transfer_id: str):
        """Send periodic heartbeats to detect connection issues"""
        while True:
            with self.lock:
                tf = self.transfers.get(transfer_id)
                if not tf or tf["status"] in ["completed", "failed"]:
                    break

            heartbeat_msg = {"type": HEARTBEAT, "transfer_id": transfer_id}
            try:
                with self.lock:
                    self._send_json(heartbeat_msg, tf["peer_addr"])
            except:
                pass

            time.sleep(self.HEARTBEAT_INTERVAL)

    def _cleanup_stale_transfers(self):
        """Clean up stale transfers periodically"""
        while self.running:
            now = time.time()
            stale_transfers = []

            with self.lock:
                for transfer_id, tf in self.transfers.items():
                    if (now - tf.get("last_activity", tf["start_time"]) > self.STALE_TRANSFER_TIMEOUT):
                        stale_transfers.append(transfer_id)

            for transfer_id in stale_transfers:
                logger.warning(f"Cleaning up stale transfer {transfer_id}")
                with self.lock:
                    tf = self.transfers.get(transfer_id)
                    if tf:
                        tf["status"] = "failed"
                        if "file_handle" in tf:
                            try:
                                tf["file_handle"].close()
                            except:
                                pass

            time.sleep(60)  # Check every minute

    # Keep existing message handling methods but with enhanced error handling
    def handle_message(self, data: bytes, addr: Tuple[str, int], peer_id: str):
        """Handle incoming messages with better error handling"""
        try:
            msg = json.loads(data.decode())
        except Exception:
            logger.debug("handle_message: not JSON – ignoring")
            return

        try:
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
            elif mtype == HEARTBEAT:
                self._handle_heartbeat(msg, addr)
            elif mtype == HEARTBEAT_ACK:
                self._handle_heartbeat_ack(msg)
        except Exception as e:
            logger.error(f"Error handling message type {mtype}: {e}")

    def _handle_heartbeat(self, msg: Dict[str, Any], addr: Tuple[str, int]):
        """Handle heartbeat message"""
        transfer_id = msg.get("transfer_id")
        if transfer_id:
            ack_msg = {"type": HEARTBEAT_ACK, "transfer_id": transfer_id}
            self._send_json(ack_msg, addr)

    def _handle_heartbeat_ack(self, msg: Dict[str, Any]):
        """Handle heartbeat acknowledgment"""
        transfer_id = msg.get("transfer_id")
        if transfer_id:
            with self.lock:
                tf = self.transfers.get(transfer_id)
                if tf:
                    tf["last_activity"] = time.time()

    # ... (keep other existing methods with minor enhancements for error handling)

    def _handle_file_init_enhanced(self, msg: Dict[str, Any], addr: Tuple[str, int], peer_id: str):
        """Enhanced file init handler"""
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
                "file_checksum": msg.get("file_checksum"),
                "chunk_size": msg["chunk_size"],
                "total_chunks": total_chunks,
                "window_size": msg.get("window_size", self.DEFAULT_WINDOW_SIZE),
                "chunks_received": 0,
                "status": "receiving",
                "peer_addr": addr,
                "peer_id": peer_id,
                "start_time": time.time(),
                "last_activity": time.time(),
                "receive_buffer": EnhancedReceiveBuffer(total_chunks),
            }

        ack = {"type": FILE_INIT_ACK, "transfer_id": transfer_id}
        self._send_json(ack, addr)
        logger.info(f"Incoming file {msg['file_name']} ({msg['file_size']} bytes) from {peer_id}")

    def _handle_chunk_ack_enhanced(self, msg: Dict[str, Any]):
        """Enhanced chunk ACK handler"""
        transfer_id = msg["transfer_id"]
        chunk_index = msg["chunk_index"]

        with self.lock:
            tf = self.transfers.get(transfer_id)
            if tf and tf["direction"] == "out":
                tf["last_activity"] = time.time()
                window = tf["window"]
                if window.mark_acked(chunk_index):
                    tf["chunks_acked"] = window.base

    def _handle_file_init_ack(self, msg: Dict[str, Any]):
        transfer_id = msg["transfer_id"]
        with self.lock:
            tf = self.transfers.get(transfer_id)
            if tf and tf["direction"] == "out":
                tf["init_acked"] = True
                tf["last_activity"] = time.time()

    def _handle_file_end(self, msg: Dict[str, Any], addr: Tuple[str, int]):
        transfer_id = msg["transfer_id"]
        self._send_json({"type": FILE_END_ACK, "transfer_id": transfer_id}, addr)

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

    def handle_binary_data(self, *_):
        """Binary datagrams that arrive outside the expected flow are ignored."""
        logger.debug("Received stray binary data – dropping")

    def stop(self):
        """Stop the file transfer manager"""
        self.running = False


# Update the class reference for backward compatibility
FileTransfer = EnhancedFileTransfer