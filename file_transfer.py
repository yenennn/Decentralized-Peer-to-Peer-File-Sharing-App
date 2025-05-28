"""
Enhanced reliable UDP file transfer using the rudp library.
Replaces custom sliding window protocol with proven reliable UDP implementation.
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
import socket

try:
    import rudp
except ImportError:
    print("Installing rudp library...")
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "rudp"])
    import rudp

logger = logging.getLogger(__name__)

# Message type constants
FILE_INIT = "file_init"
FILE_INIT_ACK = "file_init_ack"
FILE_CHUNK = "file_chunk"
CHUNK_ACK = "chunk_ack"
FILE_END = "file_end"
FILE_END_ACK = "file_end_ack"
TRANSFER_COMPLETE = "transfer_complete"
TRANSFER_ERROR = "transfer_error"


class RUDPConnection:
    """Wrapper for RUDP connection with additional P2P functionality"""

    def __init__(self, socket_obj, peer_addr: Tuple[str, int], crypto_manager, peer_id: str):
        self.peer_addr = peer_addr
        self.crypto_manager = crypto_manager
        self.peer_id = peer_id
        self.rudp_socket = rudp.RUDPSocket(socket_obj)
        self.connected = False
        self.last_activity = time.time()

    def connect(self) -> bool:
        """Establish RUDP connection with peer"""
        try:
            logger.info(f"Establishing RUDP connection to {self.peer_addr}")
            self.rudp_socket.connect(self.peer_addr)
            self.connected = True
            self.last_activity = time.time()
            logger.info(f"RUDP connection established with {self.peer_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to establish RUDP connection: {e}")
            return False

    def send_reliable(self, data: bytes) -> bool:
        """Send data reliably via RUDP"""
        try:
            self.rudp_socket.send(data)
            self.last_activity = time.time()
            return True
        except Exception as e:
            logger.error(f"RUDP send failed: {e}")
            return False

    def recv_reliable(self, buffer_size: int = 65536) -> Optional[bytes]:
        """Receive data reliably via RUDP"""
        try:
            data = self.rudp_socket.recv(buffer_size)
            self.last_activity = time.time()
            return data
        except Exception as e:
            logger.debug(f"RUDP recv error: {e}")
            return None

    def close(self):
        """Close RUDP connection"""
        try:
            if self.connected:
                self.rudp_socket.close()
                self.connected = False
                logger.info(f"RUDP connection closed with {self.peer_id}")
        except Exception as e:
            logger.error(f"Error closing RUDP connection: {e}")


class FileTransfer:
    """Enhanced reliable file transfer using RUDP library"""

    # Configuration
    DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KiB - larger chunks with RUDP reliability
    CONNECTION_TIMEOUT = 30.0  # 30 seconds for connection establishment
    TRANSFER_TIMEOUT = 300.0   # 5 minutes for transfer completion
    PROGRESS_UPDATE_INTERVAL = 1.0  # Update progress every second

    def __init__(self, sock, crypto_manager):
        self.socket = sock
        self.crypto = crypto_manager
        self.lock = threading.Lock()
        self.transfers: Dict[str, Dict[str, Any]] = {}
        self.save_dir: Path = Path.cwd()
        self.progress_callback: Optional[Callable[[str, int, int], None]] = None
        self.rudp_connections: Dict[str, RUDPConnection] = {}  # peer_id -> connection
        self.running = True

        # Start connection manager thread
        self.connection_thread = threading.Thread(target=self._manage_connections, daemon=True)
        self.connection_thread.start()

    def receive_file(self, save_dir: str, progress_callback: Callable[[str, int, int], None]):
        """Configure where incoming files are stored and how to report progress."""
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)
        self.progress_callback = progress_callback

    def get_or_create_connection(self, peer_id: str, peer_addr: Tuple[str, int]) -> Optional[RUDPConnection]:
        """Get existing or create new RUDP connection for peer"""
        with self.lock:
            if peer_id in self.rudp_connections:
                conn = self.rudp_connections[peer_id]
                if conn.connected:
                    return conn
                else:
                    # Remove stale connection
                    del self.rudp_connections[peer_id]

            # Create new connection
            try:
                conn = RUDPConnection(self.socket, peer_addr, self.crypto, peer_id)
                if conn.connect():
                    self.rudp_connections[peer_id] = conn
                    return conn
                else:
                    return None
            except Exception as e:
                logger.error(f"Failed to create RUDP connection for {peer_id}: {e}")
                return None

    def send_file(self, file_path: str, peer_id: str, peer_addr: Tuple[str, int],
                  progress_callback: Callable[[str, int, int], None]) -> str:
        """Send a file to a peer using RUDP"""
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
            target=self._rudp_upload_worker,
            args=(transfer_id,),
            daemon=True
        )
        upload_thread.start()
        return transfer_id

    def _rudp_upload_worker(self, transfer_id: str):
        """Upload worker using RUDP for reliable transmission"""
        with self.lock:
            tf = self.transfers[transfer_id]

        peer_id = tf["peer_id"]
        peer_addr = tf["peer_addr"]

        # Establish RUDP connection
        conn = self.get_or_create_connection(peer_id, peer_addr)
        if not conn:
            with self.lock:
                tf["status"] = "failed"
            logger.error(f"Failed to establish RUDP connection for transfer {transfer_id}")
            return

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
            if not conn.send_reliable(init_data):
                raise Exception("Failed to send file initialization")

            # Wait for acknowledgment
            ack_data = conn.recv_reliable()
            if not ack_data:
                raise Exception("No acknowledgment received")

            try:
                ack_msg = json.loads(ack_data.decode())
                if ack_msg.get("type") != FILE_INIT_ACK:
                    raise Exception("Invalid acknowledgment")
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise Exception("Invalid acknowledgment format")

            with self.lock:
                tf["status"] = "uploading"

            # Send file chunks
            last_progress_update = time.time()

            with open(tf["file_path"], "rb") as file_handle:
                for chunk_index in range(tf["total_chunks"]):
                    # Read chunk
                    chunk_data = file_handle.read(self.DEFAULT_CHUNK_SIZE)
                    if not chunk_data:
                        break

                    # Encrypt chunk
                    encrypted_data = self._encrypt(peer_id, chunk_data)

                    # Create chunk message
                    chunk_msg = {
                        "type": FILE_CHUNK,
                        "transfer_id": transfer_id,
                        "chunk_index": chunk_index,
                        "chunk_size": len(encrypted_data),
                        "total_chunks": tf["total_chunks"],
                    }

                    # Send chunk header + data as single message
                    chunk_header = json.dumps(chunk_msg).encode()
                    full_message = len(chunk_header).to_bytes(4, 'big') + chunk_header + encrypted_data

                    if not conn.send_reliable(full_message):
                        raise Exception(f"Failed to send chunk {chunk_index}")

                    with self.lock:
                        tf["chunks_sent"] = chunk_index + 1

                    # Update progress periodically
                    now = time.time()
                    if now - last_progress_update > self.PROGRESS_UPDATE_INTERVAL:
                        if tf["progress_cb"]:
                            tf["progress_cb"](transfer_id, chunk_index + 1, tf["total_chunks"])
                        last_progress_update = now

                    # Check if transfer was cancelled
                    with self.lock:
                        if tf["status"] == "cancelled":
                            raise Exception("Transfer cancelled")

            # Send completion message
            end_msg = {
                "type": FILE_END,
                "transfer_id": transfer_id,
            }
            end_data = json.dumps(end_msg).encode()
            if not conn.send_reliable(end_data):
                raise Exception("Failed to send completion message")

            # Wait for final acknowledgment
            final_ack = conn.recv_reliable()
            if final_ack:
                try:
                    final_msg = json.loads(final_ack.decode())
                    if final_msg.get("type") == FILE_END_ACK:
                        with self.lock:
                            tf["status"] = "completed"
                            tf["end_time"] = time.time()
                            duration = tf["end_time"] - tf["start_time"]
                            speed = tf["file_size"] / duration / 1024 if duration > 0 else 0
                            logger.info(f"Upload of {tf['file_name']} completed - {speed:.2f} KB/s")
                    else:
                        raise Exception("Invalid final acknowledgment")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    raise Exception("Invalid final acknowledgment format")
            else:
                raise Exception("No final acknowledgment received")

        except Exception as e:
            logger.error(f"Upload failed for transfer {transfer_id}: {e}")
            with self.lock:
                tf["status"] = "failed"
                tf["error"] = str(e)

    def handle_message(self, data: bytes, addr: Tuple[str, int], peer_id: str):
        """Handle incoming messages - now mainly for non-RUDP control messages"""
        try:
            msg = json.loads(data.decode())
        except Exception:
            logger.debug("handle_message: not JSON – ignoring")
            return

        mtype = msg.get("type")
        if mtype == FILE_INIT:
            self._handle_rudp_file_init(msg, addr, peer_id)
        else:
            logger.debug(f"Unhandled message type: {mtype}")

    def _handle_rudp_file_init(self, msg: Dict[str, Any], addr: Tuple[str, int], peer_id: str):
        """Handle file initialization for RUDP transfers"""
        transfer_id = msg["transfer_id"]

        with self.lock:
            if transfer_id in self.transfers:
                logger.debug(f"FILE_INIT dup for {transfer_id} – ignoring")
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

        logger.info(f"Incoming file {msg['file_name']} ({msg['file_size']} bytes) from {peer_id}")

        # Start download worker thread
        download_thread = threading.Thread(
            target=self._rudp_download_worker,
            args=(transfer_id,),
            daemon=True
        )
        download_thread.start()

    def _rudp_download_worker(self, transfer_id: str):
        """Download worker using RUDP for reliable reception"""
        with self.lock:
            tf = self.transfers[transfer_id]

        peer_id = tf["peer_id"]
        peer_addr = tf["peer_addr"]

        # Establish RUDP connection
        conn = self.get_or_create_connection(peer_id, peer_addr)
        if not conn:
            with self.lock:
                tf["status"] = "failed"
            logger.error(f"Failed to establish RUDP connection for transfer {transfer_id}")
            return

        try:
            # Send acknowledgment for file init
            ack_msg = {"type": FILE_INIT_ACK, "transfer_id": transfer_id}
            ack_data = json.dumps(ack_msg).encode()
            if not conn.send_reliable(ack_data):
                raise Exception("Failed to send initialization acknowledgment")

            # Prepare file for writing
            dest_path = self.save_dir / tf["file_name"]
            with open(dest_path, "wb") as file_handle:
                chunks_received = 0
                last_progress_update = time.time()

                while chunks_received < tf["total_chunks"]:
                    # Receive chunk message
                    message_data = conn.recv_reliable()
                    if not message_data:
                        raise Exception("Connection lost during transfer")

                    # Parse message
                    if len(message_data) < 4:
                        raise Exception("Invalid message format")

                    header_length = int.from_bytes(message_data[:4], 'big')
                    if len(message_data) < 4 + header_length:
                        raise Exception("Incomplete message")

                    header_data = message_data[4:4 + header_length]
                    chunk_data = message_data[4 + header_length:]

                    try:
                        chunk_msg = json.loads(header_data.decode())
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        raise Exception("Invalid chunk header")

                    if chunk_msg.get("type") == FILE_CHUNK:
                        chunk_index = chunk_msg["chunk_index"]

                        # Decrypt chunk
                        try:
                            plaintext = self._decrypt(peer_id, chunk_data)
                        except Exception as e:
                            raise Exception(f"Decryption failed: {e}")

                        # Write chunk to file
                        file_handle.write(plaintext)
                        file_handle.flush()

                        chunks_received += 1

                        with self.lock:
                            tf["chunks_received"] = chunks_received

                        # Update progress periodically
                        now = time.time()
                        if now - last_progress_update > self.PROGRESS_UPDATE_INTERVAL:
                            if self.progress_callback:
                                self.progress_callback(transfer_id, chunks_received, tf["total_chunks"])
                            last_progress_update = now

                        logger.debug(f"Received chunk {chunk_index + 1}/{tf['total_chunks']} for {transfer_id}")

                    elif chunk_msg.get("type") == FILE_END:
                        # Transfer completed
                        break
                    else:
                        logger.warning(f"Unexpected message type: {chunk_msg.get('type')}")

            # Send final acknowledgment
            final_ack = {"type": FILE_END_ACK, "transfer_id": transfer_id}
            final_data = json.dumps(final_ack).encode()
            if not conn.send_reliable(final_data):
                logger.warning("Failed to send final acknowledgment")

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

    def _manage_connections(self):
        """Manage RUDP connections lifecycle"""
        while self.running:
            try:
                current_time = time.time()
                stale_connections = []

                with self.lock:
                    for peer_id, conn in self.rudp_connections.items():
                        # Close connections that have been inactive for too long
                        if current_time - conn.last_activity > self.CONNECTION_TIMEOUT:
                            stale_connections.append(peer_id)

                # Clean up stale connections
                for peer_id in stale_connections:
                    with self.lock:
                        if peer_id in self.rudp_connections:
                            conn = self.rudp_connections[peer_id]
                            conn.close()
                            del self.rudp_connections[peer_id]
                            logger.info(f"Closed stale RUDP connection with {peer_id}")

                time.sleep(10)  # Check every 10 seconds

            except Exception as e:
                logger.error(f"Error in connection manager: {e}")
                time.sleep(5)

    def stop(self):
        """Stop the file transfer manager"""
        self.running = False

        # Close all RUDP connections
        with self.lock:
            for conn in self.rudp_connections.values():
                conn.close()
            self.rudp_connections.clear()

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

    def get_transfer_progress(self, transfer_id: str) -> Dict[str, Any]:
        """Get detailed progress information for a transfer"""
        with self.lock:
            if transfer_id not in self.transfers:
                return {"status": "unknown"}

            tf = self.transfers[transfer_id]

            if tf["direction"] == "out":
                completed = tf["chunks_sent"]
            else:
                completed = tf["chunks_received"]

            total = tf["total_chunks"]
            progress = (completed / total * 100) if total > 0 else 0

            result = {
                "transfer_id": transfer_id,
                "file_name": tf["file_name"],
                "file_size": tf["file_size"],
                "status": tf["status"],
                "progress": progress,
                "completed_chunks": completed,
                "total_chunks": total,
                "direction": tf["direction"],
            }

            if tf["status"] == "completed" and "end_time" in tf:
                duration = tf["end_time"] - tf["start_time"]
                result["duration"] = duration
                result["speed"] = tf["file_size"] / duration / 1024 if duration > 0 else 0

            if "error" in tf:
                result["error"] = tf["error"]

            return result

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
        """Legacy method for binary data handling - now handled by RUDP"""
        logger.debug("Binary data handling delegated to RUDP")

    def _handle_file_chunk(self, *args):
        """Legacy method - now handled by RUDP download worker"""
        pass

    def _process_chunk(self, *args):
        """Legacy method - now handled by RUDP download worker"""
        pass