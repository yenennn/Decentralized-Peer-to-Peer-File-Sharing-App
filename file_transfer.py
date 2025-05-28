"""
Enhanced reliable UDP file transfer using the srudp library.
Simple and reliable file transfer with proper library usage.
"""

import json
import logging
import math
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple
import socket

try:
    from srudp import SecureReliableSocket
except ImportError:
    print("Installing srudp library...")
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "srudp"])
    from srudp import SecureReliableSocket

logger = logging.getLogger(__name__)

# Message type constants
FILE_INIT = "file_init"
FILE_INIT_ACK = "file_init_ack"
FILE_CHUNK = "file_chunk"
FILE_END = "file_end"
FILE_END_ACK = "file_end_ack"


class FileTransfer:
    """Simple and reliable file transfer using srudp library"""

    # Configuration
    DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KiB - larger chunks since reliability is handled by srudp
    CONNECTION_TIMEOUT = 30.0
    TRANSFER_TIMEOUT = 300.0  # 5 minutes

    def __init__(self, sock, crypto_manager):
        self.base_socket = sock  # Original UDP socket (for compatibility)
        self.crypto = crypto_manager
        self.lock = threading.Lock()
        self.transfers: Dict[str, Dict[str, Any]] = {}
        self.save_dir: Path = Path.cwd()
        self.progress_callback: Optional[Callable[[str, int, int], None]] = None
        self.reliable_connections: Dict[str, SecureReliableSocket] = {}  # peer_id -> srudp socket

    def receive_file(self, save_dir: str, progress_callback: Callable[[str, int, int], None]):
        """Configure where incoming files are stored and how to report progress."""
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)
        self.progress_callback = progress_callback

    def get_reliable_connection(self, peer_addr: Tuple[str, int]) -> SecureReliableSocket:
        """Get or create a reliable connection to peer"""
        peer_key = f"{peer_addr[0]}:{peer_addr[1]}"

        with self.lock:
            if peer_key in self.reliable_connections:
                return self.reliable_connections[peer_key]

            # Create new reliable socket
            reliable_sock = SecureReliableSocket()
            reliable_sock.settimeout(self.CONNECTION_TIMEOUT)

            self.reliable_connections[peer_key] = reliable_sock
            return reliable_sock

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
            target=self._upload_worker,
            args=(transfer_id,),
            daemon=True
        )
        upload_thread.start()
        return transfer_id

    def _upload_worker(self, transfer_id: str):
        """Upload worker using srudp for reliable transmission"""
        with self.lock:
            tf = self.transfers[transfer_id]

        peer_addr = tf["peer_addr"]
        peer_id = tf["peer_id"]
        reliable_sock = None

        try:
            # Create reliable connection
            reliable_sock = self.get_reliable_connection(peer_addr)

            logger.info(f"Connecting to {peer_addr} for file transfer...")
            reliable_sock.connect(peer_addr)
            logger.info(f"Connected to {peer_addr}")

            with self.lock:
                tf["status"] = "uploading"

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
            reliable_sock.send(init_data)
            logger.info(f"Sent file init for {tf['file_name']}")

            # Wait for acknowledgment
            ack_data = reliable_sock.recv(1024)
            ack_msg = json.loads(ack_data.decode())

            if ack_msg.get("type") != FILE_INIT_ACK:
                raise Exception("Invalid acknowledgment received")

            logger.info("Received file init acknowledgment")

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

                    # Send chunk header
                    chunk_header = json.dumps(chunk_msg).encode()
                    reliable_sock.send(chunk_header)

                    # Send chunk data
                    reliable_sock.send(encrypted_data)

                    with self.lock:
                        tf["chunks_sent"] = chunk_index + 1

                    # Update progress
                    now = time.time()
                    if now - last_progress_update > 1.0:
                        if tf["progress_cb"]:
                            tf["progress_cb"](transfer_id, chunk_index + 1, tf["total_chunks"])
                        last_progress_update = now

                    logger.debug(f"Sent chunk {chunk_index + 1}/{tf['total_chunks']}")

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
            reliable_sock.send(end_data)

            # Wait for final acknowledgment
            final_ack_data = reliable_sock.recv(1024)
            final_ack_msg = json.loads(final_ack_data.decode())

            if final_ack_msg.get("type") == FILE_END_ACK:
                with self.lock:
                    tf["status"] = "completed"
                    tf["end_time"] = time.time()
                    duration = tf["end_time"] - tf["start_time"]
                    speed = tf["file_size"] / duration / 1024 if duration > 0 else 0
                    logger.info(f"Upload of {tf['file_name']} completed - {speed:.2f} KB/s")
            else:
                raise Exception("Invalid final acknowledgment")

        except Exception as e:
            logger.error(f"Upload failed for transfer {transfer_id}: {e}")
            with self.lock:
                tf["status"] = "failed"
                tf["error"] = str(e)
        finally:
            if reliable_sock:
                try:
                    reliable_sock.close()
                except:
                    pass

    def handle_message(self, data: bytes, addr: Tuple[str, int], peer_id: str):
        """Handle incoming messages - mainly for file init over regular UDP"""
        try:
            msg = json.loads(data.decode())
        except Exception:
            logger.debug("handle_message: not JSON – ignoring")
            return

        mtype = msg.get("type")
        if mtype == FILE_INIT:
            self._handle_file_init(msg, addr, peer_id)

    def _handle_file_init(self, msg: Dict[str, Any], addr: Tuple[str, int], peer_id: str):
        """Handle file initialization and start reliable download"""
        transfer_id = msg["transfer_id"]

        with self.lock:
            if transfer_id in self.transfers:
                return  # Already handling

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

        # Start download worker
        download_thread = threading.Thread(
            target=self._download_worker,
            args=(transfer_id,),
            daemon=True
        )
        download_thread.start()

    def _download_worker(self, transfer_id: str):
        """Download worker using srudp for reliable reception"""
        with self.lock:
            tf = self.transfers[transfer_id]

        peer_addr = tf["peer_addr"]
        peer_id = tf["peer_id"]
        reliable_sock = None

        try:
            # Create reliable socket for listening
            reliable_sock = SecureReliableSocket()
            reliable_sock.settimeout(self.CONNECTION_TIMEOUT)

            # Bind to a local port for the peer to connect to
            local_port = self.base_socket.getsockname()[1] + 1  # Use next port
            reliable_sock.bind(('0.0.0.0', local_port))
            reliable_sock.listen(1)

            logger.info(f"Listening for reliable connection on port {local_port}")

            # Send acknowledgment with our listening port
            ack_msg = {
                "type": FILE_INIT_ACK,
                "transfer_id": transfer_id,
                "reliable_port": local_port
            }
            ack_data = json.dumps(ack_msg).encode()
            self.base_socket.sendto(ack_data, peer_addr)

            # Accept reliable connection
            conn, addr = reliable_sock.accept()
            logger.info(f"Accepted reliable connection from {addr}")

            # Prepare file for writing
            dest_path = self.save_dir / tf["file_name"]

            with open(dest_path, "wb") as file_handle:
                chunks_received = 0
                last_progress_update = time.time()

                while chunks_received < tf["total_chunks"]:
                    # Receive chunk header
                    header_data = conn.recv(4096)
                    if not header_data:
                        break

                    try:
                        chunk_msg = json.loads(header_data.decode())
                    except:
                        break

                    if chunk_msg.get("type") == FILE_CHUNK:
                        chunk_size = chunk_msg["chunk_size"]
                        chunk_index = chunk_msg["chunk_index"]

                        # Receive chunk data
                        chunk_data = conn.recv(chunk_size)
                        if len(chunk_data) != chunk_size:
                            raise Exception(f"Incomplete chunk data received")

                        # Decrypt and write chunk
                        try:
                            plaintext = self._decrypt(peer_id, chunk_data)
                            file_handle.write(plaintext)
                            file_handle.flush()
                        except Exception as e:
                            raise Exception(f"Decryption failed: {e}")

                        chunks_received += 1

                        with self.lock:
                            tf["chunks_received"] = chunks_received

                        # Update progress
                        now = time.time()
                        if now - last_progress_update > 1.0:
                            if self.progress_callback:
                                self.progress_callback(transfer_id, chunks_received, tf["total_chunks"])
                            last_progress_update = now

                        logger.debug(f"Received chunk {chunk_index + 1}/{tf['total_chunks']}")

                    elif chunk_msg.get("type") == FILE_END:
                        # Transfer completed
                        break

            # Send final acknowledgment
            final_ack = {"type": FILE_END_ACK, "transfer_id": transfer_id}
            final_data = json.dumps(final_ack).encode()
            conn.send(final_data)

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
        finally:
            if reliable_sock:
                try:
                    reliable_sock.close()
                except:
                    pass

    def stop(self):
        """Stop the file transfer manager"""
        with self.lock:
            for sock in self.reliable_connections.values():
                try:
                    sock.close()
                except:
                    pass
            self.reliable_connections.clear()

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

    def get_transfer_status(self, transfer_id: str) -> Dict:
        """Get transfer status - compatible with existing API"""
        with self.lock:
            if transfer_id not in self.transfers:
                return {'status': 'unknown'}

            tf = self.transfers[transfer_id]

            if tf["direction"] == "out":
                completed = tf["chunks_sent"]
            else:
                completed = tf["chunks_received"]

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

            if 'error' in tf:
                result['error'] = tf['error']

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

    # Legacy compatibility methods for existing P2P node
    def handle_binary_data(self, *args):
        """Legacy method - not needed with reliable sockets"""
        pass

    def _handle_file_chunk(self, *args):
        """Legacy method - handled by reliable connection"""
        pass

    def _process_chunk(self, *args):
        """Legacy method - handled by reliable connection"""
        pass