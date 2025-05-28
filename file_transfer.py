"""
Enhanced reliable UDP file transfer using the rudp library.
Clean implementation that relies on library for all UDP reliability.
"""

import json
import logging
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

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
FILE_END = "file_end"
FILE_END_ACK = "file_end_ack"


class FileTransfer:
    """Simple and reliable file transfer using rudp library"""

    # Configuration
    DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KiB
    CONNECTION_TIMEOUT = 30.0
    TRANSFER_TIMEOUT = 300.0  # 5 minutes

    def __init__(self, base_socket, crypto_manager):
        self.base_socket = base_socket
        self.crypto = crypto_manager
        self.lock = threading.Lock()
        self.transfers: Dict[str, Dict[str, Any]] = {}
        self.save_dir: Path = Path.cwd()
        self.progress_callback: Optional[Callable[[str, int, int], None]] = None

        # RUDP server for incoming connections
        self.rudp_server = None
        self.server_thread = None
        self.is_running = False

        self._start_server()

    def _start_server(self):
        """Start RUDP server for incoming file transfers"""
        try:
            # Get a free port for RUDP server
            server_port = self.base_socket.getsockname()[1] + 1

            self.rudp_server = rudp.RUDPServer(('0.0.0.0', server_port))
            self.rudp_server.settimeout(1.0)  # For periodic checks

            self.is_running = True
            self.server_thread = threading.Thread(target=self._server_worker, daemon=True)
            self.server_thread.start()

            logger.info(f"RUDP server started on port {server_port}")

        except Exception as e:
            logger.error(f"Failed to start RUDP server: {e}")

    def _server_worker(self):
        """Server worker to handle incoming RUDP connections"""
        while self.is_running and self.rudp_server:
            try:
                conn, addr = self.rudp_server.accept()
                logger.info(f"Accepted RUDP connection from {addr}")

                # Handle connection in separate thread
                handler_thread = threading.Thread(
                    target=self._handle_incoming_connection,
                    args=(conn, addr),
                    daemon=True
                )
                handler_thread.start()

            except rudp.timeout:
                continue  # Timeout is expected for periodic checks
            except Exception as e:
                if self.is_running:
                    logger.error(f"Server error: {e}")

    def _handle_incoming_connection(self, conn, addr):
        """Handle incoming file transfer connection"""
        try:
            # Receive file initialization
            init_data = conn.recv(4096)
            init_msg = json.loads(init_data.decode())

            if init_msg.get("type") != FILE_INIT:
                logger.error("Expected FILE_INIT message")
                return

            transfer_id = init_msg["transfer_id"]
            peer_id = init_msg.get("peer_id", "unknown")

            with self.lock:
                self.transfers[transfer_id] = {
                    "direction": "in",
                    "file_name": init_msg["file_name"],
                    "file_size": init_msg["file_size"],
                    "chunk_size": init_msg["chunk_size"],
                    "total_chunks": init_msg["total_chunks"],
                    "chunks_received": 0,
                    "status": "receiving",
                    "peer_addr": addr,
                    "peer_id": peer_id,
                    "start_time": time.time(),
                }

            logger.info(f"Receiving file {init_msg['file_name']} ({init_msg['file_size']} bytes)")

            # Send acknowledgment
            ack_msg = {"type": FILE_INIT_ACK, "transfer_id": transfer_id}
            conn.send(json.dumps(ack_msg).encode())

            # Receive file
            self._receive_file_data(conn, transfer_id)

        except Exception as e:
            logger.error(f"Error handling incoming connection: {e}")
        finally:
            try:
                conn.close()
            except:
                pass

    def _receive_file_data(self, conn, transfer_id: str):
        """Receive file data through RUDP connection"""
        with self.lock:
            tf = self.transfers[transfer_id]

        dest_path = self.save_dir / tf["file_name"]

        try:
            with open(dest_path, "wb") as file_handle:
                chunks_received = 0
                last_progress_update = time.time()

                while chunks_received < tf["total_chunks"]:
                    # Receive chunk message
                    chunk_data = conn.recv(tf["chunk_size"] + 1024)  # Extra space for headers
                    if not chunk_data:
                        break

                    try:
                        chunk_msg = json.loads(chunk_data.decode())
                    except:
                        # Assume it's raw file data if not JSON
                        if tf.get("receiving_data", False):
                            # Decrypt and write
                            plaintext = self._decrypt(tf["peer_id"], chunk_data)
                            file_handle.write(plaintext)
                            chunks_received += 1
                        continue

                    if chunk_msg.get("type") == FILE_CHUNK:
                        tf["receiving_data"] = True
                        # Next message will be the actual data
                        continue

                    elif chunk_msg.get("type") == FILE_END:
                        # Send final ACK
                        final_ack = {"type": FILE_END_ACK, "transfer_id": transfer_id}
                        conn.send(json.dumps(final_ack).encode())
                        break

                with self.lock:
                    tf["chunks_received"] = chunks_received
                    tf["status"] = "completed"
                    tf["end_time"] = time.time()

                duration = tf["end_time"] - tf["start_time"]
                speed = tf["file_size"] / duration / 1024 if duration > 0 else 0
                logger.info(f"Download completed - {speed:.2f} KB/s")

        except Exception as e:
            logger.error(f"Download failed: {e}")
            with self.lock:
                tf["status"] = "failed"
                tf["error"] = str(e)

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
        total_chunks = (file_size + self.DEFAULT_CHUNK_SIZE - 1) // self.DEFAULT_CHUNK_SIZE

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

        # Start upload in separate thread
        upload_thread = threading.Thread(
            target=self._upload_file,
            args=(transfer_id,),
            daemon=True
        )
        upload_thread.start()
        return transfer_id

    def _upload_file(self, transfer_id: str):
        """Upload file using RUDP client connection"""
        with self.lock:
            tf = self.transfers[transfer_id]

        peer_addr = tf["peer_addr"]
        # Assume peer is listening on port + 1
        rudp_peer_addr = (peer_addr[0], peer_addr[1] + 1)

        client = None
        try:
            # Create RUDP client connection
            client = rudp.RUDPClient()
            client.settimeout(self.CONNECTION_TIMEOUT)

            logger.info(f"Connecting to {rudp_peer_addr} via RUDP...")
            client.connect(rudp_peer_addr)
            logger.info(f"Connected to {rudp_peer_addr}")

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
                "peer_id": tf["peer_id"],
            }

            client.send(json.dumps(init_msg).encode())
            logger.info(f"Sent file init for {tf['file_name']}")

            # Wait for acknowledgment
            ack_data = client.recv(1024)
            ack_msg = json.loads(ack_data.decode())

            if ack_msg.get("type") != FILE_INIT_ACK:
                raise Exception("Invalid acknowledgment received")

            logger.info("Received file init acknowledgment, starting transfer...")

            # Send file chunks
            with open(tf["file_path"], "rb") as file_handle:
                for chunk_index in range(tf["total_chunks"]):
                    # Read chunk
                    chunk_data = file_handle.read(self.DEFAULT_CHUNK_SIZE)
                    if not chunk_data:
                        break

                    # Encrypt chunk
                    encrypted_data = self._encrypt(tf["peer_id"], chunk_data)

                    # Send chunk header
                    chunk_msg = {
                        "type": FILE_CHUNK,
                        "transfer_id": transfer_id,
                        "chunk_index": chunk_index,
                        "chunk_size": len(encrypted_data),
                    }
                    client.send(json.dumps(chunk_msg).encode())

                    # Send chunk data
                    client.send(encrypted_data)

                    with self.lock:
                        tf["chunks_sent"] = chunk_index + 1

                    # Update progress
                    if tf["progress_cb"]:
                        tf["progress_cb"](transfer_id, chunk_index + 1, tf["total_chunks"])

                    logger.debug(f"Sent chunk {chunk_index + 1}/{tf['total_chunks']}")

                    # Check for cancellation
                    with self.lock:
                        if tf["status"] == "cancelled":
                            raise Exception("Transfer cancelled")

            # Send completion message
            end_msg = {"type": FILE_END, "transfer_id": transfer_id}
            client.send(json.dumps(end_msg).encode())

            # Wait for final acknowledgment
            final_ack_data = client.recv(1024)
            final_ack_msg = json.loads(final_ack_data.decode())

            if final_ack_msg.get("type") == FILE_END_ACK:
                with self.lock:
                    tf["status"] = "completed"
                    tf["end_time"] = time.time()
                    duration = tf["end_time"] - tf["start_time"]
                    speed = tf["file_size"] / duration / 1024 if duration > 0 else 0
                    logger.info(f"Upload completed - {speed:.2f} KB/s")
            else:
                raise Exception("Invalid final acknowledgment")

        except Exception as e:
            logger.error(f"Upload failed for transfer {transfer_id}: {e}")
            with self.lock:
                tf["status"] = "failed"
                tf["error"] = str(e)
        finally:
            if client:
                try:
                    client.close()
                except:
                    pass

    def handle_message(self, data: bytes, addr: Tuple[str, int], peer_id: str):
        """Handle incoming messages (compatibility method)"""
        # With RUDP, most handling is done through the server
        # This method can be used for coordination messages if needed
        try:
            msg = json.loads(data.decode())
            logger.debug(f"Received coordination message: {msg.get('type', 'unknown')}")
        except Exception:
            pass

    def stop(self):
        """Stop the file transfer manager"""
        self.is_running = False

        if self.rudp_server:
            try:
                self.rudp_server.close()
            except:
                pass

        if self.server_thread:
            self.server_thread.join(timeout=2.0)

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
        """Get transfer status"""
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

    # Legacy compatibility methods
    def handle_binary_data(self, *args):
        """Legacy method - not needed with RUDP"""
        pass

    def _handle_file_chunk(self, *args):
        """Legacy method - handled by RUDP connection"""
        pass

    def _process_chunk(self, *args):
        """Legacy method - handled by RUDP connection"""
        pass