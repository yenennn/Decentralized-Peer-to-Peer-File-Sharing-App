"""
Enhanced TCP-based file transfer with NAT traversal support.
"""
import os
import socket
import json
import time
import logging
import threading
import uuid
from pathlib import Path
from typing import Dict, Tuple, Optional, Callable, Any

logger = logging.getLogger(__name__)


class EnhancedTCPFileTransfer:
    """
    Enhanced TCP file transfer with NAT traversal and fallback mechanisms.
    """

    def __init__(self, crypto_manager, save_dir: str = "./downloads", tcp_port: int = 0):
        """Initialize enhanced TCP file transfer with NAT traversal support."""
        self.crypto = crypto_manager
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(exist_ok=True)

        # Transfer tracking
        self.transfers = {}
        self.lock = threading.Lock()
        self.progress_callback = None

        # TCP Server setup with SO_REUSEADDR and better socket options
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Enable port reuse for better NAT traversal
        try:
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass  # SO_REUSEPORT not available on Windows

        self.server_socket.bind(('0.0.0.0', tcp_port))
        self.tcp_port = self.server_socket.getsockname()[1]
        self.server_socket.listen(10)
        self.running = True

        # Start server thread
        self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self.server_thread.start()

        # Connection attempts tracking
        self.connection_attempts = {}

        logger.info(f"Enhanced TCP File Transfer server started on port {self.tcp_port}")

    def set_progress_callback(self, callback: Callable[[str, int, int], None]):
        """Set progress callback function"""
        self.progress_callback = callback

    def _server_loop(self):
        """Main server loop with better error handling"""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)  # Non-blocking accept
                try:
                    client_socket, client_addr = self.server_socket.accept()
                    logger.info(f"Incoming TCP connection from {client_addr}")

                    # Handle connection in separate thread
                    handler_thread = threading.Thread(
                        target=self._handle_incoming_transfer,
                        args=(client_socket, client_addr),
                        daemon=True
                    )
                    handler_thread.start()

                except socket.timeout:
                    continue  # Check if still running

            except Exception as e:
                if self.running:
                    logger.error(f"TCP server error: {e}")
                break

    def tcp_hole_punch(self, peer_ip: str, peer_tcp_port: int, attempts: int = 3) -> bool:
        """
        Attempt TCP hole punching by trying to connect multiple times.
        This helps with certain NAT configurations.
        """
        logger.info(f"Attempting TCP hole punching to {peer_ip}:{peer_tcp_port}")

        for attempt in range(attempts):
            try:
                # Create socket with specific options for NAT traversal
                punch_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                punch_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                # Bind to our TCP port (for symmetric NAT traversal)
                try:
                    punch_socket.bind(('0.0.0.0', self.tcp_port))
                except OSError:
                    # Port already in use, create new socket
                    punch_socket.close()
                    punch_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    punch_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                # Set short timeout for hole punching
                punch_socket.settimeout(2.0)

                try:
                    punch_socket.connect((peer_ip, peer_tcp_port))
                    # If successful, close and return True
                    punch_socket.close()
                    logger.info(f"TCP hole punching successful on attempt {attempt + 1}")
                    return True
                except (socket.timeout, ConnectionRefusedError, OSError):
                    punch_socket.close()
                    time.sleep(0.5)  # Small delay between attempts

            except Exception as e:
                logger.debug(f"TCP hole punch attempt {attempt + 1} failed: {e}")

        logger.warning(f"TCP hole punching failed after {attempts} attempts")
        return False

    def send_file(self, file_path: str, peer_id: str, peer_ip: str, peer_tcp_port: int,
                  progress_callback: Optional[Callable] = None) -> Optional[str]:
        """
        Send file with enhanced NAT traversal and retry mechanisms.
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None

        transfer_id = str(uuid.uuid4())
        file_size = os.path.getsize(file_path)

        # Track transfer
        with self.lock:
            self.transfers[transfer_id] = {
                'direction': 'out',
                'file_name': os.path.basename(file_path),
                'file_path': file_path,
                'file_size': file_size,
                'bytes_sent': 0,
                'status': 'connecting',
                'peer_id': peer_id,
                'peer_ip': peer_ip,
                'peer_tcp_port': peer_tcp_port,
                'start_time': time.time(),
                'progress_callback': progress_callback
            }

        # Start enhanced sender thread
        sender_thread = threading.Thread(
            target=self._enhanced_send_file_worker,
            args=(transfer_id,),
            daemon=True
        )
        sender_thread.start()

        return transfer_id

    def _enhanced_send_file_worker(self, transfer_id: str):
        """Enhanced file sender with multiple connection strategies."""
        with self.lock:
            tf = self.transfers[transfer_id]

        # Strategy 1: Try TCP hole punching first
        logger.info(f"Strategy 1: TCP hole punching to {tf['peer_ip']}:{tf['peer_tcp_port']}")
        if self.tcp_hole_punch(tf['peer_ip'], tf['peer_tcp_port']):
            if self._attempt_file_send(transfer_id):
                return

        # Strategy 2: Direct connection with longer timeout
        logger.info(f"Strategy 2: Direct TCP connection to {tf['peer_ip']}:{tf['peer_tcp_port']}")
        if self._attempt_file_send(transfer_id, timeout=30):
            return

        # Strategy 3: Try connecting to different ports (common NAT behavior)
        logger.info(f"Strategy 3: Trying alternative ports around {tf['peer_tcp_port']}")
        for port_offset in [-1, 1, -2, 2]:
            alt_port = tf['peer_tcp_port'] + port_offset
            if 1024 <= alt_port <= 65535:
                logger.info(f"Trying alternative port: {alt_port}")
                with self.lock:
                    self.transfers[transfer_id]['peer_tcp_port'] = alt_port
                if self._attempt_file_send(transfer_id, timeout=10):
                    return

        # All strategies failed
        logger.error(f"All connection strategies failed for transfer {transfer_id}")
        with self.lock:
            self.transfers[transfer_id]['status'] = 'failed'

    def _attempt_file_send(self, transfer_id: str, timeout: int = 15) -> bool:
        """Attempt to send file with specified timeout."""
        with self.lock:
            tf = self.transfers[transfer_id]

        try:
            # Update status
            with self.lock:
                self.transfers[transfer_id]['status'] = 'connecting'

            # Create connection with timeout
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(timeout)

            logger.info(f"Connecting to {tf['peer_ip']}:{tf['peer_tcp_port']} (timeout: {timeout}s)")
            client_socket.connect((tf['peer_ip'], tf['peer_tcp_port']))
            logger.info(f"Connected successfully to {tf['peer_ip']}:{tf['peer_tcp_port']}")

            # Update status to sending
            with self.lock:
                self.transfers[transfer_id]['status'] = 'sending'

            # Send metadata
            metadata = {
                "transfer_id": transfer_id,
                "file_name": tf['file_name'],
                "file_size": tf['file_size'],
                "peer_id": tf['peer_id']
            }

            metadata_json = json.dumps(metadata).encode()
            client_socket.send(len(metadata_json).to_bytes(4, 'big'))
            client_socket.send(metadata_json)

            # Send file data
            with open(tf['file_path'], 'rb') as f:
                bytes_sent = 0
                chunk_size = 64 * 1024  # 64KB chunks

                while bytes_sent < tf['file_size']:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    # Encrypt chunk
                    encrypted_chunk = self._encrypt(tf['peer_id'], chunk)

                    # Send chunk size then chunk data
                    client_socket.send(len(encrypted_chunk).to_bytes(4, 'big'))
                    client_socket.send(encrypted_chunk)

                    bytes_sent += len(chunk)

                    # Update progress
                    with self.lock:
                        self.transfers[transfer_id]['bytes_sent'] = bytes_sent

                    # Call progress callback
                    if tf.get('progress_callback'):
                        chunk_equivalent = int(bytes_sent / chunk_size) + 1
                        total_chunks = int(tf['file_size'] / chunk_size) + 1
                        tf['progress_callback'](transfer_id, chunk_equivalent, total_chunks)

                    # Log progress every 1MB
                    if bytes_sent % (1024 * 1024) == 0 or bytes_sent == tf['file_size']:
                        logger.info(
                            f"Sent {bytes_sent}/{tf['file_size']} bytes ({(bytes_sent / tf['file_size']) * 100:.1f}%)")

            client_socket.close()

            # Update transfer status to completed
            with self.lock:
                self.transfers[transfer_id]['status'] = 'completed'
                self.transfers[transfer_id]['end_time'] = time.time()
                duration = self.transfers[transfer_id]['end_time'] - self.transfers[transfer_id]['start_time']
                speed = tf['file_size'] / duration / 1024 if duration > 0 else 0
                logger.info(f"Upload of {tf['file_name']} completed - {speed:.2f} KB/s")

            return True

        except Exception as e:
            logger.error(f"File send attempt failed: {e}")
            return False

    def _handle_incoming_transfer(self, client_socket: socket.socket, client_addr: Tuple[str, int]):
        """Handle incoming file transfer with better error handling."""
        transfer_id = None
        try:
            # Set longer timeout for file transfers
            client_socket.settimeout(300)  # 5 minutes

            # Receive metadata
            metadata_size_data = client_socket.recv(4)
            if len(metadata_size_data) != 4:
                logger.error("Failed to receive metadata size")
                return

            metadata_size = int.from_bytes(metadata_size_data, 'big')
            metadata_data = b''
            while len(metadata_data) < metadata_size:
                chunk = client_socket.recv(metadata_size - len(metadata_data))
                if not chunk:
                    break
                metadata_data += chunk

            metadata = json.loads(metadata_data.decode())
            transfer_id = metadata['transfer_id']
            file_name = metadata['file_name']
            file_size = metadata['file_size']
            peer_id = metadata.get('peer_id', 'unknown')

            logger.info(f"Receiving file: {file_name} ({file_size} bytes) from {peer_id}")

            # Track transfer
            with self.lock:
                self.transfers[transfer_id] = {
                    'direction': 'in',
                    'file_name': file_name,
                    'file_size': file_size,
                    'bytes_received': 0,
                    'status': 'receiving',
                    'peer_id': peer_id,
                    'start_time': time.time()
                }

            # Receive file data
            file_path = self.save_dir / file_name
            bytes_received = 0
            chunk_size = 64 * 1024

            with open(file_path, 'wb') as f:
                while bytes_received < file_size:
                    # Receive encrypted chunk size
                    chunk_size_data = client_socket.recv(4)
                    if len(chunk_size_data) != 4:
                        break

                    encrypted_chunk_size = int.from_bytes(chunk_size_data, 'big')

                    # Receive encrypted chunk data
                    encrypted_chunk = b''
                    while len(encrypted_chunk) < encrypted_chunk_size:
                        remaining = encrypted_chunk_size - len(encrypted_chunk)
                        data = client_socket.recv(min(remaining, 8192))
                        if not data:
                            break
                        encrypted_chunk += data

                    # Decrypt and write
                    try:
                        decrypted_chunk = self._decrypt(peer_id, encrypted_chunk)
                        f.write(decrypted_chunk)
                        bytes_received += len(decrypted_chunk)

                        # Update progress
                        with self.lock:
                            self.transfers[transfer_id]['bytes_received'] = bytes_received

                        # Call progress callback
                        if self.progress_callback:
                            chunk_equivalent = int(bytes_received / chunk_size) + 1
                            total_chunks = int(file_size / chunk_size) + 1
                            self.progress_callback(transfer_id, chunk_equivalent, total_chunks)

                        # Log progress every 1MB
                        if bytes_received % (1024 * 1024) == 0 or bytes_received == file_size:
                            logger.info(
                                f"Received {bytes_received}/{file_size} bytes ({(bytes_received / file_size) * 100:.1f}%)")

                    except Exception as e:
                        logger.error(f"Decryption failed: {e}")
                        break

            # Update transfer status
            with self.lock:
                if bytes_received == file_size:
                    self.transfers[transfer_id]['status'] = 'completed'
                    self.transfers[transfer_id]['end_time'] = time.time()
                    duration = self.transfers[transfer_id]['end_time'] - self.transfers[transfer_id]['start_time']
                    speed = file_size / duration / 1024 if duration > 0 else 0
                    logger.info(f"File {file_name} received successfully - {speed:.2f} KB/s")
                else:
                    self.transfers[transfer_id]['status'] = 'failed'
                    logger.error(f"File transfer incomplete: {bytes_received}/{file_size} bytes")

        except Exception as e:
            logger.error(f"Error handling incoming transfer: {e}")
            if transfer_id:
                with self.lock:
                    if transfer_id in self.transfers:
                        self.transfers[transfer_id]['status'] = 'failed'
        finally:
            client_socket.close()

    def get_transfer_status(self, transfer_id: str) -> Dict:
        """Get transfer status with enhanced information."""
        with self.lock:
            if transfer_id not in self.transfers:
                return {'status': 'unknown'}

            transfer = self.transfers[transfer_id].copy()

        # Calculate progress
        if transfer['direction'] == 'out':
            bytes_processed = transfer.get('bytes_sent', 0)
        else:
            bytes_processed = transfer.get('bytes_received', 0)

        progress = (bytes_processed / transfer['file_size']) * 100 if transfer['file_size'] > 0 else 0

        # Calculate speed
        speed = 0
        if transfer['status'] == 'completed' and 'end_time' in transfer:
            duration = transfer['end_time'] - transfer['start_time']
            if duration > 0:
                speed = transfer['file_size'] / duration / 1024

        return {
            'transfer_id': transfer_id,
            'file_name': transfer['file_name'],
            'file_size': transfer['file_size'],
            'status': transfer['status'],
            'progress': progress,
            'speed': speed,
            'direction': transfer['direction']
        }

    def list_transfers(self) -> Dict[str, Dict]:
        """Get status of all transfers."""
        with self.lock:
            return {tid: self.get_transfer_status(tid) for tid in self.transfers.keys()}

    def _encrypt(self, peer_id: str, plaintext: bytes) -> bytes:
        """Encrypt data for peer."""
        if hasattr(self.crypto, "encrypt_data"):
            return self.crypto.encrypt_data(peer_id, plaintext)
        return plaintext

    def _decrypt(self, peer_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data from peer."""
        if hasattr(self.crypto, "decrypt_data"):
            return self.crypto.decrypt_data(peer_id, ciphertext)
        return ciphertext

    def stop(self):
        """Stop the TCP server."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        logger.info("Enhanced TCP File Transfer server stopped")