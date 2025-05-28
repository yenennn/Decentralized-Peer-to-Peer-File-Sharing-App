"""
TCP-based file transfer implementation for P2P network.
Replaces the UDP-based file transfer with reliable TCP connections.
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

class TCPFileTransfer:
    """
    TCP-based file transfer manager for P2P networks.
    Each peer acts as both a TCP server (to receive files) and TCP client (to send files).
    """

    def __init__(self, crypto_manager, save_dir: str = "./downloads", tcp_port: int = 0):
        """
        Initialize TCP file transfer manager.

        Args:
            crypto_manager: Encryption manager for secure transfers
            save_dir: Directory to save received files
            tcp_port: TCP port to listen on (0 = auto-assign)
        """
        self.crypto = crypto_manager
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(exist_ok=True)

        # Transfer tracking
        self.transfers = {}
        self.lock = threading.Lock()

        # Progress callback
        self.progress_callback = None

        # TCP Server setup - Every peer is a server
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', tcp_port))
        self.tcp_port = self.server_socket.getsockname()[1]
        self.server_socket.listen(10)
        self.running = True

        # Start server thread to accept incoming connections
        self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self.server_thread.start()

        logger.info(f"TCP File Transfer server started on port {self.tcp_port}")

    def set_progress_callback(self, callback: Callable[[str, int, int], None]):
        """Set progress callback function for transfer updates"""
        self.progress_callback = callback

    def _server_loop(self):
        """Main server loop to accept incoming file transfer connections"""
        while self.running:
            try:
                client_socket, client_addr = self.server_socket.accept()
                logger.info(f"Incoming TCP file transfer connection from {client_addr}")

                # Handle each connection in separate thread
                handler_thread = threading.Thread(
                    target=self._handle_incoming_transfer,
                    args=(client_socket, client_addr),
                    daemon=True
                )
                handler_thread.start()

            except Exception as e:
                if self.running:  # Only log if we're still supposed to be running
                    logger.error(f"TCP server accept error: {e}")
                break

    def _handle_incoming_transfer(self, client_socket: socket.socket, client_addr: Tuple[str, int]):
        """
        Handle incoming file transfer from another peer.
        This runs when another peer connects to send us a file.
        """
        transfer_id = None
        try:
            # Set socket timeout to prevent hanging
            client_socket.settimeout(300)  # 5 minutes timeout

            # Step 1: Receive metadata about the file
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

            # Step 2: Receive file data
            file_path = self.save_dir / file_name
            bytes_received = 0
            chunk_size = 64 * 1024  # 64KB chunks

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

                    # Decrypt and write chunk
                    try:
                        decrypted_chunk = self._decrypt(peer_id, encrypted_chunk)
                        f.write(decrypted_chunk)
                        bytes_received += len(decrypted_chunk)

                        # Update progress
                        with self.lock:
                            self.transfers[transfer_id]['bytes_received'] = bytes_received

                        # Call progress callback
                        if self.progress_callback:
                            # Convert bytes to "chunks" for compatibility with existing UI
                            chunk_equivalent = int(bytes_received / chunk_size) + 1
                            total_chunks = int(file_size / chunk_size) + 1
                            self.progress_callback(transfer_id, chunk_equivalent, total_chunks)

                        logger.debug(f"Received {bytes_received}/{file_size} bytes ({(bytes_received/file_size)*100:.1f}%)")

                    except Exception as e:
                        logger.error(f"Decryption failed: {e}")
                        break

            # Step 3: Update transfer status
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

    def send_file(self, file_path: str, peer_id: str, peer_ip: str, peer_tcp_port: int,
                  progress_callback: Optional[Callable] = None) -> Optional[str]:
        """
        Send file to another peer via TCP.
        This connects to the peer's TCP server and uploads the file.

        Args:
            file_path: Path to file to send
            peer_id: Target peer ID
            peer_ip: Target peer IP address
            peer_tcp_port: Target peer TCP port
            progress_callback: Optional progress callback function

        Returns:
            Transfer ID if successful, None otherwise
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
                'status': 'sending',
                'peer_id': peer_id,
                'peer_ip': peer_ip,
                'peer_tcp_port': peer_tcp_port,
                'start_time': time.time(),
                'progress_callback': progress_callback
            }

        # Start sender thread
        sender_thread = threading.Thread(
            target=self._send_file_worker,
            args=(transfer_id,),
            daemon=True
        )
        sender_thread.start()

        return transfer_id

    def _send_file_worker(self, transfer_id: str):
        """
        Worker thread to send file to peer.
        This acts as a TCP client connecting to the peer's server.
        """
        with self.lock:
            tf = self.transfers[transfer_id]

        try:
            # Step 1: Connect to peer's TCP server
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(300)  # 5 minutes timeout

            logger.info(f"Connecting to {tf['peer_ip']}:{tf['peer_tcp_port']} for transfer {transfer_id}")
            client_socket.connect((tf['peer_ip'], tf['peer_tcp_port']))
            logger.info(f"Connected successfully to {tf['peer_ip']}:{tf['peer_tcp_port']}")

            # Step 2: Send file metadata
            metadata = {
                "transfer_id": transfer_id,
                "file_name": tf['file_name'],
                "file_size": tf['file_size'],
                "peer_id": tf['peer_id']
            }

            metadata_json = json.dumps(metadata).encode()
            client_socket.send(len(metadata_json).to_bytes(4, 'big'))
            client_socket.send(metadata_json)

            # Step 3: Send file data in chunks
            with open(tf['file_path'], 'rb') as f:
                bytes_sent = 0
                chunk_size = 64 * 1024  # 64KB chunks

                while bytes_sent < tf['file_size']:
                    # Read chunk from file
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    # Encrypt chunk
                    encrypted_chunk = self._encrypt(tf['peer_id'], chunk)

                    # Send encrypted chunk size, then encrypted chunk data
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

                    logger.debug(f"Sent {bytes_sent}/{tf['file_size']} bytes ({(bytes_sent/tf['file_size'])*100:.1f}%)")

            client_socket.close()

            # Step 4: Update transfer status
            with self.lock:
                self.transfers[transfer_id]['status'] = 'completed'
                self.transfers[transfer_id]['end_time'] = time.time()
                duration = self.transfers[transfer_id]['end_time'] - self.transfers[transfer_id]['start_time']
                speed = tf['file_size'] / duration / 1024 if duration > 0 else 0
                logger.info(f"Upload of {tf['file_name']} completed - {speed:.2f} KB/s")

        except Exception as e:
            logger.error(f"Error sending file: {e}")
            with self.lock:
                self.transfers[transfer_id]['status'] = 'failed'

    def get_transfer_status(self, transfer_id: str) -> Dict:
        """Get detailed status of a file transfer"""
        with self.lock:
            if transfer_id not in self.transfers:
                return {'status': 'unknown'}

            transfer = self.transfers[transfer_id].copy()

        # Calculate progress percentage
        if transfer['direction'] == 'out':
            bytes_processed = transfer.get('bytes_sent', 0)
        else:
            bytes_processed = transfer.get('bytes_received', 0)

        progress = (bytes_processed / transfer['file_size']) * 100 if transfer['file_size'] > 0 else 0

        # Calculate transfer speed
        speed = 0
        if transfer['status'] == 'completed' and 'end_time' in transfer:
            duration = transfer['end_time'] - transfer['start_time']
            if duration > 0:
                speed = transfer['file_size'] / duration / 1024  # KB/s

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
        """Get status of all transfers"""
        with self.lock:
            return {tid: self.get_transfer_status(tid) for tid in self.transfers.keys()}

    def _encrypt(self, peer_id: str, plaintext: bytes) -> bytes:
        """Encrypt data for specific peer"""
        if hasattr(self.crypto, "encrypt_data"):
            return self.crypto.encrypt_data(peer_id, plaintext)
        return plaintext

    def _decrypt(self, peer_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data from specific peer"""
        if hasattr(self.crypto, "decrypt_data"):
            return self.crypto.decrypt_data(peer_id, ciphertext)
        return ciphertext

    def stop(self):
        """Stop the TCP file transfer server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        logger.info("TCP File Transfer server stopped")