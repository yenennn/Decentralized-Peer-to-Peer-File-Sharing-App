"""
Main P2P node implementation with QUIC file transfer.
Handles peer connections, NAT traversal using STUN, and QUIC-based file transfers.
"""
import os
import socket
import json
import time
import logging
import threading
import uuid
import base64
import queue
import asyncio
from typing import Dict, List, Tuple, Optional, Callable, Any

from stun_client import STUNClient
from crypto import CryptoManager
from file_transfer import FileTransfer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class P2PNode:
    """
    P2P node for decentralized file sharing with QUIC.
    Handles NAT traversal with STUN, peer connections, and QUIC-based file transfers.
    """

    def __init__(self, local_port: int = 0, quic_port: int = 0, save_dir: str = "./downloads"):
        """
        Initialize the P2P node.

        Args:
            local_port: Local UDP port for peer discovery. If 0, a random port will be assigned.
            quic_port: Local port for QUIC file transfers. If 0, a random port will be assigned.
            save_dir: Directory to save received files
        """
        self.node_id = str(uuid.uuid4())
        self.local_port = local_port
        self.quic_port = quic_port if quic_port != 0 else (local_port + 1000 if local_port != 0 else 4433)
        self.save_dir = os.path.abspath(save_dir)
        self.peers = {}  # {peer_id: {addr: (ip, port), quic_port: port, public_key: key}}
        self.running = False
        self.stun_client = STUNClient(local_port)
        self.crypto_manager = CryptoManager()
        self.socket = None
        self.file_transfer = None
        self.incoming_messages = queue.Queue()

        # Create save directory if it doesn't exist
        os.makedirs(self.save_dir, exist_ok=True)

        # NAT information
        self.nat_type = None
        self.external_ip = None
        self.external_port = None
        self.external_quic_port = None

        # QUIC event loop
        self.quic_loop = None
        self.quic_thread = None

    def start(self) -> Tuple[str, int, int]:
        """
        Start the P2P node.

        Returns:
            Tuple of (external_ip, external_port, quic_port)
        """
        # Discover NAT type and external IP/port using STUN
        self.nat_type, self.external_ip, self.external_port = self.stun_client.discover_nat()

        if not self.external_ip or not self.external_port:
            raise RuntimeError("Failed to discover external IP and port")

        # Create UDP socket for peer discovery
        self.socket = self.stun_client.create_socket()

        # Calculate external QUIC port (assumption: same NAT mapping offset)
        self.external_quic_port = self.external_port + (self.quic_port - self.local_port)

        # Initialize QUIC-based file transfer manager
        self.file_transfer = FileTransfer(self.crypto_manager)
        self.file_transfer.receive_file(self.save_dir, self._on_transfer_progress)

        # Start QUIC server in a separate thread
        self._start_quic_server()

        # Start message handling thread for peer discovery
        self.running = True
        self.message_thread = threading.Thread(target=self._handle_messages)
        self.message_thread.daemon = True
        self.message_thread.start()

        logger.info(f"P2P node started with ID: {self.node_id}")
        logger.info(f"NAT Type: {self.nat_type}")
        logger.info(f"External IP: {self.external_ip}")
        logger.info(f"External Port (UDP): {self.external_port}")
        logger.info(f"External QUIC Port: {self.external_quic_port}")
        logger.info(f"Local Port (UDP): {self.local_port}")
        logger.info(f"Local QUIC Port: {self.quic_port}")

        return self.external_ip, self.external_port, self.external_quic_port

    def _start_quic_server(self):
        """Start the QUIC server in a separate thread"""
        def run_quic_server():
            self.quic_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.quic_loop)

            try:
                # Start QUIC server
                self.quic_loop.run_until_complete(
                    self.file_transfer.start_server(self.quic_port)
                )
                # Keep the loop running
                self.quic_loop.run_forever()
            except Exception as e:
                logger.error(f"QUIC server error: {e}")
            finally:
                self.quic_loop.close()

        self.quic_thread = threading.Thread(target=run_quic_server, daemon=True)
        self.quic_thread.start()

        # Wait a bit for server to start
        time.sleep(1)

    def stop(self) -> None:
        """Stop the P2P node"""
        self.running = False

        # Stop QUIC server
        if self.quic_loop and self.quic_loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self.file_transfer.stop_server(self.quic_port),
                self.quic_loop
            )
            self.quic_loop.call_soon_threadsafe(self.quic_loop.stop)

        if self.socket:
            self.socket.close()
        logger.info("P2P node stopped")

    def connect_to_peer(self, peer_id: str, peer_ip: str, peer_port: int, peer_quic_port: int = None) -> bool:
        """
        Connect to a peer using their external IP and ports.

        Args:
            peer_id: Unique identifier for the peer
            peer_ip: External IP of the peer
            peer_port: External UDP port of the peer (for discovery)
            peer_quic_port: External QUIC port of the peer (for file transfer)

        Returns:
            True if connection was successful, False otherwise
        """
        if peer_quic_port is None:
            # Assume same offset as this node
            peer_quic_port = peer_port + (self.quic_port - self.local_port)

        logger.info(f"Connecting to peer {peer_id} at {peer_ip}:{peer_port} (QUIC: {peer_quic_port})")

        # Perform UDP hole punching for discovery
        if not self.stun_client.punch_hole(peer_ip, peer_port):
            logger.error(f"Failed to punch hole to {peer_ip}:{peer_port}")
            return False

        # Store peer information
        self.peers[peer_id] = {
            'addr': (peer_ip, peer_port),
            'quic_port': peer_quic_port,
            'public_key': None,
            'connected': False,
            'last_seen': time.time()
        }

        # Send hello message with our public key and QUIC port
        hello_msg = {
            'type': 'hello',
            'node_id': self.node_id,
            'public_key': self.crypto_manager.get_public_key_pem().decode(),
            'quic_port': self.external_quic_port
        }

        hello_json = json.dumps(hello_msg).encode()
        self.socket.sendto(hello_json, (peer_ip, peer_port))

        # Wait for response
        logger.info(f"Waiting for response from peer {peer_id}")

        # Start a thread to keep sending hello messages until we get a response
        def keep_trying():
            attempts = 0
            while attempts < 10 and peer_id in self.peers and not self.peers[peer_id].get('connected'):
                time.sleep(2)
                if peer_id in self.peers and not self.peers[peer_id].get('connected'):
                    # Resend hello message
                    hello_msg = {
                        'type': 'hello',
                        'node_id': self.node_id,
                        'public_key': self.crypto_manager.get_public_key_pem().decode(),
                        'quic_port': self.external_quic_port
                    }
                    hello_json = json.dumps(hello_msg).encode()
                    self.socket.sendto(hello_json, (peer_ip, peer_port))
                    logger.info(f"Resending hello to peer {peer_id} (attempt {attempts + 2}/10)")
                attempts += 1

            if peer_id in self.peers and self.peers[peer_id].get('connected'):
                logger.info(f"Successfully connected to peer {peer_id}")
            else:
                logger.warning(f"Failed to connect to peer {peer_id} after 10 attempts")

        retry_thread = threading.Thread(target=keep_trying)
        retry_thread.daemon = True
        retry_thread.start()

        return True

    def send_file(self, peer_id: str, file_path: str) -> Optional[str]:
        """
        Send a file to a peer using QUIC.

        Args:
            peer_id: Unique identifier for the peer
            file_path: Path to the file to send

        Returns:
            Transfer ID if successful, None otherwise
        """
        if peer_id not in self.peers or not self.peers[peer_id].get('connected'):
            logger.error(f"Peer {peer_id} is not connected")
            return None

        peer_info = self.peers[peer_id]
        peer_quic_addr = (peer_info['addr'][0], peer_info['quic_port'])

        try:
            # Use asyncio to send the file
            if self.quic_loop and self.quic_loop.is_running():
                future = asyncio.run_coroutine_threadsafe(
                    self.file_transfer.send_file(
                        file_path,
                        peer_id,
                        peer_quic_addr,
                        self._on_transfer_progress
                    ),
                    self.quic_loop
                )

                transfer_id = future.result(timeout=30)
                logger.info(f"Started QUIC file transfer {transfer_id} to peer {peer_id}")
                return transfer_id
            else:
                logger.error("QUIC loop not running")
                return None

        except Exception as e:
            logger.error(f"Error sending file via QUIC: {e}")
            return None

    def send_message(self, peer_id: str, message: str) -> bool:
        """
        Send a simple text message to a peer via UDP.

        Args:
            peer_id: Unique identifier for the peer
            message: The message to send

        Returns:
            True if sent, False otherwise
        """
        if peer_id not in self.peers or not self.peers[peer_id].get('connected'):
            logger.error(f"Peer {peer_id} is not connected")
            return False
        msg = {
            'type': 'test_message',
            'from': self.node_id,
            'message': message
        }
        try:
            self.socket.sendto(json.dumps(msg).encode(), self.peers[peer_id]['addr'])
            return True
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            return False

    def get_next_incoming_message(self) -> Optional[dict]:
        """
        Get the next incoming message from the queue, or None if empty.
        """
        try:
            return self.incoming_messages.get_nowait()
        except queue.Empty:
            return None

    def get_transfer_status(self, transfer_id: str) -> Dict:
        """
        Get the status of a file transfer.

        Args:
            transfer_id: Unique transfer ID

        Returns:
            Transfer status information
        """
        if transfer_id not in self.file_transfer.transfers:
            return {'status': 'unknown'}

        transfer = self.file_transfer.transfers[transfer_id]

        return {
            'transfer_id': transfer_id,
            'file_name': transfer['file_name'],
            'file_size': transfer['file_size'],
            'status': transfer.get('status', 'unknown'),
            'progress': 100,  # QUIC handles reliability, so assume complete when done
            'speed': 0  # Could be calculated if needed
        }

    def get_peer_info(self) -> Dict:
        """
        Get information about this node for sharing with peers.

        Returns:
            Dictionary with node information
        """
        return {
            'node_id': self.node_id,
            'external_ip': self.external_ip,
            'external_port': self.external_port,
            'external_quic_port': self.external_quic_port,
            'nat_type': self.nat_type
        }

    def _handle_messages(self) -> None:
        """Handle incoming UDP messages for peer discovery"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(65536)

                # First identify the peer based on address
                peer_id = None
                for pid, peer in self.peers.items():
                    if peer['addr'] == addr:
                        peer_id = pid
                        break

                # Try to decode as JSON for control messages
                try:
                    text_data = data.decode('utf-8')
                    message = json.loads(text_data)
                    message_type = message.get('type')

                    # Handle known message types
                    if message_type == 'hello':
                        self._handle_hello(message, addr)
                    elif message_type == 'hello_ack':
                        self._handle_hello_ack(message, addr)
                    elif message_type == 'key_exchange':
                        self._handle_key_exchange(message, addr)
                    elif message_type == 'key_exchange_ack':
                        self._handle_key_exchange_ack(message, addr)
                    elif message_type == 'test_message':
                        # Handle test message
                        peer_id_from = message.get('from', None)
                        msg_text = message.get('message', '')
                        if peer_id_from:
                            self.incoming_messages.put({'peer_id': peer_id_from, 'message': msg_text})
                        else:
                            logger.info(f"Received test message from unknown peer: {addr}")
                    else:
                        logger.warning(f"Unknown message type: {message_type}")

                except (json.JSONDecodeError, UnicodeDecodeError):
                    # Ignore non-JSON data (might be legacy or STUN packets)
                    logger.debug(f"Received non-JSON data from {addr}")

            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Error handling message: {e}")
                import traceback
                logger.error(traceback.format_exc())

    def _handle_hello(self, message: Dict, addr: Tuple[str, int]) -> None:
        """
        Handle hello message from a peer.

        Args:
            message: Hello message
            addr: Sender's address
        """
        peer_id = message.get('node_id')
        peer_public_key_pem = message.get('public_key')
        peer_quic_port = message.get('quic_port', addr[1] + 1000)  # Default offset

        if not peer_id or not peer_public_key_pem:
            logger.error("Invalid hello message")
            return

        logger.info(f"Received hello from peer {peer_id} at {addr} (QUIC: {peer_quic_port})")

        # Store peer information
        self.peers[peer_id] = {
            'addr': addr,
            'quic_port': peer_quic_port,
            'public_key': self.crypto_manager.load_peer_public_key(peer_public_key_pem.encode()),
            'connected': True,
            'last_seen': time.time()
        }

        # Send hello acknowledgment
        hello_ack = {
            'type': 'hello_ack',
            'node_id': self.node_id,
            'public_key': self.crypto_manager.get_public_key_pem().decode(),
            'quic_port': self.external_quic_port
        }

        hello_ack_json = json.dumps(hello_ack).encode()
        self.socket.sendto(hello_ack_json, addr)

        # Generate and send session key
        self._send_session_key(peer_id)

    def _handle_hello_ack(self, message: Dict, addr: Tuple[str, int]) -> None:
        """
        Handle hello acknowledgment from a peer.

        Args:
            message: Hello acknowledgment message
            addr: Sender's address
        """
        peer_id = message.get('node_id')
        peer_public_key_pem = message.get('public_key')
        peer_quic_port = message.get('quic_port', addr[1] + 1000)  # Default offset

        if not peer_id or not peer_public_key_pem:
            logger.error("Invalid hello_ack message")
            return

        logger.info(f"Received hello_ack from peer {peer_id} (QUIC: {peer_quic_port})")

        # Update peer information
        if peer_id in self.peers:
            self.peers[peer_id]['public_key'] = self.crypto_manager.load_peer_public_key(
                peer_public_key_pem.encode()
            )
            self.peers[peer_id]['quic_port'] = peer_quic_port
            self.peers[peer_id]['connected'] = True
            self.peers[peer_id]['last_seen'] = time.time()

            # Generate and send session key
            self._send_session_key(peer_id)
        else:
            logger.warning(f"Received hello_ack from unknown peer {peer_id}")

    def _send_session_key(self, peer_id: str) -> None:
        """
        Generate and send a session key to a peer.

        Args:
            peer_id: Unique identifier for the peer
        """
        if peer_id not in self.peers or not self.peers[peer_id].get('public_key'):
            logger.error(f"Cannot send session key to peer {peer_id}: missing public key")
            return

        # Generate a new session key
        key, iv = self.crypto_manager.generate_session_key()

        # Encrypt the session key with the peer's public key
        encrypted_key_package = self.crypto_manager.encrypt_session_key(
            self.peers[peer_id]['public_key'],
            key,
            iv
        )

        # Store the session key for this peer
        self.crypto_manager.store_peer_session_key(peer_id, key, iv)

        # Send the encrypted session key
        key_exchange = {
            'type': 'key_exchange',
            'node_id': self.node_id,
            'encrypted_key': base64.b64encode(encrypted_key_package).decode()
        }

        key_exchange_json = json.dumps(key_exchange).encode()
        self.socket.sendto(key_exchange_json, self.peers[peer_id]['addr'])

        logger.info(f"Sent session key to peer {peer_id}")

    def _handle_key_exchange(self, message: Dict, addr: Tuple[str, int]) -> None:
        """
        Handle key exchange message from a peer.

        Args:
            message: Key exchange message
            addr: Sender's address
        """
        peer_id = message.get('node_id')
        encrypted_key_b64 = message.get('encrypted_key')

        if not peer_id or not encrypted_key_b64:
            logger.error("Invalid key_exchange message")
            return

        logger.info(f"Received session key from peer {peer_id}")

        # Decrypt the session key
        try:
            encrypted_key_package = base64.b64decode(encrypted_key_b64)
            key, iv = self.crypto_manager.decrypt_session_key(encrypted_key_package)

            # Store the session key for this peer
            self.crypto_manager.store_peer_session_key(peer_id, key, iv)

            # Send acknowledgment
            key_exchange_ack = {
                'type': 'key_exchange_ack',
                'node_id': self.node_id
            }

            key_exchange_ack_json = json.dumps(key_exchange_ack).encode()
            self.socket.sendto(key_exchange_ack_json, addr)

            logger.info(f"Session key exchange with peer {peer_id} completed")

        except Exception as e:
            logger.error(f"Error decrypting session key: {e}")

    def _handle_key_exchange_ack(self, message: Dict, addr: Tuple[str, int]) -> None:
        """
        Handle key exchange acknowledgment from a peer.

        Args:
            message: Key exchange acknowledgment message
            addr: Sender's address
        """
        peer_id = message.get('node_id')

        if not peer_id:
            logger.error("Invalid key_exchange_ack message")
            return

        logger.info(f"Received key exchange acknowledgment from peer {peer_id}")

        # Update peer information
        if peer_id in self.peers:
            self.peers[peer_id]['last_seen'] = time.time()
        else:
            logger.warning(f"Received key_exchange_ack from unknown peer {peer_id}")

    def _on_transfer_progress(self, transfer_id: str, chunks_processed: int, total_chunks: int) -> None:
        """
        Callback for file transfer progress updates.

        Args:
            transfer_id: Unique transfer ID
            chunks_processed: Number of chunks processed
            total_chunks: Total number of chunks
        """
        progress = (chunks_processed / total_chunks) * 100 if total_chunks > 0 else 0
        logger.info(f"Transfer {transfer_id}: {progress:.1f}% ({chunks_processed}/{total_chunks} chunks)")