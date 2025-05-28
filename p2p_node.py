"""
Main P2P node implementation with TCP file transfer.
Handles peer connections, NAT traversal, and TCP-based file transfers.
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
from typing import Dict, List, Tuple, Optional, Callable, Any

from stun_client import STUNClient
from crypto import CryptoManager
from tcp_file_transfer import TCPFileTransfer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class P2PNode:
    """
    P2P node for decentralized file sharing with TCP-based file transfer.
    Handles NAT traversal, peer connections, and reliable file transfers.
    """

    def __init__(self, local_port: int = 0, save_dir: str = "./downloads"):
        """
        Initialize the P2P node.

        Args:
            local_port: Local UDP port to bind to for peer communication. If 0, a random port will be assigned.
            save_dir: Directory to save received files
        """
        self.node_id = str(uuid.uuid4())
        self.local_port = local_port
        self.save_dir = os.path.abspath(save_dir)
        self.peers = {}  # {peer_id: {addr: (ip, udp_port), tcp_port: port, public_key: key}}
        self.running = False
        self.stun_client = STUNClient(local_port)
        self.crypto_manager = CryptoManager()
        self.socket = None
        self.incoming_messages = queue.Queue()

        # Create save directory if it doesn't exist
        os.makedirs(self.save_dir, exist_ok=True)

        # NAT information
        self.nat_type = None
        self.external_ip = None
        self.external_port = None

        # TCP File Transfer - This replaces the UDP file transfer
        self.tcp_file_transfer = TCPFileTransfer(self.crypto_manager, save_dir)

    def start(self) -> Tuple[str, int]:
        """
        Start the P2P node.

        Returns:
            Tuple of (external_ip, external_udp_port)
        """
        # Discover NAT type and external IP/port using STUN
        self.nat_type, self.external_ip, self.external_port = self.stun_client.discover_nat()

        if not self.external_ip or not self.external_port:
            raise RuntimeError("Failed to discover external IP and port")

        # Create UDP socket for peer communication (not file transfer)
        self.socket = self.stun_client.create_socket()

        # Set progress callback for TCP file transfers
        self.tcp_file_transfer.set_progress_callback(self._on_transfer_progress)

        # Start message handling thread for peer communication
        self.running = True
        self.message_thread = threading.Thread(target=self._handle_messages)
        self.message_thread.daemon = True
        self.message_thread.start()

        logger.info(f"P2P node started with ID: {self.node_id}")
        logger.info(f"NAT Type: {self.nat_type}")
        logger.info(f"External IP: {self.external_ip}")
        logger.info(f"External UDP Port: {self.external_port}")
        logger.info(f"TCP File Transfer Port: {self.tcp_file_transfer.tcp_port}")

        return self.external_ip, self.external_port

    def stop(self) -> None:
        """Stop the P2P node and all services"""
        self.running = False
        if self.socket:
            self.socket.close()

        # Stop TCP file transfer service
        self.tcp_file_transfer.stop()

        logger.info("P2P node stopped")

    def connect_to_peer(self, peer_id: str, peer_ip: str, peer_udp_port: int, peer_tcp_port: int = None) -> bool:
        """
        Connect to a peer using their external IP and ports.

        Args:
            peer_id: Unique identifier for the peer
            peer_ip: External IP of the peer
            peer_udp_port: External UDP port of the peer (for peer communication)
            peer_tcp_port: TCP port of the peer (for file transfers) - can be None, will be exchanged

        Returns:
            True if connection was successful, False otherwise
        """
        logger.info(f"Connecting to peer {peer_id} at {peer_ip}:{peer_udp_port} (TCP: {peer_tcp_port})")

        # Perform UDP hole punching for peer communication
        if not self.stun_client.punch_hole(peer_ip, peer_udp_port):
            logger.error(f"Failed to punch hole to {peer_ip}:{peer_udp_port}")
            return False

        # Store peer information
        self.peers[peer_id] = {
            'addr': (peer_ip, peer_udp_port),  # UDP address for peer communication
            'tcp_port': peer_tcp_port,  # TCP port for file transfers
            'public_key': None,
            'connected': False,
            'last_seen': time.time()
        }

        # Send hello message with our public key and TCP port
        hello_msg = {
            'type': 'hello',
            'node_id': self.node_id,
            'public_key': self.crypto_manager.get_public_key_pem().decode(),
            'tcp_port': self.tcp_file_transfer.tcp_port  # Include our TCP port
        }

        hello_json = json.dumps(hello_msg).encode()
        self.socket.sendto(hello_json, (peer_ip, peer_udp_port))

        # Wait for response with retry mechanism
        logger.info(f"Waiting for response from peer {peer_id}")

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
                        'tcp_port': self.tcp_file_transfer.tcp_port
                    }
                    hello_json = json.dumps(hello_msg).encode()
                    self.socket.sendto(hello_json, (peer_ip, peer_udp_port))
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
        Send a file to a peer using TCP.

        Args:
            peer_id: Unique identifier for the peer
            file_path: Path to the file to send

        Returns:
            Transfer ID if successful, None otherwise
        """
        if peer_id not in self.peers or not self.peers[peer_id].get('connected'):
            logger.error(f"Peer {peer_id} is not connected")
            return None

        peer_ip = self.peers[peer_id]['addr'][0]
        peer_tcp_port = self.peers[peer_id].get('tcp_port')

        if not peer_tcp_port:
            logger.error(f"Peer {peer_id} TCP port unknown")
            return None

        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None

        try:
            transfer_id = self.tcp_file_transfer.send_file(
                file_path,
                peer_id,
                peer_ip,
                peer_tcp_port,
                self._on_transfer_progress
            )

            logger.info(f"Started TCP file transfer {transfer_id} to peer {peer_id}")
            return transfer_id

        except Exception as e:
            logger.error(f"Error sending file: {e}")
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
        Get the status of a TCP file transfer.

        Args:
            transfer_id: Unique transfer ID

        Returns:
            Transfer status information
        """
        return self.tcp_file_transfer.get_transfer_status(transfer_id)

    def list_transfers(self) -> Dict[str, Dict]:
        """Get status of all file transfers"""
        return self.tcp_file_transfer.list_transfers()

    def get_peer_info(self) -> Dict:
        """
        Get information about this node for sharing with peers.

        Returns:
            Dictionary with node information
        """
        return {
            'node_id': self.node_id,
            'external_ip': self.external_ip,
            'external_port': self.external_port,  # UDP port for peer communication
            'tcp_port': self.tcp_file_transfer.tcp_port,  # TCP port for file transfers
            'nat_type': str(self.nat_type) if self.nat_type else 'Unknown'
        }

    def list_peers(self) -> Dict[str, Dict]:
        """Get information about connected peers"""
        return {pid: {
            'addr': peer['addr'],
            'tcp_port': peer.get('tcp_port'),
            'connected': peer.get('connected', False),
            'last_seen': peer.get('last_seen', 0)
        } for pid, peer in self.peers.items()}

    def _handle_messages(self) -> None:
        """Handle incoming UDP messages for peer communication (not file transfers)"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(65536)  # Max UDP packet size

                # Only handle peer communication messages, not file transfers
                try:
                    text_data = data.decode('utf-8')
                    message = json.loads(text_data)
                    message_type = message.get('type')

                    # Handle peer communication messages only
                    if message_type == 'hello':
                        self._handle_hello(message, addr)
                    elif message_type == 'hello_ack':
                        self._handle_hello_ack(message, addr)
                    elif message_type == 'key_exchange':
                        self._handle_key_exchange(message, addr)
                    elif message_type == 'key_exchange_ack':
                        self._handle_key_exchange_ack(message, addr)
                    elif message_type == 'test_message':
                        peer_id_from = message.get('from', None)
                        msg_text = message.get('message', '')
                        if peer_id_from:
                            self.incoming_messages.put({'peer_id': peer_id_from, 'message': msg_text})
                        else:
                            logger.info(f"Received test message from unknown peer: {addr}")
                    else:
                        logger.debug(f"Unknown message type: {message_type}")

                except (json.JSONDecodeError, UnicodeDecodeError):
                    logger.debug(f"Received non-JSON data from {addr}")

            except socket.timeout:
                continue  # Just continue the loop on timeout
            except Exception as e:
                if self.running:
                    logger.error(f"Error handling message: {e}")

    def _handle_hello(self, message: Dict, addr: Tuple[str, int]) -> None:
        """
        Handle hello message from a peer.

        Args:
            message: Hello message containing peer info
            addr: Sender's address
        """
        peer_id = message.get('node_id')
        peer_public_key_pem = message.get('public_key')
        peer_tcp_port = message.get('tcp_port')  # Get TCP port from hello message

        if not peer_id or not peer_public_key_pem:
            logger.error("Invalid hello message")
            return

        logger.info(f"Received hello from peer {peer_id} at {addr} (TCP: {peer_tcp_port})")

        # Store peer information including TCP port
        self.peers[peer_id] = {
            'addr': addr,
            'tcp_port': peer_tcp_port,  # Store TCP port for file transfers
            'public_key': self.crypto_manager.load_peer_public_key(peer_public_key_pem.encode()),
            'connected': True,
            'last_seen': time.time()
        }

        # Send hello acknowledgment with our TCP port
        hello_ack = {
            'type': 'hello_ack',
            'node_id': self.node_id,
            'public_key': self.crypto_manager.get_public_key_pem().decode(),
            'tcp_port': self.tcp_file_transfer.tcp_port  # Include our TCP port
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
        peer_tcp_port = message.get('tcp_port')  # Get TCP port

        if not peer_id or not peer_public_key_pem:
            logger.error("Invalid hello_ack message")
            return

        logger.info(f"Received hello_ack from peer {peer_id} (TCP: {peer_tcp_port})")

        # Update peer information including TCP port
        if peer_id in self.peers:
            self.peers[peer_id]['public_key'] = self.crypto_manager.load_peer_public_key(
                peer_public_key_pem.encode()
            )
            self.peers[peer_id]['tcp_port'] = peer_tcp_port  # Store TCP port
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