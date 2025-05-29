"""
Enhanced P2P node implementation with improved message handling and reliability.
Handles peer connections, NAT traversal, and file transfers with better error recovery.
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
from enum import Enum

from stun_client import STUNClient
from crypto import CryptoManager
from file_transfer import FileTransfer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Enumeration of message types for better organization"""
    HELLO = "hello"
    HELLO_ACK = "hello_ack"
    KEY_EXCHANGE = "key_exchange"
    KEY_EXCHANGE_ACK = "key_exchange_ack"
    FILE_CHUNK = "file_chunk"
    TEST_MESSAGE = "test_message"
    HEARTBEAT = "heartbeat"
    HEARTBEAT_ACK = "heartbeat_ack"


class MessageHandler:
    """Separate class to handle different types of messages"""

    def __init__(self, p2p_node):
        self.node = p2p_node
        self.handlers = {
            MessageType.HELLO.value: self._handle_hello,
            MessageType.HELLO_ACK.value: self._handle_hello_ack,
            MessageType.KEY_EXCHANGE.value: self._handle_key_exchange,
            MessageType.KEY_EXCHANGE_ACK.value: self._handle_key_exchange_ack,
            MessageType.FILE_CHUNK.value: self._handle_file_chunk,
            MessageType.TEST_MESSAGE.value: self._handle_test_message,
            MessageType.HEARTBEAT.value: self._handle_heartbeat,
            MessageType.HEARTBEAT_ACK.value: self._handle_heartbeat_ack,
        }

    def handle_json_message(self, message: Dict, addr: Tuple[str, int], peer_id: Optional[str]):
        """Handle a parsed JSON message"""
        message_type = message.get('type')
        handler = self.handlers.get(message_type)

        if handler:
            try:
                handler(message, addr, peer_id)
            except Exception as e:
                logger.error(f"Error handling {message_type} message: {e}")
        elif peer_id:
            # Pass file transfer messages to the file transfer handler
            self.node.file_transfer.handle_message(
                json.dumps(message).encode(), addr, peer_id
            )
        else:
            logger.warning(f"Received {message_type} from unknown peer {addr}")

    def _handle_hello(self, message: Dict, addr: Tuple[str, int], peer_id: Optional[str]):
        """Handle hello message"""
        self.node._handle_hello(message, addr)

    def _handle_hello_ack(self, message: Dict, addr: Tuple[str, int], peer_id: Optional[str]):
        """Handle hello acknowledgment"""
        self.node._handle_hello_ack(message, addr)

    def _handle_key_exchange(self, message: Dict, addr: Tuple[str, int], peer_id: Optional[str]):
        """Handle key exchange"""
        self.node._handle_key_exchange(message, addr)

    def _handle_key_exchange_ack(self, message: Dict, addr: Tuple[str, int], peer_id: Optional[str]):
        """Handle key exchange acknowledgment"""
        self.node._handle_key_exchange_ack(message, addr)

    def _handle_file_chunk(self, message: Dict, addr: Tuple[str, int], peer_id: Optional[str]):
        """Handle file chunk header"""
        if peer_id:
            self.node._prepare_for_chunk(message, peer_id)
        else:
            logger.warning(f"Received file chunk from unknown peer {addr}")

    def _handle_test_message(self, message: Dict, addr: Tuple[str, int], peer_id: Optional[str]):
        """Handle test message"""
        peer_id_from = message.get('from')
        msg_text = message.get('message', '')
        if peer_id_from:
            self.node.incoming_messages.put({'peer_id': peer_id_from, 'message': msg_text})
        else:
            logger.info(f"Received test message from unknown peer: {addr}")

    def _handle_heartbeat(self, message: Dict, addr: Tuple[str, int], peer_id: Optional[str]):
        """Handle heartbeat message"""
        if peer_id:
            # Update last seen time
            self.node.peers[peer_id]['last_seen'] = time.time()
            # Send heartbeat response
            response = {'type': 'heartbeat_ack', 'node_id': self.node.node_id}
            try:
                self.node.socket.sendto(json.dumps(response).encode(), addr)
            except Exception as e:
                logger.error(f"Failed to send heartbeat ack: {e}")

    def _handle_heartbeat_ack(self, message: Dict, addr: Tuple[str, int], peer_id: Optional[str]):
        """Handle heartbeat acknowledgment"""
        if peer_id:
            self.node.peers[peer_id]['last_seen'] = time.time()


class ChunkState:
    """State management for incoming chunks"""

    def __init__(self):
        self.expected_chunks: Dict[str, Dict] = {}  # transfer_id -> chunk_info
        self.lock = threading.RLock()

    def expect_chunk(self, transfer_id: str, chunk_index: int, chunk_size: int):
        """Mark that we're expecting a specific chunk"""
        with self.lock:
            self.expected_chunks[transfer_id] = {
                'chunk_index': chunk_index,
                'chunk_size': chunk_size,
                'timestamp': time.time()
            }

    def get_expected_chunk(self, transfer_id: str) -> Optional[Dict]:
        """Get expected chunk info and clear it"""
        with self.lock:
            return self.expected_chunks.pop(transfer_id, None)

    def cleanup_stale(self, max_age: float = 30.0):
        """Clean up stale expected chunks"""
        now = time.time()
        with self.lock:
            stale_keys = [
                tid for tid, info in self.expected_chunks.items()
                if now - info['timestamp'] > max_age
            ]
            for key in stale_keys:
                del self.expected_chunks[key]
                logger.debug(f"Cleaned up stale chunk expectation for transfer {key}")


class ConnectionManager:
    """Manages peer connections and health monitoring"""

    def __init__(self, p2p_node):
        self.node = p2p_node
        self.connection_timeout = 60.0  # Consider peer disconnected after 60s
        self.heartbeat_interval = 20.0  # Send heartbeat every 20s
        self.running = False

    def start(self):
        """Start connection monitoring"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_connections, daemon=True)
        self.monitor_thread.start()

    def stop(self):
        """Stop connection monitoring"""
        self.running = False

    def _monitor_connections(self):
        """Monitor peer connections and send heartbeats"""
        while self.running:
            now = time.time()
            disconnected_peers = []

            for peer_id, peer_info in list(self.node.peers.items()):
                if not peer_info.get('connected'):
                    continue

                last_seen = peer_info.get('last_seen', 0)

                # Check if peer is stale
                if now - last_seen > self.connection_timeout:
                    logger.warning(f"Peer {peer_id} appears disconnected (last seen {now - last_seen:.1f}s ago)")
                    peer_info['connected'] = False
                    disconnected_peers.append(peer_id)
                    continue

                # Send heartbeat if it's time
                if now - last_seen > self.heartbeat_interval:
                    self._send_heartbeat(peer_id, peer_info['addr'])

            if disconnected_peers:
                logger.info(f"Marked {len(disconnected_peers)} peers as disconnected")

            time.sleep(10)  # Check every 10 seconds

    def _send_heartbeat(self, peer_id: str, addr: Tuple[str, int]):
        """Send heartbeat to a peer"""
        try:
            heartbeat_msg = {
                'type': 'heartbeat',
                'node_id': self.node.node_id,
                'timestamp': time.time()
            }
            self.node.socket.sendto(json.dumps(heartbeat_msg).encode(), addr)
            logger.debug(f"Sent heartbeat to peer {peer_id}")
        except Exception as e:
            logger.error(f"Failed to send heartbeat to {peer_id}: {e}")


class P2PNode:
    """
    Enhanced P2P node for decentralized file sharing.
    Handles NAT traversal, peer connections, and file transfers with improved reliability.
    """

    def __init__(self, local_port: int = 0, save_dir: str = "./downloads"):
        """
        Initialize the P2P node.

        Args:
            local_port: Local UDP port to bind to. If 0, a random port will be assigned.
            save_dir: Directory to save received files
        """
        self.node_id = str(uuid.uuid4())
        self.local_port = local_port
        self.save_dir = os.path.abspath(save_dir)
        self.peers = {}  # {peer_id: {addr: (ip, port), public_key: key, connected: bool, last_seen: float}}
        self.running = False
        self.stun_client = STUNClient(local_port)
        self.crypto_manager = CryptoManager()
        self.socket = None
        self.file_transfer = None
        self.incoming_messages = queue.Queue()

        # Enhanced message handling components
        self.message_handler = MessageHandler(self)
        self.chunk_state = ChunkState()
        self.connection_manager = ConnectionManager(self)

        # Statistics for debugging
        self.message_stats = {
            'total_received': 0,
            'json_messages': 0,
            'binary_messages': 0,
            'unknown_peer_messages': 0,
            'errors': 0,
            'chunks_processed': 0
        }

        # Create save directory if it doesn't exist
        os.makedirs(self.save_dir, exist_ok=True)

        # NAT information
        self.nat_type = None
        self.external_ip = None
        self.external_port = None

    def start(self) -> Tuple[str, int]:
        """
        Start the P2P node.

        Returns:
            Tuple of (external_ip, external_port)
        """
        # Discover NAT type and external IP/port
        self.nat_type, self.external_ip, self.external_port = self.stun_client.discover_nat()

        if not self.external_ip or not self.external_port:
            raise RuntimeError("Failed to discover external IP and port")

        # Create UDP socket
        self.socket = self.stun_client.create_socket()

        # Initialize file transfer manager
        self.file_transfer = FileTransfer(self.socket, self.crypto_manager)
        self.file_transfer.receive_file(self.save_dir, self._on_transfer_progress)

        # Start message handling and connection monitoring
        self.running = True
        self.message_thread = threading.Thread(target=self._handle_messages_enhanced, daemon=True)
        self.message_thread.start()

        # Start cleanup and monitoring threads
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()

        self.connection_manager.start()

        logger.info(f"P2P node started with ID: {self.node_id}")
        logger.info(f"NAT Type: {self.nat_type}")
        logger.info(f"External IP: {self.external_ip}")
        logger.info(f"External Port: {self.external_port}")
        logger.info(f"Local Port: {self.local_port}")

        return self.external_ip, self.external_port

    def stop(self) -> None:
        """Stop the P2P node"""
        self.running = False
        self.connection_manager.stop()

        if self.file_transfer and hasattr(self.file_transfer, 'stop'):
            self.file_transfer.stop()

        if self.socket:
            self.socket.close()

        logger.info("P2P node stopped")

    def connect_to_peer(self, peer_id: str, peer_ip: str, peer_port: int) -> bool:
        """
        Connect to a peer using their external IP and port.

        Args:
            peer_id: Unique identifier for the peer
            peer_ip: External IP of the peer
            peer_port: External port of the peer

        Returns:
            True if connection was successful, False otherwise
        """
        logger.info(f"Connecting to peer {peer_id} at {peer_ip}:{peer_port}")

        # Perform UDP hole punching
        if not self.stun_client.punch_hole(peer_ip, peer_port):
            logger.error(f"Failed to punch hole to {peer_ip}:{peer_port}")
            return False

        # Store peer information
        self.peers[peer_id] = {
            'addr': (peer_ip, peer_port),
            'public_key': None,
            'connected': False,
            'last_seen': time.time(),
            'connection_attempts': 0
        }

        # Send hello message with our public key
        hello_msg = {
            'type': 'hello',
            'node_id': self.node_id,
            'public_key': self.crypto_manager.get_public_key_pem().decode()
        }

        hello_json = json.dumps(hello_msg).encode()
        self.socket.sendto(hello_json, (peer_ip, peer_port))

        # Wait for response
        logger.info(f"Waiting for response from peer {peer_id}")

        # Start a thread to keep sending hello messages until we get a response
        def keep_trying():
            attempts = 0
            max_attempts = 10
            while attempts < max_attempts and peer_id in self.peers and not self.peers[peer_id].get('connected'):
                time.sleep(2)
                if peer_id in self.peers and not self.peers[peer_id].get('connected'):
                    # Resend hello message
                    hello_msg = {
                        'type': 'hello',
                        'node_id': self.node_id,
                        'public_key': self.crypto_manager.get_public_key_pem().decode()
                    }
                    hello_json = json.dumps(hello_msg).encode()
                    try:
                        self.socket.sendto(hello_json, (peer_ip, peer_port))
                        self.peers[peer_id]['connection_attempts'] = attempts + 1
                        logger.info(f"Resending hello to peer {peer_id} (attempt {attempts + 2}/{max_attempts})")
                    except Exception as e:
                        logger.error(f"Failed to send hello to {peer_id}: {e}")
                attempts += 1

            if peer_id in self.peers:
                if self.peers[peer_id].get('connected'):
                    logger.info(f"Successfully connected to peer {peer_id}")
                else:
                    logger.warning(f"Failed to connect to peer {peer_id} after {max_attempts} attempts")
                    # Don't remove the peer entry - they might connect later

        retry_thread = threading.Thread(target=keep_trying, daemon=True)
        retry_thread.start()

        return True

    def send_file(self, peer_id: str, file_path: str) -> Optional[str]:
        """
        Send a file to a peer.

        Args:
            peer_id: Unique identifier for the peer
            file_path: Path to the file to send

        Returns:
            Transfer ID if successful, None otherwise
        """
        if peer_id not in self.peers or not self.peers[peer_id].get('connected'):
            logger.error(f"Peer {peer_id} is not connected")
            return None

        peer_addr = self.peers[peer_id]['addr']

        try:
            transfer_id = self.file_transfer.send_file(
                file_path,
                peer_id,
                peer_addr,
                self._on_transfer_progress
            )

            logger.info(f"Started file transfer {transfer_id} to peer {peer_id}")
            return transfer_id

        except Exception as e:
            logger.error(f"Error sending file: {e}")
            return None

    def send_message(self, peer_id: str, message: str) -> bool:
        """
        Send a simple text message to a peer.

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
            'message': message,
            'timestamp': time.time()
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
        if not self.file_transfer or transfer_id not in self.file_transfer.transfers:
            return {'status': 'unknown'}

        transfer = self.file_transfer.transfers[transfer_id]

        # Calculate progress percentage
        if transfer['total_chunks'] > 0:
            if 'chunks_sent' in transfer:
                progress = (transfer['chunks_sent'] / transfer['total_chunks']) * 100
            else:
                progress = (transfer['chunks_received'] / transfer['total_chunks']) * 100
        else:
            progress = 0

        # Calculate transfer speed
        if transfer['status'] == 'completed' and 'end_time' in transfer and 'start_time' in transfer:
            duration = transfer['end_time'] - transfer['start_time']
            if duration > 0:
                speed = transfer['file_size'] / duration / 1024  # KB/s
            else:
                speed = 0
        else:
            speed = 0

        return {
            'transfer_id': transfer_id,
            'file_name': transfer['file_name'],
            'file_size': transfer['file_size'],
            'status': transfer['status'],
            'progress': progress,
            'speed': speed
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
            'nat_type': self.nat_type
        }

    def get_debug_info(self) -> Dict:
        """Get debug information about the node"""
        connected_peers = [p for p in self.peers.values() if p.get('connected')]

        return {
            'node_id': self.node_id,
            'connected_peers': len(connected_peers),
            'total_peers': len(self.peers),
            'message_stats': self.message_stats.copy(),
            'active_transfers': len(self.file_transfer.transfers) if self.file_transfer else 0,
            'expected_chunks': len(self.chunk_state.expected_chunks),
            'peer_details': {
                pid: {
                    'connected': p.get('connected', False),
                    'last_seen_ago': time.time() - p.get('last_seen', 0),
                    'attempts': p.get('connection_attempts', 0)
                } for pid, p in self.peers.items()
            }
        }

    def _handle_messages_enhanced(self) -> None:
        """Enhanced message handling with better separation of concerns"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(65536)
                self.message_stats['total_received'] += 1

                # Find peer ID based on address
                peer_id = self._find_peer_by_address(addr)

                # Try to process as JSON first
                if self._handle_as_json(data, addr, peer_id):
                    self.message_stats['json_messages'] += 1
                    continue

                # Handle as binary data
                if self._handle_as_binary(data, addr, peer_id):
                    self.message_stats['binary_messages'] += 1
                    continue

                # Unknown data type
                if not peer_id:
                    self.message_stats['unknown_peer_messages'] += 1
                    logger.debug(f"Received data from unknown peer {addr}")

            except socket.timeout:
                continue
            except Exception as e:
                self.message_stats['errors'] += 1
                logger.error(f"Error handling message: {e}")

    def _find_peer_by_address(self, addr: Tuple[str, int]) -> Optional[str]:
        """Find peer ID by address"""
        for peer_id, peer in self.peers.items():
            if peer.get('addr') == addr:
                peer['last_seen'] = time.time()  # Update last seen time
                return peer_id
        return None

    def _handle_as_json(self, data: bytes, addr: Tuple[str, int], peer_id: Optional[str]) -> bool:
        """Try to handle data as JSON message"""
        try:
            text_data = data.decode('utf-8')
            try:
                message = json.loads(text_data)
                self.message_handler.handle_json_message(message, addr, peer_id)
                return True
            except json.JSONDecodeError:
                # Valid UTF-8 but not JSON
                if peer_id and self.file_transfer:
                    self.file_transfer.handle_message(data, addr, peer_id)
                    return True
                return False
        except UnicodeDecodeError:
            return False

    def _handle_as_binary(self, data: bytes, addr: Tuple[str, int], peer_id: Optional[str]) -> bool:
        """Handle binary data (file chunks)"""
        if not peer_id or not self.file_transfer:
            return False

        # Check if this might be an expected file chunk
        chunk_processed = False

        # Try to match with expected chunks
        for transfer_id in list(self.chunk_state.expected_chunks.keys()):
            chunk_info = self.chunk_state.get_expected_chunk(transfer_id)
            if chunk_info:
                # Process the chunk
                try:
                    self.file_transfer._process_chunk(
                        transfer_id,
                        chunk_info['chunk_index'],
                        peer_id,
                        addr,
                        data
                    )
                    self.message_stats['chunks_processed'] += 1
                    logger.debug(f"Processed binary chunk {chunk_info['chunk_index']} for {transfer_id}")
                    chunk_processed = True
                    break
                except Exception as e:
                    logger.error(f"Error processing chunk: {e}")

        if not chunk_processed:
            # Fallback: let file transfer handler deal with it
            try:
                self.file_transfer.handle_binary_data(data, addr, peer_id)
                chunk_processed = True
            except Exception as e:
                logger.error(f"Error handling binary data: {e}")

        return chunk_processed

    def _prepare_for_chunk(self, message: Dict, peer_id: str):
        """Prepare to receive a file chunk"""
        transfer_id = message.get('transfer_id')
        chunk_index = message.get('chunk_index')
        chunk_size = message.get('chunk_size', 0)

        if transfer_id and chunk_index is not None:
            self.chunk_state.expect_chunk(transfer_id, chunk_index, chunk_size)
            logger.debug(f"Expecting chunk {chunk_index} for transfer {transfer_id}")

            # Also notify file transfer handler about the header
            if peer_id in self.peers:
                addr = self.peers[peer_id]['addr']
                if hasattr(self.file_transfer, '_handle_file_chunk'):
                    self.file_transfer._handle_file_chunk(message, addr, peer_id)

    def _cleanup_worker(self):
        """Background worker for cleanup tasks"""
        while self.running:
            try:
                # Clean up stale chunk expectations
                self.chunk_state.cleanup_stale()

                # Log statistics periodically
                if self.message_stats['total_received'] > 0 and self.message_stats['total_received'] % 100 == 0:
                    logger.debug(f"Message stats: {self.message_stats}")

                time.sleep(30)  # Run cleanup every 30 seconds
            except Exception as e:
                logger.error(f"Error in cleanup worker: {e}")

    def _handle_hello(self, message: Dict, addr: Tuple[str, int]) -> None:
        """
        Handle hello message from a peer.

        Args:
            message: Hello message
            addr: Sender's address
        """
        peer_id = message.get('node_id')
        peer_public_key_pem = message.get('public_key')

        if not peer_id or not peer_public_key_pem:
            logger.error("Invalid hello message")
            return

        logger.info(f"Received hello from peer {peer_id} at {addr}")

        try:
            # Store peer information
            self.peers[peer_id] = {
                'addr': addr,
                'public_key': self.crypto_manager.load_peer_public_key(peer_public_key_pem.encode()),
                'connected': True,
                'last_seen': time.time(),
                'connection_attempts': 0
            }

            # Send hello acknowledgment
            hello_ack = {
                'type': 'hello_ack',
                'node_id': self.node_id,
                'public_key': self.crypto_manager.get_public_key_pem().decode()
            }

            hello_ack_json = json.dumps(hello_ack).encode()
            self.socket.sendto(hello_ack_json, addr)

            # Generate and send session key
            self._send_session_key(peer_id)

        except Exception as e:
            logger.error(f"Error handling hello from {peer_id}: {e}")

    def _handle_hello_ack(self, message: Dict, addr: Tuple[str, int]) -> None:
        """
        Handle hello acknowledgment from a peer.

        Args:
            message: Hello acknowledgment message
            addr: Sender's address
        """
        peer_id = message.get('node_id')
        peer_public_key_pem = message.get('public_key')

        if not peer_id or not peer_public_key_pem:
            logger.error("Invalid hello_ack message")
            return

        logger.info(f"Received hello_ack from peer {peer_id}")

        try:
            # Update peer information
            if peer_id in self.peers:
                self.peers[peer_id]['public_key'] = self.crypto_manager.load_peer_public_key(
                    peer_public_key_pem.encode()
                )
                self.peers[peer_id]['connected'] = True
                self.peers[peer_id]['last_seen'] = time.time()

                # Generate and send session key
                self._send_session_key(peer_id)
            else:
                logger.warning(f"Received hello_ack from unknown peer {peer_id}")

        except Exception as e:
            logger.error(f"Error handling hello_ack from {peer_id}: {e}")

    def _send_session_key(self, peer_id: str) -> None:
        """
        Generate and send a session key to a peer.

        Args:
            peer_id: Unique identifier for the peer
        """
        if peer_id not in self.peers or not self.peers[peer_id].get('public_key'):
            logger.error(f"Cannot send session key to peer {peer_id}: missing public key")
            return

        try:
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

        except Exception as e:
            logger.error(f"Error sending session key to {peer_id}: {e}")

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