"""
P2P node with enhanced TCP file transfer and better NAT handling.
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
from enhanced_tcp_file_transfer import EnhancedTCPFileTransfer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class P2PNode:
    """P2P node with enhanced TCP file transfer capabilities."""

    def __init__(self, local_port: int = 0, save_dir: str = "./downloads"):
        """Initialize the P2P node."""
        self.node_id = str(uuid.uuid4())
        self.local_port = local_port
        self.save_dir = os.path.abspath(save_dir)
        self.peers = {}
        self.running = False
        self.stun_client = STUNClient(local_port)
        self.crypto_manager = CryptoManager()
        self.socket = None
        self.incoming_messages = queue.Queue()

        os.makedirs(self.save_dir, exist_ok=True)

        # NAT information
        self.nat_type = None
        self.external_ip = None
        self.external_port = None

        # Enhanced TCP File Transfer
        self.tcp_file_transfer = EnhancedTCPFileTransfer(self.crypto_manager, save_dir)

    def start(self) -> Tuple[str, int]:
        """Start the P2P node with enhanced error handling."""
        try:
            # Discover NAT type and external IP/port
            self.nat_type, self.external_ip, self.external_port = self.stun_client.discover_nat()

            if not self.external_ip or not self.external_port:
                raise RuntimeError("Failed to discover external IP and port")

            # Create UDP socket
            self.socket = self.stun_client.create_socket()

            # Set progress callback
            self.tcp_file_transfer.set_progress_callback(self._on_transfer_progress)

            # Start message handling thread
            self.running = True
            self.message_thread = threading.Thread(target=self._handle_messages)
            self.message_thread.daemon = True
            self.message_thread.start()

            logger.info(f"P2P node started successfully:")
            logger.info(f"  Node ID: {self.node_id}")
            logger.info(f"  NAT Type: {self.nat_type}")
            logger.info(f"  External IP: {self.external_ip}")
            logger.info(f"  External UDP Port: {self.external_port}")
            logger.info(f"  TCP File Transfer Port: {self.tcp_file_transfer.tcp_port}")

            return self.external_ip, self.external_port

        except Exception as e:
            logger.error(f"Failed to start P2P node: {e}")
            raise

    def connect_to_peer(self, peer_id: str, peer_ip: str, peer_udp_port: int, peer_tcp_port: int = None) -> bool:
        """Connect to a peer with enhanced connection logic."""
        logger.info(f"Connecting to peer {peer_id}")
        logger.info(f"  IP: {peer_ip}")
        logger.info(f"  UDP Port: {peer_udp_port}")
        logger.info(f"  TCP Port: {peer_tcp_port}")

        # Perform UDP hole punching
        if not self.stun_client.punch_hole(peer_ip, peer_udp_port):
            logger.warning(f"UDP hole punching failed, but continuing anyway...")

        # Store peer information
        self.peers[peer_id] = {
            'addr': (peer_ip, peer_udp_port),
            'tcp_port': peer_tcp_port,
            'public_key': None,
            'connected': False,
            'last_seen': time.time()
        }

        # Send hello message
        hello_msg = {
            'type': 'hello',
            'node_id': self.node_id,
            'public_key': self.crypto_manager.get_public_key_pem().decode(),
            'tcp_port': self.tcp_file_transfer.tcp_port
        }

        hello_json = json.dumps(hello_msg).encode()
        self.socket.sendto(hello_json, (peer_ip, peer_udp_port))

        # Enhanced retry mechanism
        def enhanced_retry():
            attempts = 0
            max_attempts = 15  # Increased attempts

            while attempts < max_attempts and peer_id in self.peers:
                if self.peers[peer_id].get('connected'):
                    logger.info(f"✅ Successfully connected to peer {peer_id}")
                    return

                time.sleep(2)
                attempts += 1

                if peer_id in self.peers and not self.peers[peer_id].get('connected'):
                    # Resend hello
                    try:
                        self.socket.sendto(hello_json, (peer_ip, peer_udp_port))
                        logger.info(f"🔄 Retry {attempts}/{max_attempts} - Hello sent to {peer_id}")
                    except Exception as e:
                        logger.error(f"Failed to resend hello: {e}")

            if peer_id in self.peers and not self.peers[peer_id].get('connected'):
                logger.warning(f"❌ Failed to connect to peer {peer_id} after {max_attempts} attempts")

        retry_thread = threading.Thread(target=enhanced_retry, daemon=True)
        retry_thread.start()

        return True

    def send_file(self, peer_id: str, file_path: str) -> Optional[str]:
        """Send file with enhanced error checking."""
        # Validate peer connection
        if peer_id not in self.peers:
            logger.error(f"❌ Peer {peer_id} not found")
            return None

        if not self.peers[peer_id].get('connected'):
            logger.error(f"❌ Peer {peer_id} is not connected")
            return None

        # Validate file
        if not os.path.exists(file_path):
            logger.error(f"❌ File not found: {file_path}")
            return None

        # Get peer info
        peer_ip = self.peers[peer_id]['addr'][0]
        peer_tcp_port = self.peers[peer_id].get('tcp_port')

        if not peer_tcp_port:
            logger.error(f"❌ Peer {peer_id} TCP port unknown")
            return None

        # Log file transfer attempt
        file_size = os.path.getsize(file_path)
        logger.info(f"🚀 Starting file transfer:")
        logger.info(f"  File: {os.path.basename(file_path)} ({file_size} bytes)")
        logger.info(f"  To: {peer_id} at {peer_ip}:{peer_tcp_port}")

        try:
            transfer_id = self.tcp_file_transfer.send_file(
                file_path,
                peer_id,
                peer_ip,
                peer_tcp_port,
                self._on_transfer_progress
            )

            if transfer_id:
                logger.info(f"✅ File transfer initiated: {transfer_id}")
                return transfer_id
            else:
                logger.error(f"❌ Failed to initiate file transfer")
                return None

        except Exception as e:
            logger.error(f"❌ Error sending file: {e}")
            return None

    def send_message(self, peer_id: str, message: str) -> bool:
        """Send message with better error handling."""
        if peer_id not in self.peers or not self.peers[peer_id].get('connected'):
            logger.error(f"❌ Peer {peer_id} is not connected")
            return False

        msg = {
            'type': 'test_message',
            'from': self.node_id,
            'message': message
        }
        try:
            self.socket.sendto(json.dumps(msg).encode(), self.peers[peer_id]['addr'])
            logger.info(f"📤 Message sent to {peer_id}")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to send message: {e}")
            return False

    def get_next_incoming_message(self) -> Optional[dict]:
        """Get next incoming message."""
        try:
            return self.incoming_messages.get_nowait()
        except queue.Empty:
            return None

    def get_transfer_status(self, transfer_id: str) -> Dict:
        """Get transfer status."""
        return self.tcp_file_transfer.get_transfer_status(transfer_id)

    def list_transfers(self) -> Dict[str, Dict]:
        """List all transfers."""
        return self.tcp_file_transfer.list_transfers()

    def get_peer_info(self) -> Dict:
        """Get peer information."""
        return {
            'node_id': self.node_id,
            'external_ip': self.external_ip,
            'external_port': self.external_port,
            'tcp_port': self.tcp_file_transfer.tcp_port,
            'nat_type': str(self.nat_type) if self.nat_type else 'Unknown'
        }

    def list_peers(self) -> Dict[str, Dict]:
        """List connected peers."""
        return {pid: {
            'addr': peer['addr'],
            'tcp_port': peer.get('tcp_port'),
            'connected': peer.get('connected', False),
            'last_seen': peer.get('last_seen', 0)
        } for pid, peer in self.peers.items()}

    def _handle_messages(self) -> None:
        """Handle incoming messages."""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(65536)

                try:
                    text_data = data.decode('utf-8')
                    message = json.loads(text_data)
                    message_type = message.get('type')

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
                            logger.info(f"📨 Message from unknown peer: {addr}")

                except (json.JSONDecodeError, UnicodeDecodeError):
                    logger.debug(f"Non-JSON data from {addr}")

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Message handling error: {e}")

    def _handle_hello(self, message: Dict, addr: Tuple[str, int]) -> None:
        """Handle hello message."""
        peer_id = message.get('node_id')
        peer_public_key_pem = message.get('public_key')
        peer_tcp_port = message.get('tcp_port')

        if not peer_id or not peer_public_key_pem:
            logger.error("❌ Invalid hello message")
            return

        logger.info(f"👋 Hello from {peer_id[:16]}... at {addr} (TCP: {peer_tcp_port})")

        # Store peer info
        self.peers[peer_id] = {
            'addr': addr,
            'tcp_port': peer_tcp_port,
            'public_key': self.crypto_manager.load_peer_public_key(peer_public_key_pem.encode()),
            'connected': True,
            'last_seen': time.time()
        }

        # Send hello ack
        hello_ack = {
            'type': 'hello_ack',
            'node_id': self.node_id,
            'public_key': self.crypto_manager.get_public_key_pem().decode(),
            'tcp_port': self.tcp_file_transfer.tcp_port
        }

        hello_ack_json = json.dumps(hello_ack).encode()
        self.socket.sendto(hello_ack_json, addr)

        # Generate session key
        self._send_session_key(peer_id)

    def _handle_hello_ack(self, message: Dict, addr: Tuple[str, int]) -> None:
        """Handle hello ack."""
        peer_id = message.get('node_id')
        peer_public_key_pem = message.get('public_key')
        peer_tcp_port = message.get('tcp_port')

        if not peer_id or not peer_public_key_pem:
            logger.error("❌ Invalid hello_ack message")
            return

        logger.info(f"✅ Hello ACK from {peer_id[:16]}... (TCP: {peer_tcp_port})")

        if peer_id in self.peers:
            self.peers[peer_id]['public_key'] = self.crypto_manager.load_peer_public_key(
                peer_public_key_pem.encode()
            )
            self.peers[peer_id]['tcp_port'] = peer_tcp_port
            self.peers[peer_id]['connected'] = True
            self.peers[peer_id]['last_seen'] = time.time()

            self._send_session_key(peer_id)
        else:
            logger.warning(f"⚠️ Hello ACK from unknown peer {peer_id}")

    def _send_session_key(self, peer_id: str) -> None:
        """Send session key to peer."""
        if peer_id not in self.peers or not self.peers[peer_id].get('public_key'):
            logger.error(f"❌ Cannot send session key to {peer_id}: missing public key")
            return

        try:
            # Generate session key
            key, iv = self.crypto_manager.generate_session_key()

            # Encrypt with peer's public key
            encrypted_key_package = self.crypto_manager.encrypt_session_key(
                self.peers[peer_id]['public_key'],
                key,
                iv
            )

            # Store session key
            self.crypto_manager.store_peer_session_key(peer_id, key, iv)

            # Send encrypted key
            key_exchange = {
                'type': 'key_exchange',
                'node_id': self.node_id,
                'encrypted_key': base64.b64encode(encrypted_key_package).decode()
            }

            key_exchange_json = json.dumps(key_exchange).encode()
            self.socket.sendto(key_exchange_json, self.peers[peer_id]['addr'])

            logger.info(f"🔑 Session key sent to {peer_id[:16]}...")

        except Exception as e:
            logger.error(f"❌ Failed to send session key to {peer_id}: {e}")

    def _handle_key_exchange(self, message: Dict, addr: Tuple[str, int]) -> None:
        """Handle key exchange."""
        peer_id = message.get('node_id')
        encrypted_key_b64 = message.get('encrypted_key')

        if not peer_id or not encrypted_key_b64:
            logger.error("❌ Invalid key_exchange message")
            return

        logger.info(f"🔑 Session key from {peer_id[:16]}...")

        try:
            encrypted_key_package = base64.b64decode(encrypted_key_b64)
            key, iv = self.crypto_manager.decrypt_session_key(encrypted_key_package)

            self.crypto_manager.store_peer_session_key(peer_id, key, iv)

            # Send ack
            key_exchange_ack = {
                'type': 'key_exchange_ack',
                'node_id': self.node_id
            }

            key_exchange_ack_json = json.dumps(key_exchange_ack).encode()
            self.socket.sendto(key_exchange_ack_json, addr)

            logger.info(f"✅ Session key exchange with {peer_id[:16]}... completed")

        except Exception as e:
            logger.error(f"❌ Error decrypting session key: {e}")

    def _handle_key_exchange_ack(self, message: Dict, addr: Tuple[str, int]) -> None:
        """Handle key exchange ack."""
        peer_id = message.get('node_id')

        if not peer_id:
            logger.error("❌ Invalid key_exchange_ack message")
            return

        logger.info(f"✅ Key exchange ACK from {peer_id[:16]}...")

        if peer_id in self.peers:
            self.peers[peer_id]['last_seen'] = time.time()

    def _on_transfer_progress(self, transfer_id: str, chunks_processed: int, total_chunks: int) -> None:
        """Transfer progress callback."""
        progress = (chunks_processed / total_chunks) * 100 if total_chunks > 0 else 0
        if chunks_processed % 10 == 0 or progress >= 100:  # Log every 10 chunks or completion
            logger.info(f"📊 Transfer {transfer_id[:8]}...: {progress:.1f}%")

    def stop(self) -> None:
        """Stop the P2P node."""
        logger.info("🛑 Stopping P2P node...")
        self.running = False

        if self.socket:
            self.socket.close()

        self.tcp_file_transfer.stop()

        logger.info("✅ P2P node stopped")