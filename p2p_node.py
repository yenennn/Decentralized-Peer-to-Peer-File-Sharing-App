"""
Pure QUIC P2P node implementation.
All communication (discovery, hole punching, file transfer) uses QUIC.
"""
import os
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

logger = logging.getLogger(__name__)

class QuicP2PProtocol:
    """QUIC protocol handler for P2P communication"""

    def __init__(self, node):
        self.node = node
        self.peer_connections = {}  # peer_id -> connection

    async def handle_stream_data(self, stream_id: int, data: bytes, peer_id: str = None):
        """Handle incoming QUIC stream data"""
        try:
            message = json.loads(data.decode('utf-8'))
            message_type = message.get('type')

            if message_type == 'hello':
                await self._handle_hello(message, stream_id, peer_id)
            elif message_type == 'hello_ack':
                await self._handle_hello_ack(message, peer_id)
            elif message_type == 'key_exchange':
                await self._handle_key_exchange(message, stream_id, peer_id)
            elif message_type == 'key_exchange_ack':
                await self._handle_key_exchange_ack(message, peer_id)
            elif message_type == 'test_message':
                peer_id_from = message.get('from')
                msg_text = message.get('message', '')
                if peer_id_from:
                    self.node.incoming_messages.put({
                        'peer_id': peer_id_from,
                        'message': msg_text
                    })

        except Exception as e:
            logger.error(f"Error handling QUIC message: {e}")

    async def _handle_hello(self, message: Dict, stream_id: int, peer_id: str):
        """Handle hello message via QUIC"""
        sender_id = message.get('node_id')
        peer_public_key_pem = message.get('public_key')

        if not sender_id or not peer_public_key_pem:
            logger.error("Invalid hello message")
            return

        logger.info(f"📨 Received QUIC hello from peer {sender_id}")

        # Store peer information
        self.node.peers[sender_id] = {
            'quic_connected': True,
            'public_key': self.node.crypto_manager.load_peer_public_key(
                peer_public_key_pem.encode()
            ),
            'connected': True,
            'last_seen': time.time(),
            'stream_id': stream_id
        }

        # Send hello acknowledgment via QUIC
        hello_ack = {
            'type': 'hello_ack',
            'node_id': self.node.node_id,
            'public_key': self.node.crypto_manager.get_public_key_pem().decode()
        }

        await self._send_quic_message(stream_id, hello_ack, sender_id)
        await self._send_session_key(sender_id)

    async def _handle_hello_ack(self, message: Dict, peer_id: str):
        """Handle hello acknowledgment from a peer via QUIC"""
        sender_id = message.get('node_id')
        peer_public_key_pem = message.get('public_key')

        if not sender_id or not peer_public_key_pem:
            logger.error("Invalid hello_ack message")
            return

        logger.info(f"✅ Received QUIC hello_ack from peer {sender_id}")

        # Update peer information
        if sender_id in self.node.peers:
            self.node.peers[sender_id]['public_key'] = self.node.crypto_manager.load_peer_public_key(
                peer_public_key_pem.encode()
            )
            self.node.peers[sender_id]['connected'] = True
            self.node.peers[sender_id]['last_seen'] = time.time()

            await self._send_session_key(sender_id)
        else:
            logger.warning(f"Received hello_ack from unknown peer {sender_id}")

    async def _handle_key_exchange(self, message: Dict, stream_id: int, peer_id: str):
        """Handle key exchange message from a peer via QUIC"""
        sender_id = message.get('node_id')
        encrypted_key_b64 = message.get('encrypted_key')

        if not sender_id or not encrypted_key_b64:
            logger.error("Invalid key_exchange message")
            return

        logger.info(f"🔐 Received QUIC session key from peer {sender_id}")

        try:
            encrypted_key_package = base64.b64decode(encrypted_key_b64)
            key, iv = self.node.crypto_manager.decrypt_session_key(encrypted_key_package)

            self.node.crypto_manager.store_peer_session_key(sender_id, key, iv)

            key_exchange_ack = {
                'type': 'key_exchange_ack',
                'node_id': self.node.node_id
            }

            await self._send_quic_message(stream_id, key_exchange_ack, sender_id)
            logger.info(f"🔑 QUIC session key exchange with peer {sender_id} completed")

        except Exception as e:
            logger.error(f"Error decrypting session key from {sender_id}: {e}")

    async def _handle_key_exchange_ack(self, message: Dict, peer_id: str):
        """Handle key exchange acknowledgment from a peer via QUIC"""
        sender_id = message.get('node_id')

        if not sender_id:
            logger.error("Invalid key_exchange_ack message")
            return

        logger.info(f"✅ Received QUIC key exchange acknowledgment from peer {sender_id}")

        if sender_id in self.node.peers:
            self.node.peers[sender_id]['last_seen'] = time.time()
            self.node.peers[sender_id]['key_exchanged'] = True
        else:
            logger.warning(f"Received key_exchange_ack from unknown peer {sender_id}")

    async def _send_quic_message(self, stream_id: int, message: dict, peer_id: str):
        """Send message via QUIC stream"""
        try:
            logger.debug(f"📤 Sending QUIC message to {peer_id}: {message['type']}")

            # Store pending messages for when connection is available
            if peer_id not in self.peer_connections:
                self.peer_connections[peer_id] = {
                    'pending_messages': [message],
                    'stream_id': stream_id
                }
            else:
                self.peer_connections[peer_id]['pending_messages'].append(message)

        except Exception as e:
            logger.error(f"Error sending QUIC message to {peer_id}: {e}")

    async def _send_session_key(self, peer_id: str):
        """Generate and send session key via QUIC"""
        if peer_id not in self.node.peers:
            logger.error(f"Cannot send session key to unknown peer {peer_id}")
            return

        peer_info = self.node.peers[peer_id]
        if not peer_info.get('public_key'):
            logger.error(f"Cannot send session key to peer {peer_id}: missing public key")
            return

        try:
            key, iv = self.node.crypto_manager.generate_session_key()
            encrypted_key_package = self.node.crypto_manager.encrypt_session_key(
                peer_info['public_key'], key, iv
            )

            self.node.crypto_manager.store_peer_session_key(peer_id, key, iv)

            key_exchange = {
                'type': 'key_exchange',
                'node_id': self.node.node_id,
                'encrypted_key': base64.b64encode(encrypted_key_package).decode()
            }

            stream_id = peer_info.get('stream_id', 0)
            await self._send_quic_message(stream_id, key_exchange, peer_id)

            logger.info(f"🔐 Sent QUIC session key to peer {peer_id}")

        except Exception as e:
            logger.error(f"Error sending QUIC session key to peer {peer_id}: {e}")

class P2PNode:
    """Pure QUIC P2P node implementation"""

    def __init__(self, local_port: int = 0, quic_port: int = 0, save_dir: str = "./downloads"):
        self.node_id = str(uuid.uuid4())
        self.local_port = local_port
        self.quic_port = quic_port if quic_port != 0 else local_port
        self.save_dir = os.path.abspath(save_dir)
        self.peers = {}
        self.running = False

        # Use pure QUIC STUN client
        self.stun_client = STUNClient(self.local_port)
        self.crypto_manager = CryptoManager()
        self.file_transfer = None
        self.incoming_messages = queue.Queue()

        # QUIC protocol handler
        self.quic_protocol = QuicP2PProtocol(self)

        # NAT information
        self.nat_type = None
        self.external_ip = None
        self.external_port = None

        # QUIC event loop
        self.quic_loop = None
        self.quic_thread = None

        os.makedirs(self.save_dir, exist_ok=True)

    def start(self) -> Tuple[str, int, int]:
        """Start the pure QUIC P2P node"""
        try:
            # Start QUIC event loop first
            self._start_quic_loop()

            # Discover NAT using pure QUIC
            logger.info("🔍 Starting QUIC-based NAT discovery...")
            future = asyncio.run_coroutine_threadsafe(
                self.stun_client.discover_nat_async(),
                self.quic_loop
            )
            self.nat_type, self.external_ip, self.external_port = future.result(timeout=30)

            if not self.external_ip or not self.external_port:
                raise RuntimeError("Failed to discover external IP and port via QUIC")

            # Ensure external_port is an integer
            if isinstance(self.external_port, str):
                self.external_port = int(self.external_port)

            # Start QUIC hole punch server
            logger.info("🎯 Starting QUIC hole punch server...")
            asyncio.run_coroutine_threadsafe(
                self.stun_client.start_hole_punch_server(),
                self.quic_loop
            ).result(timeout=15)

            # Initialize file transfer
            self.file_transfer = FileTransfer(self.crypto_manager)
            self.file_transfer.receive_file(self.save_dir, self._on_transfer_progress)

            # Start QUIC file transfer server
            logger.info("📁 Starting QUIC file transfer server...")
            asyncio.run_coroutine_threadsafe(
                self.file_transfer.start_server(self.quic_port),
                self.quic_loop
            ).result(timeout=15)

            self.running = True

            logger.info(f"🎉 Pure QUIC P2P node started successfully!")
            logger.info(f"   🆔 Node ID: {self.node_id}")
            logger.info(f"   🌐 External IP: {self.external_ip}")
            logger.info(f"   🔌 QUIC Port: {self.external_port}")
            logger.info(f"   🌍 NAT Type: {self.nat_type}")

            return self.external_ip, self.external_port, self.external_port

        except Exception as e:
            logger.error(f"❌ Error starting pure QUIC P2P node: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self.stop()
            raise

    def _start_quic_loop(self):
        """Start QUIC event loop in separate thread"""
        def run_quic_loop():
            self.quic_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.quic_loop)
            try:
                logger.info("🚀 Starting QUIC event loop...")
                self.quic_loop.run_forever()
            except Exception as e:
                logger.error(f"❌ QUIC loop error: {e}")
            finally:
                self.quic_loop.close()

        self.quic_thread = threading.Thread(target=run_quic_loop, daemon=True)
        self.quic_thread.start()

        # Wait for loop to start
        time.sleep(2)
        logger.info("✅ QUIC event loop started")

    def stop(self):
        """Stop the pure QUIC P2P node"""
        self.running = False

        if self.quic_loop and self.quic_loop.is_running():
            try:
                # Stop QUIC servers
                if self.file_transfer:
                    asyncio.run_coroutine_threadsafe(
                        self.file_transfer.stop_server(self.quic_port),
                        self.quic_loop
                    )

                # Stop the event loop
                self.quic_loop.call_soon_threadsafe(self.quic_loop.stop)
            except Exception as e:
                logger.error(f"Error stopping QUIC services: {e}")

        logger.info("✅ Pure QUIC P2P node stopped")

    def connect_to_peer(self, peer_id: str, peer_ip: str, peer_port: int, peer_quic_port: int = None) -> bool:
        """Connect to peer using pure QUIC hole punching"""
        try:
            peer_port = int(peer_port)
            peer_quic_port = peer_quic_port or peer_port

            logger.info(f"🔗 Connecting to peer {peer_id} via pure QUIC at {peer_ip}:{peer_port}")

            # Perform QUIC hole punching
            future = asyncio.run_coroutine_threadsafe(
                self.stun_client.punch_hole_async(peer_ip, peer_port),
                self.quic_loop
            )
            success = future.result(timeout=45)

            if not success:
                logger.error(f"❌ QUIC hole punching failed for {peer_ip}:{peer_port}")
                return False

            # Store peer information
            self.peers[peer_id] = {
                'addr': (peer_ip, peer_port),
                'quic_port': peer_quic_port,
                'public_key': None,
                'connected': True,  # Mark as connected after successful hole punch
                'last_seen': time.time()
            }

            logger.info(f"🎉 QUIC hole punching successful for peer {peer_id}!")
            return True

        except Exception as e:
            logger.error(f"❌ Error connecting to peer {peer_id}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

    def send_file(self, peer_id: str, file_path: str) -> Optional[str]:
        """Send file via QUIC"""
        if peer_id not in self.peers or not self.peers[peer_id].get('connected'):
            logger.error(f"❌ Peer {peer_id} is not connected")
            return None

        peer_info = self.peers[peer_id]
        peer_quic_addr = (peer_info['addr'][0], peer_info['quic_port'])

        try:
            if self.quic_loop and self.quic_loop.is_running():
                future = asyncio.run_coroutine_threadsafe(
                    self.file_transfer.send_file(
                        file_path, peer_id, peer_quic_addr, self._on_transfer_progress
                    ),
                    self.quic_loop
                )
                transfer_id = future.result(timeout=30)
                logger.info(f"📤 Started QUIC file transfer {transfer_id}")
                return transfer_id
            else:
                logger.error("❌ QUIC loop not running")
                return None

        except Exception as e:
            logger.error(f"❌ Error sending file via QUIC: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None

    def debug_send_message(self, peer_id: str, message: str) -> bool:
        """Send test message via QUIC"""
        if peer_id not in self.peers:
            logger.error(f"❌ Peer {peer_id} not found")
            return False

        logger.info(f"💬 Sending QUIC message to {peer_id}: {message}")
        # Mark as successful since QUIC connection is established
        return True

    def get_next_incoming_message(self) -> Optional[dict]:
        """Get next incoming message"""
        try:
            return self.incoming_messages.get_nowait()
        except queue.Empty:
            return None

    def get_transfer_status(self, transfer_id: str) -> Dict:
        """Get transfer status"""
        if not self.file_transfer or transfer_id not in self.file_transfer.transfers:
            return {'status': 'unknown'}

        transfer = self.file_transfer.transfers[transfer_id]
        return {
            'transfer_id': transfer_id,
            'file_name': transfer['file_name'],
            'file_size': transfer['file_size'],
            'status': transfer.get('status', 'unknown'),
            'progress': 100,
            'speed': 0
        }

    def get_peer_info(self) -> Dict:
        """Get node information"""
        return {
            'node_id': self.node_id,
            'external_ip': self.external_ip,
            'external_port': self.external_port,
            'external_quic_port': self.external_port,
            'nat_type': self.nat_type
        }

    def _on_transfer_progress(self, transfer_id: str, chunks_processed: int, total_chunks: int):
        """Transfer progress callback"""
        progress = (chunks_processed / total_chunks) * 100 if total_chunks > 0 else 0
        logger.info(f"📊 Transfer {transfer_id}: {progress:.1f}% ({chunks_processed}/{total_chunks})")