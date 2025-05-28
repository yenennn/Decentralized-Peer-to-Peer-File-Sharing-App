"""Main P2P node implementation.
Handles peer connections, NAT traversal, and file transfers using KCP integration.
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
from typing import Dict, Tuple, Optional, Callable, Any

from stun_client import STUNClient
from crypto import CryptoManager
from file_transfer import FileTransfer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class P2PNode:
    """
    P2P node for decentralized file sharing.
    Uses KCP-backed FileTransfer for reliable file delivery.
    """

    def __init__(self, local_port: int = 0, save_dir: str = "./downloads"):
        self.node_id = str(uuid.uuid4())
        self.local_port = local_port
        self.save_dir = os.path.abspath(save_dir)
        self.peers: Dict[str, Dict[str, Any]] = {}
        self.running = False
        self.stun_client = STUNClient(local_port)
        self.crypto_manager = CryptoManager()
        self.socket: Optional[socket.socket] = None
        self.file_transfer: Optional[FileTransfer] = None
        self.incoming_messages = queue.Queue()

    def start(self) -> Tuple[str, int]:
        """Discover NAT info, bind socket, and start message loop."""
        self.nat_type, self.external_ip, self.external_port = self.stun_client.discover_nat()
        if not self.external_ip or not self.external_port:
            raise RuntimeError("Failed NAT discovery")

        self.socket = self.stun_client.create_socket()
        self.file_transfer = FileTransfer(self.socket, self.crypto_manager)
        self.file_transfer.receive_file(self.save_dir, self._on_transfer_progress)

        self.running = True
        thread = threading.Thread(target=self._handle_messages, daemon=True)
        thread.start()
        logger.info(f"P2P node {self.node_id} started on port {self.local_port}")
        return self.external_ip, self.external_port

    def stop(self) -> None:
        """Gracefully stop the node and close socket."""
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info("P2P node stopped")

    def connect_to_peer(self, peer_id: str, peer_ip: str, peer_port: int) -> bool:
        """
        Perform NAT hole punching and exchange hello to establish connection.
        """
        logger.info(f"Connecting to peer {peer_id} at {peer_ip}:{peer_port}")
        if not self.stun_client.punch_hole(peer_ip, peer_port):
            logger.error(f"Failed to punch hole to {peer_ip}:{peer_port}")
            return False

        self.peers[peer_id] = {
            'addr': (peer_ip, peer_port),
            'public_key': None,
            'connected': False,
            'last_seen': time.time()
        }
        hello = {
            'type': 'hello',
            'node_id': self.node_id,
            'public_key': self.crypto_manager.get_public_key_pem().decode()
        }
        self.socket.sendto(json.dumps(hello).encode(), (peer_ip, peer_port))
        # spawn retry thread (omitted for brevity)
        return True

    def send_message(self, peer_id: str, message: str) -> bool:
        """Send a simple text message to a connected peer."""
        if peer_id not in self.peers or not self.peers[peer_id].get('connected'):
            logger.error(f"Peer {peer_id} is not connected")
            return False
        msg = {'type': 'test_message', 'from': self.node_id, 'message': message}
        try:
            self.socket.sendto(json.dumps(msg).encode(), self.peers[peer_id]['addr'])
            return True
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            return False

    def send_file(self, peer_id: str, file_path: str) -> Optional[str]:
        """Initiate a KCP-backed file transfer to a peer."""
        if peer_id not in self.peers or not self.peers[peer_id].get('connected'):
            logger.error("Peer not connected")
            return None
        addr = self.peers[peer_id]['addr']
        try:
            transfer_id = self.file_transfer.send_file(
                file_path, peer_id, addr, self._on_transfer_progress)
            logger.info(f"Started transfer {transfer_id}")
            return transfer_id
        except Exception as e:
            logger.error(f"Send file error: {e}")
            return None

    def get_peer_info(self) -> Dict[str, Any]:
        """Return this node's ID and external connection info for sharing with peers."""
        return {
            'node_id': self.node_id,
            'external_ip': getattr(self, 'external_ip', None),
            'external_port': getattr(self, 'external_port', None),
            'nat_type': getattr(self, 'nat_type', None)
        }

        """Initiate a KCP-backed file transfer to a peer."""
        if peer_id not in self.peers or not self.peers[peer_id].get('connected'):
            logger.error("Peer not connected")
            return None
        addr = self.peers[peer_id]['addr']
        try:
            transfer_id = self.file_transfer.send_file(
                file_path, peer_id, addr, self._on_transfer_progress)
            logger.info(f"Started transfer {transfer_id}")
            return transfer_id
        except Exception as e:
            logger.error(f"Send file error: {e}")
            return None

    def get_next_incoming_message(self) -> Optional[dict]:
        """Retrieve next text message from queue."""
        try:
            return self.incoming_messages.get_nowait()
        except queue.Empty:
            return None

    def get_transfer_status(self, transfer_id: str) -> Dict[str, Any]:
        """Return progress and status for an ongoing or completed transfer."""
        # Check send sessions
        sess = self.file_transfer._send_sessions.get(transfer_id)
        if sess:
            total = sess['file_size']
            # assume progress_cb updated a _bytes_sent field
            sent = sess.get('_bytes_sent', 0)
            pct = (sent / total * 100) if total else 0
            status = 'completed' if sess['end_acked'] else 'in_progress'
            return {'transfer_id': transfer_id, 'file_name': os.path.basename(sess['file_path']),
                    'file_size': total, 'progress': pct, 'status': status}
        # Check receive sessions
        sess = self.file_transfer._recv_sessions.get(transfer_id)
        if sess:
            total = sess['file_size']
            received = sess.get('received', 0)
            pct = (received / total * 100) if total else 0
            status = 'completed' if received >= total else 'in_progress'
            file_name = os.path.basename(sess['file_handle'].name)
            return {'transfer_id': transfer_id, 'file_name': file_name,
                    'file_size': total, 'progress': pct, 'status': status}
        return {'status': 'unknown'}

    def _handle_messages(self) -> None:
        """Dispatch JSON control and binary KCP packets."""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(64*1024)
                peer_id = next((pid for pid,p in self.peers.items() if p['addr']==addr), None)
                try:
                    msg = json.loads(data.decode())
                    # Control messages: file init/end, hello, key exchange, etc.
                    if peer_id:
                        self.file_transfer.handle_message(data, addr, peer_id)
                    # handle other JSON (hello/key) elsewhere
                except (json.JSONDecodeError, UnicodeDecodeError):
                    # Binary → KCP data
                    if peer_id:
                        self.file_transfer.handle_binary_data(data, addr, peer_id)
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Message loop error: {e}")
                break

    def _on_transfer_progress(self, transfer_id: str, processed: int, total: int) -> None:
        """Callback from FileTransfer reporting bytes sent/received."""
        pct = (processed / total * 100) if total else 0
        logger.info(f"Transfer {transfer_id}: {pct:.1f}% ({processed}/{total})")
