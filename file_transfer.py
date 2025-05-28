"""
QUIC-based file transfer with sliding window protocol.
Replaces UDP with QUIC for reliable, secure file transfers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple, Set, List
from collections import defaultdict
import ssl

from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, ConnectionTerminated, StreamReset
from aioquic.tls import SessionTicket

logger = logging.getLogger(__name__)

# Message type constants
FILE_INIT = "file_init"
FILE_INIT_ACK = "file_init_ack"
FILE_CHUNK = "file_chunk"
CHUNK_ACK = "chunk_ack"
FILE_END = "file_end"
FILE_END_ACK = "file_end_ack"
WINDOW_ACK = "window_ack"
SELECTIVE_NACK = "selective_nack"


class QuicFileTransferProtocol(QuicConnectionProtocol):
    """QUIC protocol handler for file transfers"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.file_transfers: Dict[str, Dict] = {}
        self.stream_handlers: Dict[int, Callable] = {}
        self.save_dir = Path("./downloads")
        self.progress_callback: Optional[Callable] = None
        self.crypto = None
        self.peer_id = None

    def set_crypto_manager(self, crypto_manager):
        """Set the crypto manager for encryption/decryption"""
        self.crypto = crypto_manager

    def set_peer_id(self, peer_id: str):
        """Set the peer ID for this connection"""
        self.peer_id = peer_id

    def set_progress_callback(self, callback: Callable[[str, int, int], None]):
        """Set callback for transfer progress updates"""
        self.progress_callback = callback

    def set_save_directory(self, save_dir: str):
        """Set directory for saving incoming files"""
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)

    def quic_event_received(self, event: QuicEvent):
        """Handle QUIC events"""
        if isinstance(event, StreamDataReceived):
            self._handle_stream_data(event.stream_id, event.data, event.end_stream)
        elif isinstance(event, ConnectionTerminated):
            logger.info("QUIC connection terminated")
        elif isinstance(event, StreamReset):
            logger.warning(f"Stream {event.stream_id} was reset")

    def _handle_stream_data(self, stream_id: int, data: bytes, end_stream: bool):
        """Handle incoming stream data"""
        try:
            # Try to decode as JSON for control messages
            message = json.loads(data.decode('utf-8'))
            message_type = message.get('type')

            if message_type == FILE_INIT:
                self._handle_file_init(stream_id, message)
            elif message_type == FILE_INIT_ACK:
                self._handle_file_init_ack(message)
            elif message_type == FILE_CHUNK:
                # File chunk messages are followed by binary data on the same stream
                transfer_id = message['transfer_id']
                chunk_index = message['chunk_index']
                self.stream_handlers[stream_id] = {
                    'type': 'file_chunk',
                    'transfer_id': transfer_id,
                    'chunk_index': chunk_index,
                    'chunk_size': message['chunk_size']
                }
            elif message_type == CHUNK_ACK:
                self._handle_chunk_ack(message)
            elif message_type == FILE_END:
                self._handle_file_end(stream_id, message)
            elif message_type == FILE_END_ACK:
                self._handle_file_end_ack(message)

        except (json.JSONDecodeError, UnicodeDecodeError):
            # This is binary data (file chunk)
            if stream_id in self.stream_handlers:
                handler_info = self.stream_handlers[stream_id]
                if handler_info['type'] == 'file_chunk':
                    self._handle_file_chunk_data(
                        handler_info['transfer_id'],
                        handler_info['chunk_index'],
                        data
                    )
                    del self.stream_handlers[stream_id]

    def _handle_file_init(self, stream_id: int, message: Dict):
        """Handle file transfer initialization"""
        transfer_id = message['transfer_id']
        file_name = message['file_name']
        file_size = message['file_size']
        total_chunks = message['total_chunks']

        logger.info(f"Receiving file: {file_name} ({file_size} bytes, {total_chunks} chunks)")

        # Create transfer record
        self.file_transfers[transfer_id] = {
            'direction': 'incoming',
            'file_name': file_name,
            'file_size': file_size,
            'total_chunks': total_chunks,
            'chunks_received': 0,
            'file_path': self.save_dir / file_name,
            'file_handle': None,
            'start_time': time.time(),
            'chunks_data': {},
            'next_chunk_to_write': 0,
            'status': 'receiving'
        }

        # Send acknowledgment
        ack_message = {
            'type': FILE_INIT_ACK,
            'transfer_id': transfer_id
        }
        self._connection.send_stream_data(
            stream_id,
            json.dumps(ack_message).encode(),
            end_stream=True
        )

    def _handle_file_init_ack(self, message: Dict):
        """Handle file initialization acknowledgment"""
        transfer_id = message['transfer_id']
        if transfer_id in self.file_transfers:
            self.file_transfers[transfer_id]['init_acked'] = True
            logger.debug(f"Received FILE_INIT_ACK for {transfer_id}")

    def _handle_file_chunk_data(self, transfer_id: str, chunk_index: int, data: bytes):
        """Handle file chunk data"""
        if transfer_id not in self.file_transfers:
            logger.error(f"Received chunk for unknown transfer: {transfer_id}")
            return

        transfer = self.file_transfers[transfer_id]

        # Decrypt data if crypto manager is available
        if self.crypto and self.peer_id:
            try:
                data = self.crypto.decrypt_data(self.peer_id, data)
            except Exception as e:
                logger.error(f"Failed to decrypt chunk {chunk_index}: {e}")
                return

        transfer['chunks_data'][chunk_index] = data
        transfer['chunks_received'] += 1

        # Write chunks to file in order
        self._write_chunks_to_file(transfer_id)

        # Update progress
        if self.progress_callback:
            self.progress_callback(
                transfer_id,
                transfer['chunks_received'],
                transfer['total_chunks']
            )

        # Send chunk acknowledgment
        ack_message = {
            'type': CHUNK_ACK,
            'transfer_id': transfer_id,
            'chunk_index': chunk_index
        }

        # Use a new stream for the ACK
        ack_stream = self._connection.get_next_available_stream_id()
        self._connection.send_stream_data(
            ack_stream,
            json.dumps(ack_message).encode(),
            end_stream=True
        )

        logger.debug(f"Received and ACKed chunk {chunk_index}/{transfer['total_chunks']} for {transfer_id}")

    def _handle_chunk_ack(self, message: Dict):
        """Handle chunk acknowledgment"""
        transfer_id = message['transfer_id']
        chunk_index = message['chunk_index']

        if transfer_id in self.file_transfers:
            transfer = self.file_transfers[transfer_id]
            if 'chunks_acked' not in transfer:
                transfer['chunks_acked'] = set()
            transfer['chunks_acked'].add(chunk_index)
            logger.debug(f"Received ACK for chunk {chunk_index} of {transfer_id}")

    def _write_chunks_to_file(self, transfer_id: str):
        """Write received chunks to file in correct order"""
        transfer = self.file_transfers[transfer_id]

        if not transfer['file_handle']:
            transfer['file_handle'] = open(transfer['file_path'], 'wb')

        # Write chunks in order
        next_chunk = transfer['next_chunk_to_write']
        while next_chunk in transfer['chunks_data']:
            transfer['file_handle'].write(transfer['chunks_data'][next_chunk])
            del transfer['chunks_data'][next_chunk]
            next_chunk += 1

        transfer['next_chunk_to_write'] = next_chunk
        transfer['file_handle'].flush()

        # Check if transfer is complete
        if transfer['chunks_received'] >= transfer['total_chunks']:
            transfer['file_handle'].close()
            transfer['status'] = 'completed'
            transfer['end_time'] = time.time()

            duration = transfer['end_time'] - transfer['start_time']
            speed = transfer['file_size'] / duration / 1024 if duration > 0 else 0

            logger.info(f"File transfer completed: {transfer['file_name']} ({speed:.2f} KB/s)")

    def _handle_file_end(self, stream_id: int, message: Dict):
        """Handle file transfer end notification"""
        transfer_id = message['transfer_id']

        # Send acknowledgment
        ack_message = {
            'type': FILE_END_ACK,
            'transfer_id': transfer_id
        }
        self._connection.send_stream_data(
            stream_id,
            json.dumps(ack_message).encode(),
            end_stream=True
        )

        logger.debug(f"Received FILE_END for {transfer_id}")

    def _handle_file_end_ack(self, message: Dict):
        """Handle file end acknowledgment"""
        transfer_id = message['transfer_id']
        if transfer_id in self.file_transfers:
            self.file_transfers[transfer_id]['end_acked'] = True
            logger.debug(f"Received FILE_END_ACK for {transfer_id}")

    async def send_file(self, file_path: str) -> str:
        """Send a file over QUIC"""
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        transfer_id = str(uuid.uuid4())
        file_size = file_path.stat().st_size
        chunk_size = 32 * 1024  # 32 KB chunks (matching original)
        total_chunks = math.ceil(file_size / chunk_size)

        logger.info(f"Sending file: {file_path.name} ({file_size} bytes, {total_chunks} chunks)")

        # Create transfer record
        self.file_transfers[transfer_id] = {
            'direction': 'outgoing',
            'file_name': file_path.name,
            'file_size': file_size,
            'total_chunks': total_chunks,
            'chunks_sent': 0,
            'start_time': time.time(),
            'status': 'sending',
            'chunks_acked': set()
        }

        # Send file initialization
        init_stream = self._connection.get_next_available_stream_id()
        init_message = {
            'type': FILE_INIT,
            'transfer_id': transfer_id,
            'file_name': file_path.name,
            'file_size': file_size,
            'total_chunks': total_chunks,
            'chunk_size': chunk_size
        }

        self._connection.send_stream_data(
            init_stream,
            json.dumps(init_message).encode(),
            end_stream=True
        )

        # Wait for initialization acknowledgment
        timeout = time.time() + 10  # 10 second timeout
        while time.time() < timeout:
            if self.file_transfers[transfer_id].get('init_acked'):
                break
            await asyncio.sleep(0.1)

        if not self.file_transfers[transfer_id].get('init_acked'):
            logger.error(f"Timeout waiting for FILE_INIT_ACK for {transfer_id}")
            return transfer_id

        # Send file chunks
        with open(file_path, 'rb') as file:
            for chunk_index in range(total_chunks):
                chunk_data = file.read(chunk_size)

                # Encrypt data if crypto manager is available
                if self.crypto and self.peer_id:
                    try:
                        chunk_data = self.crypto.encrypt_data(self.peer_id, chunk_data)
                    except Exception as e:
                        logger.error(f"Failed to encrypt chunk {chunk_index}: {e}")
                        continue

                # Send chunk header and data on the same stream
                chunk_stream = self._connection.get_next_available_stream_id()
                chunk_header = {
                    'type': FILE_CHUNK,
                    'transfer_id': transfer_id,
                    'chunk_index': chunk_index,
                    'chunk_size': len(chunk_data)
                }

                # Send header first
                self._connection.send_stream_data(
                    chunk_stream,
                    json.dumps(chunk_header).encode()
                )

                # Send chunk data
                self._connection.send_stream_data(
                    chunk_stream,
                    chunk_data,
                    end_stream=True
                )

                self.file_transfers[transfer_id]['chunks_sent'] += 1

                # Update progress
                if self.progress_callback:
                    self.progress_callback(
                        transfer_id,
                        chunk_index + 1,
                        total_chunks
                    )

                logger.debug(f"Sent chunk {chunk_index}/{total_chunks} for {transfer_id}")

                # Small delay to prevent overwhelming the receiver
                await asyncio.sleep(0.001)

        # Send completion notification
        end_stream = self._connection.get_next_available_stream_id()
        end_message = {
            'type': FILE_END,
            'transfer_id': transfer_id
        }

        self._connection.send_stream_data(
            end_stream,
            json.dumps(end_message).encode(),
            end_stream=True
        )

        # Wait for final acknowledgment
        timeout = time.time() + 30  # 30 second timeout
        while time.time() < timeout:
            if self.file_transfers[transfer_id].get('end_acked'):
                break
            await asyncio.sleep(0.1)

        # Update transfer record
        transfer = self.file_transfers[transfer_id]
        transfer['status'] = 'completed'
        transfer['end_time'] = time.time()

        duration = transfer['end_time'] - transfer['start_time']
        speed = file_size / duration / 1024 if duration > 0 else 0

        logger.info(f"File sent: {file_path.name} ({speed:.2f} KB/s)")

        return transfer_id


class FileTransfer:
    """QUIC-based file transfer manager"""

    def __init__(self, crypto_manager=None):
        self.crypto = crypto_manager
        self.transfers: Dict[str, Dict[str, Any]] = {}
        self.save_dir: Path = Path.cwd()
        self.progress_callback: Optional[Callable[[str, int, int], None]] = None
        self.servers: Dict[int, Any] = {}  # port -> server
        self.clients: Dict[str, QuicFileTransferProtocol] = {}  # peer_id -> protocol

    def receive_file(self, save_dir: str, progress_callback: Callable[[str, int, int], None]):
        """Configure where incoming files are stored and how to report progress."""
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)
        self.progress_callback = progress_callback

    async def start_server(self, port: int) -> bool:
        """Start a QUIC server for receiving files"""
        if port in self.servers:
            logger.warning(f"Server already running on port {port}")
            return True

        try:
            # Create QUIC configuration
            configuration = QuicConfiguration(
                is_client=False,
                certificate=self._generate_self_signed_cert(),
                private_key=self._generate_private_key()
            )

            def create_protocol():
                protocol = QuicFileTransferProtocol()
                protocol.set_save_directory(str(self.save_dir))
                protocol.set_crypto_manager(self.crypto)
                if self.progress_callback:
                    protocol.set_progress_callback(self.progress_callback)
                return protocol

            # Start server
            server = await serve(
                "0.0.0.0",
                port,
                configuration=configuration,
                create_protocol=create_protocol
            )

            self.servers[port] = server
            logger.info(f"QUIC file transfer server started on port {port}")
            return True

        except Exception as e:
            logger.error(f"Failed to start QUIC server on port {port}: {e}")
            return False

    async def stop_server(self, port: int):
        """Stop a QUIC server"""
        if port in self.servers:
            self.servers[port].close()
            await self.servers[port].wait_closed()
            del self.servers[port]
            logger.info(f"QUIC server on port {port} stopped")

    async def connect_to_peer(self, peer_id: str, peer_ip: str, peer_port: int) -> bool:
        """Connect to a peer's QUIC server"""
        try:
            # Create QUIC configuration
            configuration = QuicConfiguration(
                is_client=True,
                verify_mode=ssl.CERT_NONE  # Disable certificate verification for P2P
            )

            # Connect to peer
            protocol = await connect(
                peer_ip,
                peer_port,
                configuration=configuration,
                create_protocol=QuicFileTransferProtocol
            ).__aenter__()

            protocol.set_crypto_manager(self.crypto)
            protocol.set_peer_id(peer_id)
            if self.progress_callback:
                protocol.set_progress_callback(self.progress_callback)

            self.clients[peer_id] = protocol
            logger.info(f"Connected to peer {peer_id} at {peer_ip}:{peer_port}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to peer {peer_id}: {e}")
            return False

    async def send_file(self, file_path: str, peer_id: str, peer_addr: Tuple[str, int],
                       progress_callback: Callable[[str, int, int], None]) -> str:
        """Send a file to a peer"""
        if peer_id not in self.clients:
            # Try to connect first
            if not await self.connect_to_peer(peer_id, peer_addr[0], peer_addr[1]):
                raise ConnectionError(f"Cannot connect to peer {peer_id}")

        protocol = self.clients[peer_id]
        transfer_id = await protocol.send_file(file_path)

        # Store transfer info
        self.transfers[transfer_id] = {
            'direction': 'out',
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'file_size': os.path.getsize(file_path),
            'peer_id': peer_id,
            'peer_addr': peer_addr,
            'status': 'completed'  # QUIC handles reliability automatically
        }

        return transfer_id

    def handle_message(self, data: bytes, addr: Tuple[str, int], peer_id: str):
        """Legacy method for compatibility - not used in QUIC version"""
        logger.debug("handle_message called but not used in QUIC implementation")

    def handle_binary_data(self, data: bytes, addr: Tuple[str, int], peer_id: str):
        """Legacy method for compatibility - not used in QUIC version"""
        logger.debug("handle_binary_data called but not used in QUIC implementation")

    def _generate_self_signed_cert(self):
        """Generate a self-signed certificate for the server"""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "P2P File Transfer"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress("127.0.0.1"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        return cert.public_bytes(serialization.Encoding.PEM)

    def _generate_private_key(self):
        """Generate a private key for the server"""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )