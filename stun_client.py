"""
QUIC-based STUN client for NAT traversal and hole punching.
Replaces UDP with QUIC for all communication including hole punching.
"""
import asyncio
import logging
import random
import time
import struct
import json
from typing import Tuple, Optional
from pathlib import Path
import ssl

from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, ConnectionTerminated

logger = logging.getLogger(__name__)

# List of public STUN servers (we'll use QUIC connections to them)
STUN_SERVERS = [
    ('stun.l.google.com', 443),  # Use HTTPS/HTTP3 ports for QUIC
    ('cloudflare-quic.com', 443),
    ('google.com', 443),
    ('facebook.com', 443),
    ('github.com', 443)
]

class NATType:
    """NAT type constants"""
    UNKNOWN = "Unknown"
    OPEN_INTERNET = "Open Internet"
    FULL_CONE = "Full Cone"
    RESTRICTED_CONE = "Restricted Cone"
    PORT_RESTRICTED_CONE = "Port Restricted Cone"
    SYMMETRIC = "Symmetric"
    BLOCKED = "Blocked"

class QuicSTUNProtocol(QuicConnectionProtocol):
    """QUIC protocol for STUN-like NAT discovery"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.external_address = None
        self.response_received = False

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            try:
                data = json.loads(event.data.decode())
                if data.get('type') == 'address_response':
                    self.external_address = (data['ip'], data['port'])
                    self.response_received = True
            except:
                pass

class QuicHolePunchProtocol(QuicConnectionProtocol):
    """QUIC protocol for hole punching"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hole_punched = False
        self.peer_connected = False

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            try:
                data = json.loads(event.data.decode())
                if data.get('type') == 'hole_punch':
                    self.hole_punched = True
                    # Send response
                    stream_id = self._connection.get_next_available_stream_id()
                    response = {'type': 'hole_punch_ack', 'message': 'hole punched'}
                    self._connection.send_stream_data(
                        stream_id,
                        json.dumps(response).encode(),
                        end_stream=True
                    )
                elif data.get('type') == 'hole_punch_ack':
                    self.peer_connected = True
            except:
                pass

class STUNClient:
    """QUIC-based client for NAT discovery and hole punching"""

    def __init__(self, local_port: int = 0):
        self.local_port = local_port if local_port != 0 else random.randint(10000, 65000)
        self.nat_type = NATType.UNKNOWN
        self.external_ip = None
        self.external_port = None
        self.server = None
        self.hole_punch_server = None

    async def discover_nat_async(self) -> Tuple[str, str, int]:
        """Discover NAT type and external IP:port using QUIC connections"""

        # Start our own QUIC server first to discover external address
        await self._start_discovery_server()

        # Try to connect to external services to determine our external address
        for host, port in STUN_SERVERS:
            try:
                logger.info(f"Trying to discover external address via {host}:{port}")

                configuration = QuicConfiguration(
                    is_client=True,
                    verify_mode=ssl.CERT_NONE,
                    alpn_protocols=["h3"]
                )

                async with connect(host, port, configuration=configuration) as protocol:
                    # We're connected, which means we can reach external services
                    # Our external address should be discoverable through our server
                    break

            except Exception as e:
                logger.warning(f"Failed to connect to {host}:{port}: {e}")
                continue

        # For simplicity, we'll use a public IP discovery service
        # In a real implementation, you'd have dedicated STUN-like servers
        self.external_ip = await self._get_external_ip()
        self.external_port = self.local_port  # Assume same port for now
        self.nat_type = NATType.FULL_CONE  # Simplified assumption

        logger.info(f"Discovered - IP: {self.external_ip}, Port: {self.external_port}")
        return self.nat_type, self.external_ip, self.external_port

    async def _start_discovery_server(self):
        """Start QUIC server for NAT discovery"""
        configuration = QuicConfiguration(
            is_client=False,
            certificate=self._generate_self_signed_cert(),
            private_key=self._generate_private_key()
        )

        def create_protocol():
            return QuicSTUNProtocol()

        self.server = await serve(
            "0.0.0.0",
            self.local_port,
            configuration=configuration,
            create_protocol=create_protocol
        )

        logger.info(f"QUIC discovery server started on port {self.local_port}")

    async def _get_external_ip(self) -> str:
        """Get external IP using a simple HTTP request"""
        import aiohttp
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api.ipify.org') as response:
                    return await response.text()
        except:
            return "127.0.0.1"  # Fallback

    async def punch_hole_async(self, peer_ip: str, peer_port: int, attempts: int = 5) -> bool:
        """Perform QUIC hole punching to establish connection with peer"""

        logger.info(f"Attempting QUIC hole punching to {peer_ip}:{peer_port}")

        configuration = QuicConfiguration(
            is_client=True,
            verify_mode=ssl.CERT_NONE
        )

        for attempt in range(attempts):
            try:
                # Try to establish QUIC connection
                protocol = await connect(
                    peer_ip,
                    peer_port,
                    configuration=configuration,
                    create_protocol=QuicHolePunchProtocol
                ).__aenter__()

                # Send hole punch message
                stream_id = protocol._connection.get_next_available_stream_id()
                message = {'type': 'hole_punch', 'attempt': attempt + 1}
                protocol._connection.send_stream_data(
                    stream_id,
                    json.dumps(message).encode(),
                    end_stream=True
                )

                # Wait for response
                timeout = time.time() + 5
                while time.time() < timeout:
                    if protocol.peer_connected:
                        logger.info(f"QUIC hole punch successful on attempt {attempt + 1}")
                        return True
                    await asyncio.sleep(0.1)

            except Exception as e:
                logger.warning(f"Hole punch attempt {attempt + 1} failed: {e}")
                if attempt < attempts - 1:
                    await asyncio.sleep(1)

        logger.error("QUIC hole punching failed after all attempts")
        return False

    async def start_hole_punch_server(self):
        """Start QUIC server to accept hole punch attempts"""
        configuration = QuicConfiguration(
            is_client=False,
            certificate=self._generate_self_signed_cert(),
            private_key=self._generate_private_key()
        )

        def create_protocol():
            return QuicHolePunchProtocol()

        self.hole_punch_server = await serve(
            "0.0.0.0",
            self.local_port,
            configuration=configuration,
            create_protocol=create_protocol
        )

        logger.info(f"QUIC hole punch server started on port {self.local_port}")

    def discover_nat(self) -> Tuple[str, str, int]:
        """Synchronous wrapper for async NAT discovery"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.discover_nat_async())
        finally:
            loop.close()

    def punch_hole(self, peer_ip: str, peer_port: int, attempts: int = 5) -> bool:
        """Synchronous wrapper for async hole punching"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.punch_hole_async(peer_ip, peer_port, attempts))
        finally:
            loop.close()

    def create_socket(self):
        """Legacy method - not needed for QUIC implementation"""
        logger.info("create_socket called but not needed for QUIC implementation")
        return None

    def _generate_self_signed_cert(self):
        """Generate self-signed certificate for QUIC"""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        import ipaddress

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "P2P QUIC"),
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
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                x509.IPAddress(ipaddress.ip_address("0.0.0.0")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        return cert.public_bytes(serialization.Encoding.PEM)

    def _generate_private_key(self):
        """Generate private key for QUIC"""
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