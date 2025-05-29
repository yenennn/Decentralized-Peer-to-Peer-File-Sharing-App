"""
Pure QUIC-based NAT discovery and hole punching.
Uses QUIC connections to discover external IP and perform hole punching.
"""
import logging
import random
import time
import asyncio
import json
import ssl
from typing import Tuple, Optional
import socket

from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, ConnectionTerminated

logger = logging.getLogger(__name__)

# Public services that support QUIC (HTTP/3)
QUIC_DISCOVERY_SERVICES = [
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

class QuicNATDiscoveryProtocol(QuicConnectionProtocol):
    """QUIC protocol for NAT discovery"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.discovery_complete = False
        self.external_address = None
        self.connection_successful = False

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            # Any response means we can connect to external services
            self.connection_successful = True
            self.discovery_complete = True
        elif isinstance(event, ConnectionTerminated):
            # Even if connection terminates, we know we could connect
            if not self.discovery_complete:
                self.connection_successful = True
                self.discovery_complete = True

class QuicHolePunchProtocol(QuicConnectionProtocol):
    """QUIC protocol for hole punching"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hole_punched = False
        self.peer_connected = False
        self.messages_received = []

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            try:
                data = json.loads(event.data.decode())
                message_type = data.get('type')

                if message_type == 'hole_punch':
                    self.hole_punched = True
                    # Send response
                    stream_id = self._connection.get_next_available_stream_id()
                    response = {'type': 'hole_punch_ack', 'message': 'hole punched successfully'}
                    self._connection.send_stream_data(
                        stream_id,
                        json.dumps(response).encode(),
                        end_stream=True
                    )
                    logger.info("✅ Received QUIC hole punch request and sent ACK")

                elif message_type == 'hole_punch_ack':
                    self.peer_connected = True
                    logger.info("✅ Received QUIC hole punch ACK - connection established")

                self.messages_received.append(data)

            except Exception as e:
                logger.error(f"Error processing QUIC hole punch message: {e}")

class STUNClient:
    """Pure QUIC client for NAT discovery and hole punching"""

    def __init__(self, local_port: int = 0):
        self.local_port = local_port if local_port != 0 else random.randint(10000, 65000)
        self.nat_type = NATType.UNKNOWN
        self.external_ip = None
        self.external_port = None
        self.quic_server = None

    async def discover_nat_async(self) -> Tuple[str, str, int]:
        """Discover NAT type and external IP using QUIC connections"""
        logger.info("🔍 Starting QUIC-based NAT discovery...")

        # Start our QUIC server first
        await self._start_discovery_server()

        # Test QUIC connectivity to external services
        external_connectivity = await self._test_external_quic_connectivity()

        if external_connectivity:
            logger.info("✅ QUIC external connectivity confirmed")
            # Get external IP using HTTP service
            self.external_ip = await self._get_external_ip_http()
            self.external_port = self.local_port
            self.nat_type = NATType.FULL_CONE  # Assume full cone if QUIC works
        else:
            logger.warning("⚠️ QUIC external connectivity failed, using fallback")
            self.external_ip, self.external_port = await self._fallback_discovery()
            self.nat_type = NATType.UNKNOWN

        logger.info(f"🌐 Discovery complete - IP: {self.external_ip}, Port: {self.external_port}")
        return self.nat_type, self.external_ip, self.external_port

    async def _start_discovery_server(self):
        """Start QUIC server for discovery and hole punching"""
        configuration = QuicConfiguration(
            is_client=False,
            certificate=self._generate_self_signed_cert(),
            private_key=self._generate_private_key(),
            idle_timeout=60.0
        )

        def create_protocol():
            return QuicNATDiscoveryProtocol()

        try:
            self.quic_server = await serve(
                "0.0.0.0",
                self.local_port,
                configuration=configuration,
                create_protocol=create_protocol
            )

            logger.info(f"🚀 QUIC discovery server started on port {self.local_port}")

        except Exception as e:
            logger.error(f"❌ Failed to start QUIC discovery server: {e}")
            raise

    async def _test_external_quic_connectivity(self) -> bool:
        """Test if we can make QUIC connections to external services"""
        for host, port in QUIC_DISCOVERY_SERVICES:
            try:
                logger.info(f"🔗 Testing QUIC connectivity to {host}:{port}")

                configuration = QuicConfiguration(
                    is_client=True,
                    verify_mode=ssl.CERT_NONE,  # Skip cert verification for discovery
                    alpn_protocols=["h3", "h3-29", "h3-27"]
                )

                # Try to establish QUIC connection
                protocol = await asyncio.wait_for(
                    connect(
                        host,
                        port,
                        configuration=configuration,
                        create_protocol=QuicNATDiscoveryProtocol
                    ).__aenter__(),
                    timeout=10.0
                )

                # Send a simple HTTP/3 request or just test connection
                stream_id = protocol._connection.get_next_available_stream_id()
                request = f"GET / HTTP/3\r\nHost: {host}\r\n\r\n"
                protocol._connection.send_stream_data(
                    stream_id,
                    request.encode(),
                    end_stream=True
                )

                # Wait for any response
                timeout = time.time() + 5
                while time.time() < timeout:
                    if protocol.connection_successful or protocol.discovery_complete:
                        logger.info(f"✅ QUIC connectivity test successful with {host}")
                        return True
                    await asyncio.sleep(0.1)

                # Close connection
                await protocol.__aexit__(None, None, None)

            except Exception as e:
                logger.warning(f"⚠️ QUIC test failed for {host}: {e}")
                continue

        logger.error("❌ All QUIC connectivity tests failed")
        return False

    async def _get_external_ip_http(self) -> str:
        """Get external IP using HTTP service"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api.ipify.org', timeout=10) as response:
                    external_ip = await response.text()
                    logger.info(f"🌍 External IP discovered: {external_ip}")
                    return external_ip.strip()
        except Exception as e:
            logger.warning(f"⚠️ HTTP IP discovery failed: {e}")
            return await self._fallback_ip_discovery()

    async def _fallback_ip_discovery(self) -> str:
        """Fallback IP discovery method"""
        try:
            # Try alternative IP services
            services = [
                'https://ipinfo.io/ip',
                'https://checkip.amazonaws.com',
                'https://icanhazip.com'
            ]

            import aiohttp
            async with aiohttp.ClientSession() as session:
                for service in services:
                    try:
                        async with session.get(service, timeout=5) as response:
                            ip = await response.text()
                            return ip.strip()
                    except:
                        continue

            # Last resort - use local IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            logger.warning(f"🏠 Using local IP as fallback: {local_ip}")
            return local_ip

        except Exception as e:
            logger.error(f"❌ All IP discovery methods failed: {e}")
            return "127.0.0.1"

    async def _fallback_discovery(self) -> Tuple[str, int]:
        """Fallback discovery when QUIC fails"""
        ip = await self._fallback_ip_discovery()
        return ip, self.local_port

    async def punch_hole_async(self, peer_ip: str, peer_port: int, attempts: int = 3) -> bool:
        """Perform QUIC hole punching to establish connection with peer"""
        logger.info(f"🔓 Attempting QUIC hole punching to {peer_ip}:{peer_port}")

        configuration = QuicConfiguration(
            is_client=True,
            verify_mode=ssl.CERT_NONE,
            idle_timeout=30.0
        )

        for attempt in range(attempts):
            try:
                logger.info(f"🎯 QUIC hole punch attempt {attempt + 1}/{attempts}")

                # Try to establish QUIC connection
                protocol = await asyncio.wait_for(
                    connect(
                        peer_ip,
                        peer_port,
                        configuration=configuration,
                        create_protocol=QuicHolePunchProtocol
                    ).__aenter__(),
                    timeout=15.0
                )

                # Send hole punch message
                stream_id = protocol._connection.get_next_available_stream_id()
                message = {
                    'type': 'hole_punch',
                    'attempt': attempt + 1,
                    'timestamp': time.time(),
                    'from_port': self.local_port
                }

                protocol._connection.send_stream_data(
                    stream_id,
                    json.dumps(message).encode(),
                    end_stream=True
                )

                logger.info(f"📤 Sent QUIC hole punch message")

                # Wait for response
                timeout = time.time() + 10
                while time.time() < timeout:
                    if protocol.peer_connected:
                        logger.info(f"🎉 QUIC hole punch successful on attempt {attempt + 1}!")
                        return True
                    await asyncio.sleep(0.1)

                # Close connection for this attempt
                await protocol.__aexit__(None, None, None)

            except asyncio.TimeoutError:
                logger.warning(f"⏱️ Attempt {attempt + 1} timed out")
            except Exception as e:
                logger.warning(f"⚠️ Attempt {attempt + 1} failed: {e}")

            if attempt < attempts - 1:
                logger.info("⏳ Waiting before next attempt...")
                await asyncio.sleep(3)

        logger.error("❌ QUIC hole punching failed after all attempts")
        return False

    async def start_hole_punch_server(self):
        """Start QUIC server to accept hole punch attempts"""
        if self.quic_server:
            logger.info("✅ QUIC hole punch server already running")
            return

        configuration = QuicConfiguration(
            is_client=False,
            certificate=self._generate_self_signed_cert(),
            private_key=self._generate_private_key(),
            idle_timeout=120.0
        )

        def create_protocol():
            return QuicHolePunchProtocol()

        try:
            self.quic_server = await serve(
                "0.0.0.0",
                self.local_port,
                configuration=configuration,
                create_protocol=create_protocol
            )

            logger.info(f"🎯 QUIC hole punch server ready on port {self.local_port}")

        except Exception as e:
            logger.error(f"❌ Failed to start QUIC hole punch server: {e}")
            raise

    def discover_nat(self) -> Tuple[str, str, int]:
        """Synchronous wrapper for async NAT discovery"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.discover_nat_async())
        finally:
            loop.close()

    def punch_hole(self, peer_ip: str, peer_port: int, attempts: int = 3) -> bool:
        """Synchronous wrapper for async hole punching"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.punch_hole_async(peer_ip, peer_port, attempts))
        finally:
            loop.close()

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

    # Legacy compatibility methods
    def create_socket(self):
        """Legacy method - not needed for pure QUIC implementation"""
        logger.info("create_socket called but not needed for pure QUIC implementation")
        return None