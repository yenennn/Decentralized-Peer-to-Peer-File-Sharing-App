"""
STUN client for NAT traversal.
Uses a simplified implementation without external dependencies.
"""
import socket
import logging
import random
import time
import struct
import threading
from typing import Tuple, Optional, Dict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# List of public STUN servers
STUN_SERVERS = [
    ('stun.l.google.com', 19302),
    ('stun1.l.google.com', 19302),
    ('stun2.l.google.com', 19302),
    ('stun.ekiga.net', 3478),
    ('stun.ideasip.com', 3478),
    ('stun.schlund.de', 3478),
    ('stun.stunprotocol.org', 3478),
    ('stun.voiparound.com', 3478),
    ('stun.voipbuster.com', 3478),
    ('stun.voipstunt.com', 3478),
    ('stun.voxgratia.org', 3478)
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


class STUNClient:
    """Client for STUN server communication and NAT traversal"""

    def __init__(self, local_port: int = 0):
        """
        Initialize the STUN client.

        Args:
            local_port: Local UDP port to bind to. If 0, a random port will be assigned.
        """
        self.local_port = local_port if local_port != 0 else random.randint(10000, 65000)
        self.nat_type = NATType.UNKNOWN
        self.external_ip = None
        self.external_port = None
        self.socket = None

    def discover_nat(self) -> Tuple[str, str, int]:
        """
        Discover NAT type and external IP:port using STUN.

        Returns:
            Tuple of (NAT type, external IP, external port)
        """
        if not self.socket:
            self.create_socket()

        # Try multiple STUN servers in case some are down
        for stun_server, stun_port in STUN_SERVERS:
            try:
                logger.info(f"Trying STUN server {stun_server}:{stun_port}")

                # Create a simple STUN binding request
                transaction_id = random.randbytes(12)

                # STUN Message Type: Binding Request (0x0001)
                # Message Length: 0 (no attributes)
                # Magic Cookie: 0x2112A442
                # Transaction ID: 12 random bytes
                stun_request = struct.pack(
                    '>HHII',
                    0x0001,  # Binding Request
                    0x0000,  # Message Length
                    0x2112A442,  # Magic Cookie
                    int.from_bytes(transaction_id[:4], byteorder='big')
                ) + transaction_id[4:]

                # Send the STUN request
                self.socket.sendto(stun_request, (stun_server, stun_port))

                # Wait for response
                self.socket.settimeout(5)
                try:
                    data, addr = self.socket.recvfrom(1024)

                    # Parse the STUN response
                    if len(data) < 20:
                        logger.warning(f"Invalid STUN response from {stun_server}")
                        continue

                    # Check if it's a STUN Binding Response (0x0101)
                    msg_type = struct.unpack('>H', data[0:2])[0]
                    if msg_type != 0x0101:
                        logger.warning(f"Not a STUN Binding Response: {msg_type:04x}")
                        continue

                    # Parse the response to find the XOR-MAPPED-ADDRESS attribute (0x0020)
                    # Skip the 20-byte header
                    pos = 20
                    while pos + 4 <= len(data):
                        attr_type = struct.unpack('>H', data[pos:pos + 2])[0]
                        attr_len = struct.unpack('>H', data[pos + 2:pos + 4])[0]

                        if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                            if attr_len >= 8:  # IPv4 address
                                # Skip the first 4 bytes (family and port)
                                xor_port = struct.unpack('>H', data[pos + 6:pos + 8])[0] ^ (0x2112A442 >> 16)
                                xor_ip = struct.unpack('>I', data[pos + 8:pos + 12])[0] ^ 0x2112A442
                                ip = socket.inet_ntoa(struct.pack('>I', xor_ip))

                                self.external_ip = ip
                                self.external_port = xor_port
                                self.nat_type = NATType.FULL_CONE  # Simplified - assume Full Cone

                                logger.info(f"NAT Type: {self.nat_type}")
                                logger.info(f"External IP: {self.external_ip}")
                                logger.info(f"External Port: {self.external_port}")

                                return self.nat_type, self.external_ip, self.external_port

                        pos += 4 + attr_len  # Move to the next attribute
                        # Align to 4-byte boundary
                        if attr_len % 4 != 0:
                            pos += 4 - (attr_len % 4)

                except socket.timeout:
                    logger.warning(f"Timeout waiting for STUN response from {stun_server}")
                    continue

            except Exception as e:
                logger.error(f"Error with STUN server {stun_server}: {e}")
                continue

        logger.error("Failed to discover external IP and port using any STUN server")
        return NATType.UNKNOWN, None, None

    def create_socket(self) -> socket.socket:
        """
        Create and bind a UDP socket for P2P communication.

        Returns:
            Bound UDP socket
        """
        if self.socket:
            return self.socket

        try:
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind to the specified local port
            self.socket.bind(('0.0.0.0', self.local_port))

            # Get the actual port (in case we used 0)
            self.local_port = self.socket.getsockname()[1]
            logger.info(f"Socket bound to local port {self.local_port}")

            return self.socket

        except Exception as e:
            logger.error(f"Error creating socket: {e}")
            raise

    def punch_hole(self, peer_ip: str, peer_port: int, attempts: int = 5) -> bool:
        """
        Perform UDP hole punching to establish a direct connection with a peer.

        Args:
            peer_ip: External IP of the peer
            peer_port: External port of the peer
            attempts: Number of hole punching attempts

        Returns:
            True if hole punching was attempted, False otherwise
        """
        if not self.socket:
            self.create_socket()

        logger.info(f"Attempting to punch hole to {peer_ip}:{peer_port}")

        # Send multiple packets to punch a hole in the NAT
        for i in range(attempts):
            try:
                # Send a hole punching message
                self.socket.sendto(b"HOLE_PUNCHING", (peer_ip, peer_port))
                logger.info(f"Sent hole punching packet {i + 1}/{attempts}")
                time.sleep(0.5)  # Short delay between attempts
            except Exception as e:
                logger.error(f"Error during hole punching: {e}")
                return False

        logger.info(f"Hole punching to {peer_ip}:{peer_port} completed")
        return True
