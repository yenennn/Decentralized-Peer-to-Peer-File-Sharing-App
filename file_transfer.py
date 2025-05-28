"""
UDP file transfer implementation with sliding window protocol.
Combines the sender and receiver logic from the provided code.
"""

import json
import logging
import math
import os
import threading
import time
import uuid
from pathlib import Path
import socket
from typing import Dict, Tuple, Set, List, Optional, Callable, Any
from collections import defaultdict

logger = logging.getLogger(__name__)

# Message type constants
CONN_REQ = "CONN_REQ"
REQ_TO_SEND = "REQ_TO_SEND"
FILE_INIT = "file_init"
FILE_INIT_ACK = "file_init_ack"
FILE_CHUNK = "file_chunk"
CHUNK_ACK = "chunk_ack"
FILE_END = "file_end"
FILE_END_ACK = "file_end_ack"
WINDOW_ACK = "window_ack"
NACK = "NACK"
REQ_ACK = "REQ_ACK"
ACK = "ACK"
ACK_ALL = "ACK_ALL"


class UDPSender:
    """Implements the sender logic for UDP file transfer"""

    def __init__(self, socket, dest_addr, fragment_size=1024, window_size=10, timeout=4):
        self.socket = socket
        self.dest_addr = dest_addr
        self.fragment_size = fragment_size
        self.window_size = window_size
        self.timeout = timeout

        self.sender_data_buffer = []
        self.sender_index_buffer = []
        self.time_out_tries = 0
        self.seq_num = 0
        self.max_time_out_tries = 3
        self.cont_iter_last = False
        self.cont_iter_timeout = False

        # Error simulation (disabled by default)
        self.sim_packet_loss = False
        self.packets_lost = []

    def send_file(self, file_path, encrypt_func=None, progress_callback=None):
        """Send a file using sliding window protocol"""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False

        file_size = os.path.getsize(file_path)
        logger.info(f"Sending file: {file_path}, size: {file_size} bytes")

        # Request permission to send
        self.socket.sendto(REQ_TO_SEND.encode(), self.dest_addr)
        response = self._get_response()

        if response != ACK:
            logger.error("Request to send denied")
            return False

        # Send window size for verification
        self.socket.sendto(str(self.window_size).encode(), self.dest_addr)
        response = self._get_response()

        if response == NACK:
            logger.error("Window size mismatch")
            return False

        # Initialize transfer
        self.seq_num = 0
        self.sender_data_buffer = []
        self.sender_index_buffer = []
        self.time_out_tries = 0
        self.cont_iter_last = False
        self.cont_iter_timeout = False

        # Calculate total packets
        total_packets = math.ceil(file_size / self.fragment_size)
        packet_num = -1  # Starting index

        # Start transfer
        with open(file_path, "rb") as f:
            data = f.read(self.fragment_size)

            while data or self.cont_iter_last or self.cont_iter_timeout:
                if self.cont_iter_last:
                    # Process final window
                    if self._process_final_window_packet(progress_callback, total_packets):
                        break
                else:
                    if self.seq_num < self.window_size:
                        # Check if we should simulate packet loss
                        if self.sim_packet_loss and packet_num + 1 in self.packets_lost:
                            packet_num += 1
                            self.seq_num += 1

                            # Add to buffer but don't send
                            if encrypt_func:
                                encrypted_data = encrypt_func(data)
                                self.sender_data_buffer.append(encrypted_data)
                            else:
                                self.sender_data_buffer.append(data)

                            self.sender_index_buffer.append(packet_num)
                            data = f.read(self.fragment_size)
                            time.sleep(0.02)
                        else:
                            # Send the packet
                            if encrypt_func:
                                encrypted_data = encrypt_func(data)
                                self.socket.sendto(encrypted_data, self.dest_addr)
                            else:
                                self.socket.sendto(data, self.dest_addr)

                            packet_num += 1
                            self.seq_num += 1

                            # Add to buffer
                            if encrypt_func:
                                self.sender_data_buffer.append(encrypted_data)
                            else:
                                self.sender_data_buffer.append(data)

                            self.sender_index_buffer.append(packet_num)

                            # Get next chunk
                            data = f.read(self.fragment_size)
                            time.sleep(0.02)

                            # Send packet number
                            if packet_num == total_packets - 1:
                                msg = "F" + str(packet_num)  # Final packet
                                self.socket.sendto(msg.encode(), self.dest_addr)
                                self.cont_iter_last = True
                            else:
                                msg = "N" + str(packet_num)  # Not final packet
                                self.socket.sendto(msg.encode(), self.dest_addr)

                            # Update progress if callback provided
                            if progress_callback:
                                progress_callback(packet_num + 1, total_packets)
                    else:
                        # Process window when it's full
                        if self._process_final_window_packet(progress_callback, total_packets):
                            break

        logger.info("File transfer completed successfully")
        return True

    def _get_response(self):
        """Get response from receiver"""
        try:
            rec_msg = self.socket.recvfrom(self.fragment_size)
            return rec_msg[0].decode()
        except socket.timeout:
            return "TIMEOUT"

    def _process_final_window_packet(self, progress_callback, total_packets):
        """Process the end of a window and handle acknowledgments"""
        logger.debug(f"Sent packet indices: {self.sender_index_buffer}")
        logger.debug("Waiting for acknowledgment...")

        server_response = self._get_response()

        if server_response == ACK_ALL:
            # Reset timeout tries
            if self.time_out_tries != 0:
                self.time_out_tries = 0

            # Reset sequence number and buffers
            self.seq_num = 0
            self.sender_data_buffer = []
            self.sender_index_buffer = []

            # Reset extra iterations
            self.cont_iter_last = False
            if self.cont_iter_timeout:
                self.cont_iter_timeout = False

            # Update progress if callback provided
            if progress_callback:
                packets_sent = min(self.window_size * (len(self.sender_index_buffer) // self.window_size + 1), total_packets)
                progress_callback(packets_sent, total_packets)

        elif server_response.startswith(NACK):
            # Extract packet number that needs to be resent
            index_of_packet_not_received = int(server_response[4:])
            logger.info(f"Packet #{index_of_packet_not_received} was lost. Resending...")

            # Convert to sequence number within window
            seq_of_packet_not_received = index_of_packet_not_received % self.window_size

            # Resend the lost packet
            if 0 <= seq_of_packet_not_received < len(self.sender_data_buffer):
                self.socket.sendto(self.sender_data_buffer[seq_of_packet_not_received], self.dest_addr)
            else:
                logger.warning(f"Invalid sequence number: {seq_of_packet_not_received}")

        elif server_response == "TIMEOUT":
            self.cont_iter_timeout = True

            # Retry until max tries reached
            if self.time_out_tries < self.max_time_out_tries:
                self.time_out_tries += 1
                logger.warning(f"Request timed-out. Requesting acknowledgement again... (Tries left: {self.max_time_out_tries - self.time_out_tries}/{self.max_time_out_tries})")
                self.socket.sendto(REQ_ACK.encode(), self.dest_addr)
            else:
                if self.cont_iter_last:
                    self.cont_iter_last = False
                self.cont_iter_timeout = False
                logger.error("Server is not responding.")
                return True

        return False


class UDPReceiver:
    """Implements the receiver logic for UDP file transfer"""

    def __init__(self, socket, save_dir, fragment_size=1024, window_size=10, timeout=4):
        self.socket = socket
        self.save_dir = Path(save_dir)
        self.fragment_size = fragment_size
        self.window_size = window_size
        self.timeout = timeout

        self.receiving = False
        self.receiver_buffer = {}
        self.expected_packets = 0
        self.received_packets = 0
        self.last_packet_num = -1
        self.current_window = 0

        # Ensure save directory exists
        self.save_dir.mkdir(parents=True, exist_ok=True)

    def receive_file(self, sender_addr, file_name, decrypt_func=None, progress_callback=None):
        """Receive a file using sliding window protocol"""
        logger.info(f"Starting to receive file: {file_name} from {sender_addr}")

        self.receiving = True
        self.receiver_buffer = {}
        self.received_packets = 0
        self.last_packet_num = -1
        self.current_window = 0

        # Create file
        file_path = self.save_dir / file_name
        file_handle = open(file_path, "wb")

        try:
            # Acknowledge connection request
            self.socket.sendto(ACK.encode(), sender_addr)

            # Wait for request to send
            msg, addr = self.socket.recvfrom(self.fragment_size)
            if msg.decode() != REQ_TO_SEND:
                logger.error("Expected REQ_TO_SEND message")
                file_handle.close()
                return False

            # Acknowledge request to send
            self.socket.sendto(ACK.encode(), sender_addr)

            # Get window size
            msg, addr = self.socket.recvfrom(self.fragment_size)
            client_window_size = int(msg.decode())

            if client_window_size != self.window_size:
                logger.error(f"Window size mismatch: client={client_window_size}, server={self.window_size}")
                self.socket.sendto(NACK.encode(), sender_addr)
                file_handle.close()
                return False

            # Main receive loop
            while self.receiving:
                try:
                    # Receive data
                    chunk, addr = self.socket.recvfrom(self.fragment_size + 100)  # Extra space for headers

                    # Check if it's a packet number message
                    if len(chunk) < self.fragment_size and (chunk.startswith(b"N") or chunk.startswith(b"F")):
                        msg = chunk.decode()
                        packet_type = msg[0]
                        packet_num = int(msg[1:])

                        # Check if this is the final packet
                        if packet_type == "F":
                            self.expected_packets = packet_num + 1
                            logger.info(f"Final packet number received: {packet_num}")

                        # Process current window if complete
                        if self._is_window_complete():
                            self._process_window(file_handle, decrypt_func)

                            # Send ACK for the entire window
                            self.socket.sendto(ACK_ALL.encode(), sender_addr)

                            # Update progress
                            if progress_callback:
                                progress_callback(self.received_packets, self.expected_packets)

                            # Check if transfer is complete
                            if self.expected_packets > 0 and self.received_packets >= self.expected_packets:
                                logger.info("File transfer completed")
                                break

                    # Check if it's a REQ_ACK message
                    elif len(chunk) < 20 and chunk.decode() == REQ_ACK:
                        if self._is_window_complete():
                            self.socket.sendto(ACK_ALL.encode(), sender_addr)
                        else:
                            # Find missing packets
                            missing = []
                            start_idx = self.current_window * self.window_size
                            end_idx = min(start_idx + self.window_size, self.expected_packets if self.expected_packets > 0 else float('inf'))

                            for i in range(start_idx, end_idx):
                                if i not in self.receiver_buffer:
                                    missing.append(i)

                            if missing:
                                # Request retransmission of first missing packet
                                nack_msg = f"{NACK}{missing[0]}"
                                self.socket.sendto(nack_msg.encode(), sender_addr)

                    # Otherwise it's a data chunk
                    else:
                        # Add to buffer and send individual ACK
                        packet_num = self.last_packet_num + 1

                        # Decrypt if needed
                        if decrypt_func:
                            try:
                                decrypted_data = decrypt_func(chunk)
                                self.receiver_buffer[packet_num] = decrypted_data
                            except Exception as e:
                                logger.error(f"Decryption failed: {e}")
                                continue
                        else:
                            self.receiver_buffer[packet_num] = chunk

                        self.last_packet_num = packet_num

                except socket.timeout:
                    logger.warning("Socket timeout while receiving")

                    # If we're expecting more packets but didn't receive any
                    if self.expected_packets > 0 and self.received_packets < self.expected_packets:
                        # Send NACK for the next expected packet
                        next_expected = self.received_packets
                        nack_msg = f"{NACK}{next_expected}"
                        self.socket.sendto(nack_msg.encode(), sender_addr)
                    else:
                        # Just wait for more data
                        continue

            # Send final acknowledgment
            self.socket.sendto(FILE_END_ACK.encode(), sender_addr)
            logger.info(f"File received successfully: {file_path}")
            return True

        except Exception as e:
            logger.error(f"Error receiving file: {e}")
            return False
        finally:
            file_handle.close()

    def _is_window_complete(self):
        """Check if the current window is complete"""
        start_idx = self.current_window * self.window_size
        end_idx = start_idx + self.window_size

        # If we know the total, don't check beyond it
        if self.expected_packets > 0:
            end_idx = min(end_idx, self.expected_packets)

        # Check if all packets in the window are received
        for i in range(start_idx, end_idx):
            if i not in self.receiver_buffer:
                return False

        return True

    def _process_window(self, file_handle, decrypt_func):
        """Process a complete window and write to file"""
        start_idx = self.current_window * self.window_size
        end_idx = start_idx + self.window_size

        # If we know the total, don't process beyond it
        if self.expected_packets > 0:
            end_idx = min(end_idx, self.expected_packets)

        # Write all packets in the window to file
        for i in range(start_idx, end_idx):
            if i in self.receiver_buffer:
                data = self.receiver_buffer[i]
                file_handle.write(data)
                file_handle.flush()

                # Remove from buffer
                del self.receiver_buffer[i]
                self.received_packets += 1

        # Move to next window
        self.current_window += 1


class FileTransfer:
    """Main file transfer class that integrates with the P2P system"""

    def __init__(self, sock, crypto_manager):
        self.socket = sock
        self.crypto = crypto_manager
        self.lock = threading.Lock()
        self.transfers = {}
        self.save_dir = Path.cwd()
        self.progress_callback = None

        # Default settings
        self.fragment_size = 32 * 1024  # 32 KiB
        self.window_size = 10
        self.timeout = 4

    def receive_file(self, save_dir: str, progress_callback: Callable[[str, int, int], None]):
        """Configure where incoming files are stored and how to report progress."""
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)
        self.progress_callback = progress_callback

    def send_file(self, file_path: str, peer_id: str, peer_addr: Tuple[str, int],
                  progress_callback: Callable[[str, int, int], None]) -> str:
        """
        Send a file to a peer.

        Args:
            file_path: Path to the file to send
            peer_id: Unique identifier for the peer
            peer_addr: Tuple of (ip, port) for the peer
            progress_callback: Callback function for progress updates

        Returns:
            Transfer ID if successful, None otherwise
        """
        file_path = str(file_path)
        if not os.path.isfile(file_path):
            raise FileNotFoundError(file_path)

        transfer_id = str(uuid.uuid4())
        file_size = os.path.getsize(file_path)

        with self.lock:
            self.transfers[transfer_id] = {
                "direction": "out",
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_size": file_size,
                "status": "pending",
                "peer_addr": peer_addr,
                "peer_id": peer_id,
                "start_time": time.time(),
                "progress_cb": progress_callback
            }

        # Start upload worker thread
        t = threading.Thread(target=self._upload_worker, args=(transfer_id,), daemon=True)
        t.start()
        return transfer_id

    def _upload_worker(self, transfer_id: str):
        """Worker thread for uploading files"""
        with self.lock:
            tf = self.transfers[transfer_id]

        try:
            # Initialize sender
            sender = UDPSender(
                self.socket,
                tf["peer_addr"],
                fragment_size=self.fragment_size,
                window_size=self.window_size,
                timeout=self.timeout
            )

            # Define encrypt function
            def encrypt_func(data):
                return self._encrypt(tf["peer_id"], data)

            # Define progress callback
            def on_progress(sent, total):
                with self.lock:
                    if tf["progress_cb"]:
                        tf["progress_cb"](transfer_id, sent, total)

            # Send the file
            success = sender.send_file(tf["file_path"], encrypt_func, on_progress)

            with self.lock:
                if success:
                    tf["status"] = "completed"
                    tf["end_time"] = time.time()
                    duration = tf["end_time"] - tf["start_time"]
                    speed = tf["file_size"] / duration / 1024 if duration > 0 else 0
                    logger.info(f"Upload of {tf['file_name']} completed - {speed:.2f} KB/s")
                else:
                    tf["status"] = "failed"

        except Exception as e:
            logger.error(f"Error in upload worker: {e}")
            with self.lock:
                tf["status"] = "failed"

    def handle_message(self, data: bytes, addr: Tuple[str, int], peer_id: str):
        """
        Handle incoming file transfer messages.

        Args:
            data: Raw message data
            addr: Sender's address (ip, port)
            peer_id: Unique identifier for the peer
        """
        try:
            # Try to decode as JSON
            msg = json.loads(data.decode())
            msg_type = msg.get("type")

            if msg_type == CONN_REQ:
                # Initial connection request
                self._send_json({"type": ACK}, addr)

            elif msg_type == REQ_TO_SEND:
                # Request to start file transfer
                transfer_id = str(uuid.uuid4())

                with self.lock:
                    self.transfers[transfer_id] = {
                        "direction": "in",
                        "peer_id": peer_id,
                        "peer_addr": addr,
                        "status": "receiving",
                        "start_time": time.time()
                    }

                # Start receive worker thread
                t = threading.Thread(
                    target=self._receive_worker,
                    args=(transfer_id, msg.get("file_name", f"file_{transfer_id}.dat")),
                    daemon=True
                )
                t.start()

                # Acknowledge the request
                self._send_json({"type": ACK}, addr)

            elif msg_type == FILE_END:
                # File transfer completed
                self._send_json({"type": FILE_END_ACK}, addr)

            # Other message types are handled by the worker threads

        except json.JSONDecodeError:
            logger.debug("Not a JSON message, ignoring")

        except Exception as e:
            logger.error(f"Error handling message: {e}")

    def _receive_worker(self, transfer_id: str, file_name: str):
        """Worker thread for receiving files"""
        with self.lock:
            tf = self.transfers[transfer_id]

        try:
            # Initialize receiver
            receiver = UDPReceiver(
                self.socket,
                self.save_dir,
                fragment_size=self.fragment_size,
                window_size=self.window_size,
                timeout=self.timeout
            )

            # Define decrypt function
            def decrypt_func(data):
                return self._decrypt(tf["peer_id"], data)

            # Define progress callback
            def on_progress(received, total):
                with self.lock:
                    if self.progress_callback:
                        self.progress_callback(transfer_id, received, total)

            # Receive the file
            success = receiver.receive_file(tf["peer_addr"], file_name, decrypt_func, on_progress)

            with self.lock:
                if success:
                    tf["status"] = "completed"
                    tf["end_time"] = time.time()
                    tf["file_name"] = file_name
                    tf["file_path"] = str(self.save_dir / file_name)
                    duration = tf["end_time"] - tf["start_time"]
                    logger.info(f"Download of {file_name} completed")
                else:
                    tf["status"] = "failed"

        except Exception as e:
            logger.error(f"Error in receive worker: {e}")
            with self.lock:
                tf["status"] = "failed"

    def _send_json(self, obj: Dict[str, Any], addr: Tuple[str, int]):
        """Send a JSON message to a peer"""
        try:
            self.socket.sendto(json.dumps(obj).encode(), addr)
        except Exception as e:
            logger.error(f"Error sending JSON: {e}")

    def _encrypt(self, peer_id: str, plaintext: bytes) -> bytes:
        """Encrypt data using the crypto manager"""
        if hasattr(self.crypto, "encrypt_data"):
            return self.crypto.encrypt_data(peer_id, plaintext)
        return plaintext

    def _decrypt(self, peer_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data using the crypto manager"""
        if hasattr(self.crypto, "decrypt_data"):
            return self.crypto.decrypt_data(peer_id, ciphertext)
        return ciphertext

    def get_transfer_status(self, transfer_id: str) -> Dict:
        """
        Get the status of a file transfer.

        Args:
            transfer_id: Unique transfer ID

        Returns:
            Transfer status information
        """
        with self.lock:
            if transfer_id not in self.transfers:
                return {'status': 'unknown'}

            tf = self.transfers[transfer_id]

            result = {
                'transfer_id': transfer_id,
                'status': tf.get('status', 'unknown'),
                'file_name': tf.get('file_name', 'unknown'),
                'file_size': tf.get('file_size', 0),
                'progress': 0,
                'speed': 0
            }

            # Calculate speed if completed
            if tf.get('status') == 'completed' and 'end_time' in tf and 'start_time' in tf:
                duration = tf['end_time'] - tf['start_time']
                if duration > 0 and 'file_size' in tf:
                    result['speed'] = tf['file_size'] / duration / 1024  # KB/s

            return result

    def handle_binary_data(self, data: bytes, addr: Tuple[str, int], peer_id: str):
        """Handle incoming binary data"""
        logger.debug(f"Received binary data from {addr}, {len(data)} bytes")
        # Binary data is handled by the worker threads directly