"""
Reliable file transfer over UDP using KCP.
Replaces custom sliding-window logic with the KCP protocol for reliable, ordered delivery.
"""
import os
import threading
import time
import uuid
import json
import logging
from pathlib import Path
from typing import Callable, Dict, Tuple

from kcp import KCP

# Control message types
FILE_INIT     = "file_init"
FILE_INIT_ACK = "file_init_ack"
FILE_END      = "file_end"
FILE_END_ACK  = "file_end_ack"

logger = logging.getLogger(__name__)

class FileTransfer:
    """FileTransfer using KCP for reliability."""
    DEFAULT_CHUNK_SIZE = 32 * 1024  # 32 KiB

    def __init__(self, sock, crypto_manager):
        self.socket = sock
        self.crypto = crypto_manager
        self.save_dir = Path.cwd()
        self.progress_callback: Callable[[str, int, int], None] = lambda *args: None

        # Active send/receive sessions by transfer_id
        # Each holds: peer_addr, peer_id, file_path/file_handle, file_size, init_acked, end_acked, kcp instance
        self._send_sessions: Dict[str, Dict] = {}
        self._recv_sessions: Dict[str, Dict] = {}

    def receive_file(self, save_dir: str, progress_callback: Callable[[str, int, int], None]):
        """Configure where to save incoming files and set progress callback."""
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)
        self.progress_callback = progress_callback

    def send_file(self,
                  file_path: str,
                  peer_id: str,
                  peer_addr: Tuple[str, int],
                  progress_callback: Callable[[str, int, int], None]) -> str:
        """Start a file send operation reliably over KCP."""
        if not os.path.isfile(file_path):
            raise FileNotFoundError(file_path)

        transfer_id = str(uuid.uuid4())
        file_size = os.path.getsize(file_path)

        # 1) Send FILE_INIT control message over UDP
        init_msg = {
            'type': FILE_INIT,
            'transfer_id': transfer_id,
            'file_name': os.path.basename(file_path),
            'file_size': file_size,
            'chunk_size': self.DEFAULT_CHUNK_SIZE
        }
        self.socket.sendto(json.dumps(init_msg).encode(), peer_addr)

        # 2) Store session
        self._send_sessions[transfer_id] = {
            'peer_addr': peer_addr,
            'peer_id': peer_id,
            'file_path': file_path,
            'file_size': file_size,
            'progress_cb': progress_callback,
            'init_acked': False,
            'end_acked': False,
            'kcp': None
        }

        # 3) Start KCP upload thread
        t = threading.Thread(target=self._kcp_upload_worker,
                             args=(transfer_id,),
                             daemon=True)
        t.start()

        return transfer_id

    def _kcp_upload_worker(self, transfer_id: str):
        sess = self._send_sessions[transfer_id]
        peer_addr = sess['peer_addr']
        peer_id   = sess['peer_id']

        # Wait for FILE_INIT_ACK from receiver
        while not sess['init_acked']:
            time.sleep(0.1)

        # 4) Create and configure KCP for this transfer
        conv = uuid.UUID(transfer_id).int & 0x7FFFFFFF

        def _upload_output(_kcp, data: bytes):
            self.socket.sendto(data, peer_addr)

        kcp = KCP(conv, _upload_output)
        sess['kcp'] = kcp

        # 5) Stream encrypted file data over KCP
        total = sess['file_size']
        sent = 0
        with open(sess['file_path'], 'rb') as f:
            while True:
                chunk = f.read(self.DEFAULT_CHUNK_SIZE)
                if not chunk:
                    break
                data = self.crypto.encrypt_data(peer_id, chunk)
                kcp.send(data)
                kcp.flush()
                sent += len(chunk)
                sess['progress_cb'](transfer_id, sent, total)
                time.sleep(0.01)

        # 6) Allow final KCP packets to flush
        for _ in range(20):
            kcp.flush()
            time.sleep(0.05)

        # 7) Signal end of transfer
        end_msg = {'type': FILE_END, 'transfer_id': transfer_id}
        self.socket.sendto(json.dumps(end_msg).encode(), peer_addr)

        # 8) Wait for FILE_END_ACK
        while not sess['end_acked']:
            time.sleep(0.1)

        logger.info(f"Transfer {transfer_id} completed reliably over KCP.")

    def handle_message(self, data: bytes, addr: Tuple[str, int], peer_id: str):
        """Handle incoming JSON control messages over UDP."""
        try:
            msg = json.loads(data.decode())
        except Exception:
            return

        mtype = msg.get('type')
        tid   = msg.get('transfer_id')

        if mtype == FILE_INIT:
            self._handle_file_init(msg, addr, peer_id)
        elif mtype == FILE_INIT_ACK:
            if tid in self._send_sessions:
                self._send_sessions[tid]['init_acked'] = True
        elif mtype == FILE_END:
            # Receiver signals end; send ACK
            ack = {'type': FILE_END_ACK, 'transfer_id': tid}
            self.socket.sendto(json.dumps(ack).encode(), addr)
        elif mtype == FILE_END_ACK:
            if tid in self._send_sessions:
                self._send_sessions[tid]['end_acked'] = True

    def _handle_file_init(self, msg: Dict, addr: Tuple[str, int], peer_id: str):
        """Initialize receive side and reply with FILE_INIT_ACK."""
        transfer_id = msg['transfer_id']
        file_name   = msg['file_name']
        file_size   = msg['file_size']

        # Send acknowledgment
        ack = {'type': FILE_INIT_ACK, 'transfer_id': transfer_id}
        self.socket.sendto(json.dumps(ack).encode(), addr)

        # Prepare file for writing
        dest = self.save_dir / file_name
        fh = dest.open('wb')

        # Create KCP for this transfer
        conv = uuid.UUID(transfer_id).int & 0x7FFFFFFF

        def _recv_output(_kcp, data: bytes):
            self.socket.sendto(data, addr)

        kcp = KCP(conv, _recv_output)

        # Store session
        self._recv_sessions[transfer_id] = {
            'peer_addr': addr,
            'peer_id': peer_id,
            'file_handle': fh,
            'file_size': file_size,
            'received': 0,
            'kcp': kcp
        }

        # Start KCP receive loop
        t = threading.Thread(target=self._kcp_receive_worker,
                             args=(transfer_id,), daemon=True)
        t.start()

    def _kcp_receive_worker(self, transfer_id: str):
        sess = self._recv_sessions[transfer_id]
        kcp = sess['kcp']
        total = sess['file_size']
        received = 0
        peer_id = sess['peer_id']

        while received < total:
            kcp.update(int(time.time() * 1000))
            packet = kcp.recv()
            if packet:
                data = self.crypto.decrypt_data(peer_id, packet)
                sess['file_handle'].write(data)
                received += len(data)
                self.progress_callback(transfer_id, received, total)
            time.sleep(0.01)

        sess['file_handle'].close()
        logger.info(f"Received file {transfer_id} complete.")

    def handle_binary_data(self, data: bytes, addr: Tuple[str, int], peer_id: str):
        """Feed incoming UDP/KCP packets into the right KCP session."""
        # Try send and recv sessions
        for sess in list(self._send_sessions.values()) + list(self._recv_sessions.values()):
            if sess.get('peer_addr') == addr and sess.get('kcp'):
                sess['kcp'].input(data)
                return
        # No matching session; drop silently