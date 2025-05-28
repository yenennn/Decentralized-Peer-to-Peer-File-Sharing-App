"""
Reliable UDP file transfer using Scapy-style packets with errorless retransmission.
This is a drop-in replacement for your previous file_transfer.py.
"""

import os
import math
import threading
import time
import uuid
from typing import Any, Callable, Dict, Optional, Tuple, Set, List

from scapy.all import IP, UDP, Raw, send, sniff, conf

import logging
logger = logging.getLogger(__name__)

CHUNK_SIZE = 32 * 1024
TIMEOUT = 1.0
MAX_RETRIES = 12

PKT_DATA = 0xA0
PKT_ACK = 0xA1
PKT_EOF = 0xA2

def _make_data_packet(transfer_id: str, seq: int, data: bytes) -> bytes:
    # [PKT_DATA][UUID16][SEQ4][DATA]
    t_id = uuid.UUID(transfer_id).bytes
    return bytes([PKT_DATA]) + t_id + seq.to_bytes(4, "big") + data

def _make_ack_packet(transfer_id: str, seq: int) -> bytes:
    t_id = uuid.UUID(transfer_id).bytes
    return bytes([PKT_ACK]) + t_id + seq.to_bytes(4, "big")

def _make_eof_packet(transfer_id: str, total_chunks: int) -> bytes:
    t_id = uuid.UUID(transfer_id).bytes
    return bytes([PKT_EOF]) + t_id + total_chunks.to_bytes(4, "big")

def _parse_packet(pktbytes: bytes):
    """Returns: (pkt_type, transfer_id, seq, data)"""
    pkt_type = pktbytes[0]
    t_id = str(uuid.UUID(bytes=pktbytes[1:17]))
    seq = int.from_bytes(pktbytes[17:21], "big") if pkt_type in (PKT_DATA, PKT_ACK, PKT_EOF) else None
    data = pktbytes[21:] if pkt_type == PKT_DATA else None
    return pkt_type, t_id, seq, data

class ScapyFileTransfer:
    def __init__(self, sock, crypto_manager):
        self.socket = sock
        self.crypto = crypto_manager
        self.lock = threading.Lock()
        self.transfers: Dict[str, Dict[str, Any]] = {}
        self.save_dir = os.getcwd()
        self.progress_callback: Optional[Callable[[str, int, int], None]] = None

    def receive_file(self, save_dir: str, progress_callback: Callable[[str, int, int], None]):
        self.save_dir = save_dir
        self.progress_callback = progress_callback

    def send_file(self, file_path: str, peer_id: str, peer_addr: Tuple[str, int],
                  progress_callback: Callable[[str, int, int], None]) -> str:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(file_path)
        transfer_id = str(uuid.uuid4())
        file_size = os.path.getsize(file_path)
        total_chunks = math.ceil(file_size / CHUNK_SIZE)
        with self.lock:
            self.transfers[transfer_id] = {
                "direction": "out",
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_size": file_size,
                "total_chunks": total_chunks,
                "peer_addr": peer_addr,
                "peer_id": peer_id,
                "progress_cb": progress_callback,
                "acked": set(),
                "retries": {},
                "status": "pending",
                "start_time": time.time(),
            }
        threading.Thread(target=self._upload_worker, args=(transfer_id,), daemon=True).start()
        return transfer_id

    def _upload_worker(self, transfer_id: str):
        with self.lock:
            tf = self.transfers[transfer_id]
        file_path = tf["file_path"]
        peer_addr = tf["peer_addr"]
        total_chunks = tf["total_chunks"]
        acked = tf["acked"]
        retries = tf["retries"]

        # Preload all chunks (so crypto can be applied if needed)
        chunks: List[bytes] = []
        with open(file_path, "rb") as f:
            for _ in range(total_chunks):
                data = f.read(CHUNK_SIZE)
                data = self.crypto.encrypt_data(tf["peer_id"], data)
                chunks.append(data)

        # For sending and waiting for ACKs
        for seq in range(total_chunks):
            retries[seq] = 0

        sent_time: Dict[int, float] = {}
        while len(acked) < total_chunks:
            for seq in range(total_chunks):
                if seq in acked:
                    continue
                if retries[seq] >= MAX_RETRIES:
                    logger.error(f"Chunk {seq} of {transfer_id} failed after max retries.")
                    with self.lock:
                        tf["status"] = "failed"
                    return

                now = time.time()
                if seq not in sent_time or now - sent_time[seq] > TIMEOUT:
                    pkt = _make_data_packet(transfer_id, seq, chunks[seq])
                    self.socket.sendto(pkt, peer_addr)
                    sent_time[seq] = now
                    retries[seq] += 1

            # Sniff for ACKs for this transfer_id
            def ack_filter(pkt):
                if not pkt or not hasattr(pkt, "load"):
                    return False
                try:
                    pkt_type, t_id, seq, _ = _parse_packet(pkt.load)
                    return pkt_type == PKT_ACK and t_id == transfer_id
                except Exception:
                    return False
            sniffed = sniff(
                lfilter=ack_filter,
                timeout=TIMEOUT,
                count=1,
                iface=conf.iface,
                prn=lambda pkt: acked.add(_parse_packet(pkt.load)[2]),
                stop_filter=lambda pkt: len(acked) == total_chunks,
                store=0
            )

            # Progress callback
            if tf["progress_cb"]:
                tf["progress_cb"](transfer_id, len(acked), total_chunks)

        # EOF packet
        eof_pkt = _make_eof_packet(transfer_id, total_chunks)
        self.socket.sendto(eof_pkt, peer_addr)
        with self.lock:
            tf["status"] = "completed"
            tf["end_time"] = time.time()
        logger.info(f"Transfer {transfer_id} completed.")

    def handle_message(self, data: bytes, addr: Tuple[str, int], peer_id: str):
        # Accept data or EOF
        pkt_type, t_id, seq, chunk_data = _parse_packet(data)
        if pkt_type == PKT_DATA:
            self._handle_chunk(t_id, seq, chunk_data, addr, peer_id)
        elif pkt_type == PKT_EOF:
            self._handle_eof(t_id, seq, addr)
        # Ignore PKT_ACK (sender handles acks locally)

    def _handle_chunk(self, transfer_id: str, seq: int, chunk: bytes, addr, peer_id):
        with self.lock:
            if transfer_id not in self.transfers:
                # Init transfer
                tf = {
                    "direction": "in",
                    "file_name": f"incoming_{transfer_id}",
                    "file_size": None,
                    "total_chunks": None,
                    "chunks": {},
                    "peer_addr": addr,
                    "peer_id": peer_id,
                    "status": "receiving",
                    "start_time": time.time(),
                }
                self.transfers[transfer_id] = tf
            else:
                tf = self.transfers[transfer_id]
        # Decrypt
        try:
            data = self.crypto.decrypt_data(peer_id, chunk)
        except Exception as e:
            logger.error(f"Decryption failed for chunk {seq} of {transfer_id}: {e}")
            tf["status"] = "failed"
            return

        tf["chunks"][seq] = data
        # Send ACK
        ack_pkt = _make_ack_packet(transfer_id, seq)
        self.socket.sendto(ack_pkt, addr)

        # Progress callback
        if self.progress_callback:
            self.progress_callback(transfer_id, len(tf["chunks"]), tf.get("total_chunks", 0) or 0)

    def _handle_eof(self, transfer_id: str, total_chunks: int, addr):
        with self.lock:
            tf = self.transfers.get(transfer_id)
            if not tf:
                logger.warning(f"EOF for unknown transfer {transfer_id}")
                return
            tf["total_chunks"] = total_chunks
            if len(tf["chunks"]) < total_chunks:
                logger.warning(f"EOF received but only {len(tf['chunks'])}/{total_chunks} chunks received")
                tf["status"] = "failed"
                return
            # Save file
            dest = os.path.join(self.save_dir, tf["file_name"])
            with open(dest, "wb") as out:
                for i in range(total_chunks):
                    out.write(tf["chunks"][i])
            tf["status"] = "completed"
            tf["end_time"] = time.time()
            logger.info(f"Received file written to {dest}")

    # For compatibility, not used
    def handle_binary_data(self, *_):
        pass

    def _process_chunk(self, transfer_id: str, chunk_index: int, peer_id: str,
                       addr: Tuple[str, int], data: bytes):
        self._handle_chunk(transfer_id, chunk_index, data, addr, peer_id)

# Alias for drop-in replacement
FileTransfer = ScapyFileTransfer