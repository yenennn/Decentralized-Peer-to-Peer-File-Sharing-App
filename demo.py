"""
Enhanced demo application for P2P file sharing with TCP transfers.
"""
import argparse
import threading
import time
import os
import logging
from typing import Dict, List, Tuple, Optional

from p2p_node import P2PNode

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def print_banner():
    """Print a banner for the demo"""
    print("\n" + "=" * 80)
    print("Decentralized P2P File Sharing Demo - TCP Version")
    print("=" * 80)
    print("This demo shows how to use the P2P file sharing system with reliable TCP transfers.")
    print("Each peer uses STUN for NAT traversal and UDP for peer discovery.")
    print("Files are transferred reliably using TCP connections with AES encryption.")
    print("=" * 80)


def print_peer_info(node: P2PNode):
    """Print information about the peer"""
    info = node.get_peer_info()
    print("\nYour Peer Information:")
    print(f"Node ID: {info['node_id']}")
    print(f"External IP: {info['external_ip']}")
    print(f"External UDP Port: {info['external_port']} (for peer communication)")
    print(f"TCP File Transfer Port: {info['tcp_port']} (for file transfers)")
    print(f"NAT Type: {info['nat_type']}")
    print("\nShare this information with other peers to connect.")
    print("Format for connecting: connect <peer_id> <ip> <udp_port> <tcp_port>")
    print("=" * 80 + "\n")


def print_help():
    """Print help information"""
    print("\nCommands:")
    print("  connect <peer_id> <peer_ip> <peer_udp_port> <peer_tcp_port> - Connect to a peer")
    print("  send <peer_id> <file_path> - Send a file to a peer")
    print("  msg <peer_id> <message> - Send a test message to a peer")
    print("  status <transfer_id> - Check the status of a file transfer")
    print("  transfers - List all file transfers")
    print("  peers - List connected peers")
    print("  info - Show your peer information")
    print("  help - Show this help message")
    print("  exit - Exit the demo")
    print()


def monitor_transfer(node: P2PNode, transfer_id: str):
    """Monitor a file transfer and print updates"""
    print(f"Monitoring transfer {transfer_id}...")

    while True:
        status = node.get_transfer_status(transfer_id)

        if status['status'] == 'unknown':
            print(f"Transfer {transfer_id} not found")
            break

        direction = status.get('direction', 'unknown')
        direction_str = "⬆️ Uploading" if direction == 'out' else "⬇️ Downloading"

        print(f"{direction_str}: {status['file_name']} - {status['progress']:.1f}% - {status['status']}")

        if status['status'] in ['completed', 'failed']:
            if status['status'] == 'completed':
                print(f"✅ Transfer completed! Speed: {status['speed']:.2f} KB/s")
            else:
                print("❌ Transfer failed!")
            break

        time.sleep(2)


def list_peers(node: P2PNode):
    """List all connected peers"""
    peers = node.list_peers()

    if not peers:
        print("No connected peers.")
        return

    print("\nConnected Peers:")
    print("-" * 80)
    for peer_id, info in peers.items():
        status = "✅ Connected" if info['connected'] else "❌ Disconnected"
        last_seen = time.strftime('%H:%M:%S', time.localtime(info['last_seen']))
        print(f"ID: {peer_id[:16]}...")
        print(f"   Address: {info['addr'][0]}:{info['addr'][1]} (UDP)")
        print(f"   TCP Port: {info.get('tcp_port', 'Unknown')}")
        print(f"   Status: {status}")
        print(f"   Last Seen: {last_seen}")
        print()


def list_transfers(node: P2PNode):
    """List all file transfers"""
    transfers = node.list_transfers()

    if not transfers:
        print("No file transfers.")
        return

    print("\nFile Transfers:")
    print("-" * 80)
    for transfer_id, status in transfers.items():
        direction = status.get('direction', 'unknown')
        direction_str = "⬆️ Upload" if direction == 'out' else "⬇️ Download"
        status_icon = {
            'completed': '✅',
            'failed': '❌',
            'sending': '⬆️',
            'receiving': '⬇️'
        }.get(status['status'], '❓')

        print(f"{status_icon} {direction_str}: {status['file_name']}")
        print(f"   ID: {transfer_id}")
        print(f"   Progress: {status['progress']:.1f}%")
        print(f"   Status: {status['status']}")
        if status['speed'] > 0:
            print(f"   Speed: {status['speed']:.2f} KB/s")
        print()


def main():
    """Main function for the demo"""
    parser = argparse.ArgumentParser(description='P2P File Sharing Demo - TCP Version')
    parser.add_argument('--port', type=int, default=0, help='Local UDP port for peer communication (default: random)')
    parser.add_argument('--save-dir', type=str, default='./downloads', help='Directory to save received files')
    args = parser.parse_args()

    print_banner()

    # Create and start P2P node
    node = P2PNode(args.port, args.save_dir)

    try:
        node.start()
    except Exception as e:
        print(f"Failed to start P2P node: {e}")
        return

    print_peer_info(node)
    print_help()

    # Thread to print incoming messages
    def print_incoming_messages():
        while True:
            msg = node.get_next_incoming_message()
            if msg is not None:
                print(f"\n💬 [Message from {msg['peer_id'][:16]}...]: {msg['message']}")
                print("Enter command: ", end="", flush=True)
            time.sleep(0.2)

    message_thread = threading.Thread(target=print_incoming_messages, daemon=True)
    message_thread.start()

    # Main command loop
    try:
        while True:
            try:
                command = input("Enter command: ").strip().split()

                if not command:
                    continue

                cmd = command[0].lower()

                if cmd == 'exit':
                    break

                elif cmd == 'help':
                    print_help()

                elif cmd == 'info':
                    print_peer_info(node)

                elif cmd == 'peers':
                    list_peers(node)

                elif cmd == 'transfers':
                    list_transfers(node)

                elif cmd == 'connect':
                    if len(command) != 5:
                        print("Usage: connect <peer_id> <peer_ip> <peer_udp_port> <peer_tcp_port>")
                        continue

                    peer_id = command[1]
                    peer_ip = command[2]
                    peer_udp_port = int(command[3])
                    peer_tcp_port = int(command[4])

                    success = node.connect_to_peer(peer_id, peer_ip, peer_udp_port, peer_tcp_port)
                    if success:
                        print(f"🔄 Connecting to peer {peer_id}...")
                    else:
                        print(f"❌ Failed to initiate connection to peer {peer_id}")

                elif cmd == 'send':
                    if len(command) != 3:
                        print("Usage: send <peer_id> <file_path>")
                        continue

                    peer_id = command[1]
                    file_path = command[2]

                    if not os.path.exists(file_path):
                        print(f"❌ File not found: {file_path}")
                        continue

                    transfer_id = node.send_file(peer_id, file_path)
                    if transfer_id:
                        print(f"🚀 Started file transfer: {transfer_id}")

                        # Start monitoring in background
                        monitor_thread = threading.Thread(
                            target=monitor_transfer,
                            args=(node, transfer_id),
                            daemon=True
                        )
                        monitor_thread.start()
                    else:
                        print("❌ Failed to start file transfer")

                elif cmd == 'msg':
                    if len(command) < 3:
                        print("Usage: msg <peer_id> <message>")
                        continue

                    peer_id = command[1]
                    message = ' '.join(command[2:])

                    success = node.send_message(peer_id, message)
                    if success:
                        print(f"✅ Message sent to {peer_id}")
                    else:
                        print(f"❌ Failed to send message to {peer_id}")

                elif cmd == 'status':
                    if len(command) != 2:
                        print("Usage: status <transfer_id>")
                        continue

                    transfer_id = command[1]
                    status = node.get_transfer_status(transfer_id)

                    if status['status'] == 'unknown':
                        print(f"❓ Transfer {transfer_id} not found")
                    else:
                        direction = status.get('direction', 'unknown')
                        direction_str = "Upload" if direction == 'out' else "Download"
                        print(f"\n{direction_str} Status for {transfer_id}:")
                        print(f"  File: {status['file_name']}")
                        print(f"  Progress: {status['progress']:.1f}%")
                        print(f"  Status: {status['status']}")
                        if status['speed'] > 0:
                            print(f"  Speed: {status['speed']:.2f} KB/s")

                else:
                    print(f"❓ Unknown command: {cmd}")
                    print("Type 'help' for available commands.")

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"❌ Error: {e}")

    finally:
        print("\n🛑 Shutting down...")
        node.stop()
        print("👋 Goodbye!")


if __name__ == "__main__":
    main()