"""
Demo script for the P2P file sharing system.
Shows how to use the system to share files between peers.
"""
import os
import sys
import time
import logging
import argparse
import threading
from typing import Dict, List, Tuple, Optional

from p2p_node import P2PNode

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def print_banner():
    """Print a banner for the demo"""
    print("\n" + "=" * 80)
    print("Decentralized P2P File Sharing Demo")
    print("=" * 80)
    print("This demo shows how to use the P2P file sharing system to share files between peers.")
    print("Each peer uses STUN for NAT traversal and UDP hole punching for direct connections.")
    print("Files are encrypted with AES and transferred directly between peers.\n")

def print_peer_info(node: P2PNode):
    """Print information about the peer"""
    info = node.get_peer_info()
    print("\nYour Peer Information:")
    print(f"Node ID: {info['node_id']}")
    print(f"External IP: {info['external_ip']}")
    print(f"External Port: {info['external_port']}")
    print(f"NAT Type: {info['nat_type']}")
    print("\nShare this information with other peers to connect.")
    print("=" * 80 + "\n")

def print_help():
    """Print help information"""
    print("\nCommands:")
    print("  connect <peer_id> <peer_ip> <peer_port> - Connect to a peer")
    print("  send <peer_id> <file_path> - Send a file to a peer")
    print("  msg <peer_id> <message> - Send a test message to a peer")  # <-- Added
    print("  status <transfer_id> - Check the status of a file transfer")
    print("  list - List connected peers")
    print("  info - Show your peer information")
    print("  help - Show this help message")
    print("  exit - Exit the demo")

def monitor_transfer(node: P2PNode, transfer_id: str):
    """Monitor a file transfer and print updates"""
    while True:
        status = node.get_transfer_status(transfer_id)
        if status['status'] == 'unknown':
            print(f"Transfer {transfer_id} not found")
            break

        print(f"Transfer: {status['file_name']} - {status['progress']:.1f}% - {status['status']}")

        if status['status'] in ['completed', 'failed']:
            if status['status'] == 'completed':
                print(f"Transfer completed! Speed: {status['speed']:.2f} KB/s")
            else:
                print("Transfer failed!")
            break

        time.sleep(1)

def main():
    """Main function for the demo"""
    parser = argparse.ArgumentParser(description='P2P File Sharing Demo')
    parser.add_argument('--port', type=int, default=0, help='Local UDP port (default: random)')
    parser.add_argument('--save-dir', type=str, default='./downloads', help='Directory to save received files')
    args = parser.parse_args()

    print_banner()

    # Create and start P2P node
    node = P2PNode(args.port, args.save_dir)

    # Add a thread to print received messages
    def print_incoming_messages():
        while True:
            msg = node.get_next_incoming_message()
            if msg is not None:
                print(f"\n[Message from {msg['peer_id']}]: {msg['message']}")
            time.sleep(0.2)
    threading.Thread(target=print_incoming_messages, daemon=True).start()

    try:
        node.start()
        print_peer_info(node)
        print_help()

        # Main command loop
        while True:
            try:
                command = input("\n> ").strip()

                if not command:
                    continue

                parts = command.split()
                cmd = parts[0].lower()

                if cmd == 'exit':
                    break

                elif cmd == 'help':
                    print_help()

                elif cmd == 'info':
                    print_peer_info(node)

                elif cmd == 'list':
                    if not node.peers:
                        print("No connected peers")
                    else:
                        print("\nConnected Peers:")
                        for peer_id, peer in node.peers.items():
                            if peer.get('connected'):
                                print(f"  {peer_id} - {peer['addr'][0]}:{peer['addr'][1]}")

                elif cmd == 'connect':
                    if len(parts) != 4:
                        print("Usage: connect <peer_id> <peer_ip> <peer_port>")
                        continue

                    peer_id = parts[1]
                    peer_ip = parts[2]

                    try:
                        peer_port = int(parts[3])
                    except ValueError:
                        print("Port must be a number")
                        continue

                    print(f"Connecting to peer {peer_id} at {peer_ip}:{peer_port}...")
                    if node.connect_to_peer(peer_id, peer_ip, peer_port):
                        print("Connection initiated. Check 'list' command to see if connection is established.")
                    else:
                        print("Failed to initiate connection")

                elif cmd == 'send':
                    if len(parts) < 3:
                        print("Usage: send <peer_id> <file_path>")
                        continue

                    peer_id = parts[1]
                    file_path = ' '.join(parts[2:])

                    if not os.path.exists(file_path):
                        print(f"File not found: {file_path}")
                        continue

                    if peer_id not in node.peers or not node.peers[peer_id].get('connected'):
                        print(f"Peer {peer_id} is not connected")
                        continue

                    print(f"Sending file {file_path} to peer {peer_id}...")
                    transfer_id = node.send_file(peer_id, file_path)

                    if transfer_id:
                        print(f"Transfer started with ID: {transfer_id}")
                        # Start a thread to monitor the transfer
                        monitor_thread = threading.Thread(
                            target=monitor_transfer,
                            args=(node, transfer_id)
                        )
                        monitor_thread.daemon = True
                        monitor_thread.start()
                    else:
                        print("Failed to start file transfer")

                elif cmd == 'status':
                    if len(parts) != 2:
                        print("Usage: status <transfer_id>")
                        continue

                    transfer_id = parts[1]
                    status = node.get_transfer_status(transfer_id)

                    if status['status'] == 'unknown':
                        print(f"Transfer {transfer_id} not found")
                    else:
                        print(f"\nTransfer: {status['file_name']}")
                        print(f"Size: {status['file_size']} bytes")
                        print(f"Progress: {status['progress']:.1f}%")
                        print(f"Status: {status['status']}")
                        if status['status'] == 'completed':
                            print(f"Speed: {status['speed']:.2f} KB/s")

                elif cmd == 'msg':
                    if len(parts) < 3:
                        print("Usage: msg <peer_id> <message>")
                        continue
                    peer_id = parts[1]
                    message = ' '.join(parts[2:])
                    if peer_id not in node.peers or not node.peers[peer_id].get('connected'):
                        print(f"Peer {peer_id} is not connected")
                        continue
                    node.send_message(peer_id, message)
                    print(f"Sent message to {peer_id}")

                else:
                    print(f"Unknown command: {cmd}")
                    print_help()

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")

    except Exception as e:
        print(f"Error starting P2P node: {e}")
    finally:
        # Stop the P2P node
        node.stop()
        print("\nP2P node stopped. Goodbye!")

if __name__ == "__main__":
    main()
