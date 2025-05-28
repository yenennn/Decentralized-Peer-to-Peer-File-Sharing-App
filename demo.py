"""
Demo script for the P2P file sharing system with QUIC support.
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
    print("Decentralized P2P File Sharing Demo with QUIC")
    print("=" * 80)
    print("This demo shows how to use the P2P file sharing system to share files between peers.")
    print("Uses STUN for NAT traversal, UDP for peer discovery, and QUIC for reliable file transfers.")
    print("Files are encrypted with AES and transferred directly between peers using QUIC.\n")


def print_peer_info(node: P2PNode):
    """Print information about the peer"""
    info = node.get_peer_info()
    print("\nYour Peer Information:")
    print(f"Node ID: {info['node_id']}")
    print(f"External IP: {info['external_ip']}")
    print(f"External UDP Port: {info['external_port']} (for peer discovery)")
    print(f"External QUIC Port: {info['external_quic_port']} (for file transfers)")
    print(f"NAT Type: {info['nat_type']}")
    print("\nShare this information with other peers to connect.")
    print("Note: Other peers need your UDP port for initial connection.")
    print("=" * 80 + "\n")


def print_help():
    """Print help information"""
    print("\nCommands:")
    print("  connect <peer_id> <peer_ip> <peer_udp_port> [peer_quic_port] - Connect to a peer")
    print("  send <peer_id> <file_path> - Send a file to a peer via QUIC")
    print("  msg <peer_id> <message> - Send a test message to a peer via UDP")
    print("  status <transfer_id> - Check the status of a file transfer")
    print("  list - List connected peers")
    print("  info - Show your peer information")
    print("  help - Show this help message")
    print("  exit - Exit the demo")
    print("\nNote: File transfers use QUIC (reliable), messages use UDP (fast)")


def monitor_transfer(node: P2PNode, transfer_id: str):
    """Monitor a file transfer and print updates"""
    print(f"Monitoring transfer {transfer_id}...")
    last_progress = -1

    while True:
        try:
            status = node.get_transfer_status(transfer_id)
            if status['status'] == 'unknown':
                print(f"Transfer {transfer_id} not found or completed")
                break

            current_progress = status.get('progress', 0)
            if current_progress != last_progress:
                print(f"Transfer: {status['file_name']} - {current_progress:.1f}% - {status['status']}")
                last_progress = current_progress

            if status['status'] in ['completed', 'failed']:
                if status['status'] == 'completed':
                    speed = status.get('speed', 0)
                    print(f"✅ Transfer completed! Speed: {speed:.2f} KB/s")
                else:
                    print("❌ Transfer failed!")
                break

            time.sleep(2)
        except Exception as e:
            logger.error(f"Error monitoring transfer: {e}")
            break


def main():
    """Main function for the demo"""
    parser = argparse.ArgumentParser(description='P2P File Sharing Demo with QUIC')
    parser.add_argument('--port', type=int, default=0, help='Local UDP port (default: random)')
    parser.add_argument('--quic-port', type=int, default=0, help='Local QUIC port (default: UDP port + 1000)')
    parser.add_argument('--save-dir', type=str, default='./downloads', help='Directory to save received files')
    args = parser.parse_args()

    print_banner()

    # Create and start P2P node
    node = P2PNode(local_port=args.port, quic_port=args.quic_port, save_dir=args.save_dir)

    # Add a thread to print received messages
    def print_incoming_messages():
        while True:
            try:
                msg = node.get_next_incoming_message()
                if msg is not None:
                    print(f"\n📨 [Message from {msg['peer_id']}]: {msg['message']}")
                    print("> ", end="", flush=True)  # Re-show prompt
                time.sleep(0.2)
            except Exception as e:
                logger.error(f"Error in message thread: {e}")
                break

    message_thread = threading.Thread(target=print_incoming_messages, daemon=True)
    message_thread.start()

    try:
        # Start the node - now returns 3 values
        external_ip, external_port, external_quic_port = node.start()
        print(f"✅ P2P node started successfully!")
        print(f"   UDP Port: {external_port} (peer discovery)")
        print(f"   QUIC Port: {external_quic_port} (file transfers)")

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
                                udp_port = peer['addr'][1]
                                quic_port = peer.get('quic_port', 'unknown')
                                print(f"  🔗 {peer_id} - {peer['addr'][0]}:{udp_port} (QUIC: {quic_port})")

                elif cmd == 'connect':
                    if len(parts) < 4:
                        print("Usage: connect <peer_id> <peer_ip> <peer_udp_port> [peer_quic_port]")
                        continue

                    peer_id = parts[1]
                    peer_ip = parts[2]

                    try:
                        peer_udp_port = int(parts[3])
                        peer_quic_port = int(parts[4]) if len(parts) > 4 else None
                    except ValueError:
                        print("Ports must be numbers")
                        continue

                    print(f"🔄 Connecting to peer {peer_id} at {peer_ip}:{peer_udp_port}...")
                    if peer_quic_port:
                        print(f"   Using QUIC port: {peer_quic_port}")

                    if node.connect_to_peer(peer_id, peer_ip, peer_udp_port, peer_quic_port):
                        print("✅ Connection initiated. Check 'list' command to see if connection is established.")
                    else:
                        print("❌ Failed to initiate connection")

                elif cmd == 'send':
                    if len(parts) < 3:
                        print("Usage: send <peer_id> <file_path>")
                        continue

                    peer_id = parts[1]
                    file_path = ' '.join(parts[2:])

                    if not os.path.exists(file_path):
                        print(f"❌ File not found: {file_path}")
                        continue

                    if peer_id not in node.peers or not node.peers[peer_id].get('connected'):
                        print(f"❌ Peer {peer_id} is not connected. Use 'connect' command first.")
                        continue

                    file_size = os.path.getsize(file_path)
                    print(f"📤 Sending file {file_path} ({file_size} bytes) to peer {peer_id} via QUIC...")

                    transfer_id = node.send_file(peer_id, file_path)

                    if transfer_id:
                        print(f"✅ Transfer started with ID: {transfer_id}")
                        # Start a thread to monitor the transfer
                        monitor_thread = threading.Thread(
                            target=monitor_transfer,
                            args=(node, transfer_id),
                            daemon=True
                        )
                        monitor_thread.start()
                    else:
                        print("❌ Failed to start file transfer")

                elif cmd == 'status':
                    if len(parts) != 2:
                        print("Usage: status <transfer_id>")
                        continue

                    transfer_id = parts[1]
                    status = node.get_transfer_status(transfer_id)

                    if status['status'] == 'unknown':
                        print(f"❌ Transfer {transfer_id} not found")
                    else:
                        print(f"\n📊 Transfer Status:")
                        print(f"   File: {status['file_name']}")
                        print(f"   Size: {status['file_size']} bytes")
                        print(f"   Progress: {status['progress']:.1f}%")
                        print(f"   Status: {status['status']}")
                        if status['status'] == 'completed':
                            speed = status.get('speed', 0)
                            print(f"   Speed: {speed:.2f} KB/s")

                elif cmd == 'msg':
                    if len(parts) < 3:
                        print("Usage: msg <peer_id> <message>")
                        continue

                    peer_id = parts[1]
                    message = ' '.join(parts[2:])

                    if peer_id not in node.peers or not node.peers[peer_id].get('connected'):
                        print(f"❌ Peer {peer_id} is not connected")
                        continue

                    if node.send_message(peer_id, message):
                        print(f"✅ Sent message to {peer_id}")
                    else:
                        print(f"❌ Failed to send message to {peer_id}")

                else:
                    print(f"❌ Unknown command: {cmd}")
                    print_help()

            except KeyboardInterrupt:
                print("\n🔄 Interrupt received. Type 'exit' to quit.")
                continue
            except Exception as e:
                logger.error(f"Error processing command: {e}")
                import traceback
                logger.error(traceback.format_exc())

    except Exception as e:
        logger.error(f"Error starting P2P node: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return 1
    finally:
        # Stop the P2P node
        print("\n🔄 Stopping P2P node...")
        try:
            node.stop()
            print("✅ P2P node stopped. Goodbye!")
        except Exception as e:
            logger.error(f"Error stopping node: {e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())