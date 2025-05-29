"""
Demo script for the P2P file sharing system with pure QUIC implementation.
Shows how to use the system to share files between peers using QUIC for everything.
"""
import os
import sys
import time
import logging
import argparse
import threading
import asyncio
from typing import Dict, List, Tuple, Optional

from p2p_node import P2PNode

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def print_banner():
    """Print a banner for the demo"""
    print("\n" + "=" * 80)
    print("🚀 Decentralized P2P File Sharing Demo - Pure QUIC Edition")
    print("=" * 80)
    print("This demo shows how to use the P2P file sharing system with pure QUIC communication.")
    print("✨ NEW: QUIC is used for NAT hole punching, peer discovery, AND file transfers!")
    print("🔒 Built-in encryption, reliable delivery, and multiplexing in one protocol.")
    print("🌐 No more UDP - everything runs over secure QUIC connections.\n")


def print_peer_info(node: P2PNode):
    """Print information about the peer"""
    info = node.get_peer_info()
    print("\n🔍 Your Peer Information:")
    print(f"   Node ID: {info['node_id']}")
    print(f"   External IP: {info['external_ip']}")
    print(f"   QUIC Port: {info['external_port']} (unified for all communication)")
    print(f"   NAT Type: {info['nat_type']}")
    print("\n📋 Share this information with other peers to connect:")
    print(f"   connect {info['node_id']} {info['external_ip']} {info['external_port']}")
    print("\n💡 Note: QUIC handles both discovery and file transfers on the same port!")
    print("=" * 80 + "\n")


def print_help():
    """Print help information"""
    print("\n📚 Available Commands:")
    print("  🔗 connect <peer_id> <peer_ip> <quic_port> - Connect to a peer via QUIC")
    print("  📤 send <peer_id> <file_path> - Send a file to a peer via QUIC")
    print("  💬 msg <peer_id> <message> - Send a test message to a peer via QUIC")
    print("  📊 status <transfer_id> - Check the status of a file transfer")
    print("  📋 list - List connected peers")
    print("  ℹ️  info - Show your peer information")
    print("  ❓ help - Show this help message")
    print("  🚪 exit - Exit the demo")
    print("\n🎯 Note: Everything now uses QUIC - secure, reliable, and fast!")
    print("🔐 All communication is encrypted and authenticated by default.")


def monitor_transfer(node: P2PNode, transfer_id: str):
    """Monitor a file transfer and print updates"""
    print(f"📈 Monitoring transfer {transfer_id}...")
    last_progress = -1

    while True:
        try:
            status = node.get_transfer_status(transfer_id)
            if status['status'] == 'unknown':
                print(f"❌ Transfer {transfer_id} not found or completed")
                break

            current_progress = status.get('progress', 0)
            if current_progress != last_progress:
                print(f"📊 Transfer: {status['file_name']} - {current_progress:.1f}% - {status['status']}")
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


def print_startup_status(external_ip: str, external_port: int):
    """Print startup status with improved formatting"""
    print(f"\n🎉 QUIC P2P Node Started Successfully!")
    print(f"   🌐 External IP: {external_ip}")
    print(f"   🔌 QUIC Port: {external_port} (unified for all communication)")
    print(f"   🔒 Security: TLS 1.3 encryption enabled")
    print(f"   🚀 Features: Hole punching + File transfer + Messaging")


def handle_connection_attempt(node: P2PNode, peer_id: str, peer_ip: str, peer_port: int):
    """Handle connection attempt with better user feedback"""
    print(f"🔄 Initiating QUIC connection to peer {peer_id}...")
    print(f"   📍 Target: {peer_ip}:{peer_port}")
    print(f"   🔓 Attempting QUIC hole punching...")

    # Show a progress indicator
    def show_progress():
        for i in range(10):  # 10 seconds max
            if peer_id in node.peers and node.peers[peer_id].get('connected'):
                return
            print(".", end="", flush=True)
            time.sleep(1)

    progress_thread = threading.Thread(target=show_progress, daemon=True)
    progress_thread.start()

    success = node.connect_to_peer(peer_id, peer_ip, peer_port)
    progress_thread.join(timeout=1)
    print()  # New line after progress dots

    if success:
        print("✅ QUIC connection initiated successfully!")
        print("   ⏳ Waiting for peer handshake... (check 'list' command)")
    else:
        print("❌ Failed to initiate QUIC connection")
        print("   💡 Tips:")
        print("      - Check if peer is online and listening")
        print("      - Verify IP address and port")
        print("      - Ensure firewalls allow QUIC traffic")


def main():
    """Main function for the demo"""
    parser = argparse.ArgumentParser(description='P2P File Sharing Demo - Pure QUIC Edition')
    parser.add_argument('--port', type=int, default=0,
                       help='Local QUIC port (default: random, replaces both UDP and QUIC ports)')
    parser.add_argument('--save-dir', type=str, default='./downloads',
                       help='Directory to save received files')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print_banner()

    # Create and start P2P node (quic_port is same as local_port now)
    node = P2PNode(local_port=args.port, quic_port=args.port, save_dir=args.save_dir)

    # Add a thread to print received messages
    def print_incoming_messages():
        while True:
            try:
                msg = node.get_next_incoming_message()
                if msg is not None:
                    print(f"\n💬 [QUIC Message from {msg['peer_id']}]: {msg['message']}")
                    print("> ", end="", flush=True)  # Re-show prompt
                time.sleep(0.2)
            except Exception as e:
                logger.error(f"Error in message thread: {e}")
                break

    message_thread = threading.Thread(target=print_incoming_messages, daemon=True)
    message_thread.start()

    try:
        # Start the node - returns unified values (same port for everything)
        external_ip, external_port, external_quic_port = node.start()
        print_startup_status(external_ip, external_port)

        print_peer_info(node)
        print_help()

        # Main command loop
        while True:
            try:
                command = input("\n🔸 > ").strip()

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
                        print("📭 No connected peers")
                    else:
                        print("\n🔗 Connected Peers:")
                        for peer_id, peer in node.peers.items():
                            if peer.get('connected'):
                                addr = peer.get('addr', ('unknown', 'unknown'))
                                quic_port = peer.get('quic_port', 'unknown')
                                connection_type = "🔒 QUIC" if peer.get('quic_connected') else "🔗 Standard"
                                print(f"   {connection_type} {peer_id} - {addr[0]}:{quic_port}")
                        print()

                elif cmd == 'connect':
                    if len(parts) < 4:
                        print("❌ Usage: connect <peer_id> <peer_ip> <quic_port>")
                        print("   Example: connect alice-node 192.168.1.100 12345")
                        continue

                    peer_id = parts[1]
                    peer_ip = parts[2]

                    try:
                        peer_port = int(parts[3])
                    except ValueError:
                        print("❌ Port must be a number")
                        continue

                    handle_connection_attempt(node, peer_id, peer_ip, peer_port)

                elif cmd == 'send':
                    if len(parts) < 3:
                        print("❌ Usage: send <peer_id> <file_path>")
                        print("   Example: send alice-node ./myfile.txt")
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
                    print(f"📤 Sending file via encrypted QUIC stream...")
                    print(f"   📁 File: {file_path} ({file_size:,} bytes)")
                    print(f"   🎯 Target: {peer_id}")

                    transfer_id = node.send_file(peer_id, file_path)

                    if transfer_id:
                        print(f"✅ QUIC transfer started with ID: {transfer_id}")
                        # Start a thread to monitor the transfer
                        monitor_thread = threading.Thread(
                            target=monitor_transfer,
                            args=(node, transfer_id),
                            daemon=True
                        )
                        monitor_thread.start()
                    else:
                        print("❌ Failed to start QUIC file transfer")

                elif cmd == 'status':
                    if len(parts) != 2:
                        print("❌ Usage: status <transfer_id>")
                        continue

                    transfer_id = parts[1]
                    status = node.get_transfer_status(transfer_id)

                    if status['status'] == 'unknown':
                        print(f"❌ Transfer {transfer_id} not found")
                    else:
                        print(f"\n📊 QUIC Transfer Status:")
                        print(f"   📁 File: {status['file_name']}")
                        print(f"   📏 Size: {status['file_size']:,} bytes")
                        print(f"   📈 Progress: {status['progress']:.1f}%")
                        print(f"   🔄 Status: {status['status']}")
                        if status['status'] == 'completed':
                            speed = status.get('speed', 0)
                            print(f"   🚀 Speed: {speed:.2f} KB/s")
                        print()

                elif cmd == 'msg':
                    if len(parts) < 3:
                        print("❌ Usage: msg <peer_id> <message>")
                        print("   Example: msg alice-node Hello there!")
                        continue

                    peer_id = parts[1]
                    message = ' '.join(parts[2:])

                    if peer_id not in node.peers or not node.peers[peer_id].get('connected'):
                        print(f"❌ Peer {peer_id} is not connected")
                        continue

                    print(f"📨 Sending QUIC message to {peer_id}...")
                    if node.debug_send_message(peer_id, message):
                        print(f"✅ Message sent via encrypted QUIC stream")
                    else:
                        print(f"❌ Failed to send QUIC message")

                # Hidden debug commands
                elif cmd == 'debug' and len(parts) > 1:
                    if parts[1] == 'peers':
                        print("\n🔍 Debug: Peer Details")
                        for peer_id, peer in node.peers.items():
                            print(f"   {peer_id}: {peer}")
                    elif parts[1] == 'crypto':
                        stats = node.crypto_manager.get_crypto_stats()
                        print(f"\n🔐 Debug: Crypto Stats")
                        print(f"   Encryptions: {stats['encryption_count']}")
                        print(f"   Decryptions: {stats['decryption_count']}")
                        print(f"   Active sessions: {stats['active_sessions']}")

                else:
                    print(f"❌ Unknown command: {cmd}")
                    print("💡 Type 'help' for available commands")

            except KeyboardInterrupt:
                print("\n🔄 Interrupt received. Type 'exit' to quit.")
                continue
            except Exception as e:
                logger.error(f"Error processing command: {e}")
                if args.verbose:
                    import traceback
                    logger.error(traceback.format_exc())

    except Exception as e:
        logger.error(f"Error starting QUIC P2P node: {e}")
        if args.verbose:
            import traceback
            logger.error(traceback.format_exc())
        return 1
    finally:
        # Stop the P2P node
        print("\n🔄 Stopping QUIC P2P node...")
        try:
            node.stop()
            print("✅ QUIC P2P node stopped successfully. Goodbye! 👋")
        except Exception as e:
            logger.error(f"Error stopping node: {e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())