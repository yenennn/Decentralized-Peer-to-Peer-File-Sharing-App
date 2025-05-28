def main():
    """
    Main entry point for the P2P file transfer application.
    Handles command parsing and initiates appropriate actions.
    """
    import sys
    import time
    import threading
    from p2p_node import P2PNode

    # Create and start the P2P node
    node = P2PNode(local_port=0, save_dir="./downloads")
    external_ip, external_port = node.start()

    print(f"P2P Node started successfully!")
    print(f"Node ID: {node.node_id}")
    print(f"External IP: {external_ip}")
    print(f"External Port: {external_port}")

    def monitor_transfer(transfer_id):
        """Monitor the progress of a file transfer"""
        try:
            done = False
            while not done:
                time.sleep(1)
                try:
                    status = node.get_transfer_status(transfer_id)
                    if status.get('status') == 'completed':
                        print(f"Transfer completed: {status.get('file_name')}")
                        done = True
                    elif status.get('status') == 'failed':
                        print(f"Transfer failed: {status.get('file_name', 'unknown')}")
                        done = True
                    elif status.get('status') == 'unknown':
                        print("Transfer not found or expired")
                        done = True
                    else:
                        # Get progress information if available
                        progress = status.get('progress', 0)
                        print(f"Transfer in progress: {progress:.1f}%")
                except KeyError as e:
                    # Handle missing keys gracefully
                    print(f"Waiting for transfer to initialize...")
        except Exception as e:
            print(f"Error monitoring transfer: {e}")

    # Command loop
    try:
        while True:
            cmd = input("\nEnter command (or 'help'): ").strip()

            if cmd == 'help':
                print("\nCommands:")
                print("  info - Display node information")
                print("  connect <peer_id> <ip> <port> - Connect to a peer")
                print("  send <peer_id> <file_path> - Send a file to a peer")
                print("  message <peer_id> <text> - Send a text message to a peer")
                print("  exit - Exit the application")

            elif cmd == 'info':
                print(f"\nNode ID: {node.node_id}")
                print(f"External IP: {external_ip}")
                print(f"External Port: {external_port}")
                print(f"Connected peers: {len(node.peers)}")

            elif cmd.startswith('connect '):
                parts = cmd.split(' ')
                if len(parts) >= 4:
                    peer_id = parts[1]
                    peer_ip = parts[2]
                    peer_port = int(parts[3])

                    if node.connect_to_peer(peer_id, peer_ip, peer_port):
                        print(f"Connection initiated to peer {peer_id}")
                    else:
                        print(f"Failed to connect to peer {peer_id}")
                else:
                    print("Usage: connect <peer_id> <ip> <port>")

            elif cmd.startswith('send '):
                parts = cmd.split(' ')
                if len(parts) >= 3:
                    peer_id = parts[1]
                    file_path = ' '.join(parts[2:])

                    transfer_id = node.send_file(peer_id, file_path)
                    if transfer_id:
                        print(f"File transfer initiated: {transfer_id}")
                        # Start monitoring thread
                        t = threading.Thread(target=monitor_transfer, args=(transfer_id,), daemon=True)
                        t.start()
                    else:
                        print("Failed to initiate file transfer")
                else:
                    print("Usage: send <peer_id> <file_path>")

            elif cmd.startswith('message '):
                parts = cmd.split(' ', 2)
                if len(parts) >= 3:
                    peer_id = parts[1]
                    message = parts[2]

                    if node.send_message(peer_id, message):
                        print(f"Message sent to peer {peer_id}")
                    else:
                        print(f"Failed to send message to peer {peer_id}")
                else:
                    print("Usage: message <peer_id> <text>")

            elif cmd == 'exit':
                break

            else:
                print("Unknown command. Type 'help' for available commands.")

    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        node.stop()
        print("P2P node stopped")

if __name__ == "__main__":
    main()