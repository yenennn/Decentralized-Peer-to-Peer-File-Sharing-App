import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import time
import os
from typing import Dict, Optional

# Assuming p2p_node is in the same directory or accessible via PYTHONPATH
from p2p_node import P2PNode

# Configure logging for the P2PNode (optional, but good practice)
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class P2PGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P File Sharing")
        self.root.geometry("800x700")

        self.node: Optional[P2PNode] = None
        self.active_transfers = {}  # transfer_id: {'peer_id', 'file_name', 'direction'}
        self.is_node_started = False

        # Default configuration
        self.local_port = 0  # Use 0 for random port
        self.save_dir = "./downloads_gui"
        os.makedirs(self.save_dir, exist_ok=True)

        self.setup_ui()
        self.update_ui_status()  # Start UI updates for messages/peers/transfers

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Configuration and Node Control ---
        config_frame = ttk.LabelFrame(main_frame, text="Node Configuration & Control", padding="10")
        config_frame.pack(fill=tk.X, pady=5)

        ttk.Label(config_frame, text="Local Port:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.port_entry = ttk.Entry(config_frame, width=10)
        self.port_entry.insert(0, str(self.local_port))
        self.port_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(config_frame, text="Save Directory:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.save_dir_entry = ttk.Entry(config_frame, width=30)
        self.save_dir_entry.insert(0, self.save_dir)
        self.save_dir_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)

        self.start_node_button = ttk.Button(config_frame, text="Start Node", command=self.start_node)
        self.start_node_button.grid(row=0, column=4, padx=10, pady=5)

        # --- Your Peer Info ---
        info_frame = ttk.LabelFrame(main_frame, text="Your Peer Information", padding="10")
        info_frame.pack(fill=tk.X, pady=5)

        self.node_id_label = ttk.Label(info_frame, text="Node ID: Not Started")
        self.node_id_label.pack(anchor=tk.W)
        self.ext_ip_label = ttk.Label(info_frame, text="External IP: Not Started")
        self.ext_ip_label.pack(anchor=tk.W)
        self.ext_port_label = ttk.Label(info_frame, text="External Port: Not Started")
        self.ext_port_label.pack(anchor=tk.W)
        self.nat_type_label = ttk.Label(info_frame, text="NAT Type: Not Started")
        self.nat_type_label.pack(anchor=tk.W)

        connection_frame = ttk.Frame(info_frame, padding=(0, 5, 0, 0))
        connection_frame.pack(fill=tk.X, pady=(5, 0))

        ttk.Label(connection_frame, text="Connection String:").pack(side=tk.LEFT)
        self.connection_string = ttk.Entry(connection_frame, width=50)
        self.connection_string.pack(side=tk.LEFT, padx=(5, 5), fill=tk.X, expand=True)
        self.connection_string.insert(0, "connect <node_id> <external_ip> <external_port>")
        self.connection_string.config(state="readonly")

        copy_button = ttk.Button(connection_frame, text="Copy",
                                 command=self.copy_connection_string)
        copy_button.pack(side=tk.LEFT)

        # --- Connect to Peer ---
        # --- Connect to Peer ---
        connect_frame = ttk.LabelFrame(main_frame, text="Connect to Peer", padding="10")
        connect_frame.pack(fill=tk.X, pady=5)

        # Add connection string entry for pasting
        ttk.Label(connect_frame, text="Paste Connection String:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.connection_entry = ttk.Entry(connect_frame, width=50)
        self.connection_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky=tk.EW)
        self.connection_entry.insert(0, "connect <peer_id> <peer_ip> <peer_port>")

        # Quick connect button
        self.quick_connect_button = ttk.Button(connect_frame, text="Quick Connect",
                                               command=self.quick_connect_peer,
                                               state=tk.DISABLED)
        self.quick_connect_button.grid(row=0, column=3, padx=5, pady=5)

        # Separator between quick connect and manual options
        ttk.Separator(connect_frame, orient=tk.HORIZONTAL).grid(row=1, column=0, columnspan=4,
                                                                sticky=tk.EW, pady=10)



        connect_frame.columnconfigure(1, weight=1)

        # --- Paned Window for Peers and Actions ---
        paned_window = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True, pady=5)

        # --- Connected Peers ---
        peers_frame = ttk.LabelFrame(paned_window, text="Connected Peers", padding="10")
        paned_window.add(peers_frame, weight=1)

        self.peers_listbox = tk.Listbox(peers_frame, height=8)
        self.peers_listbox.pack(fill=tk.BOTH, expand=True)
        self.peers_listbox.bind('<<ListboxSelect>>', self.on_peer_select)

        # --- Actions (Send File / Message) ---
        actions_frame = ttk.LabelFrame(paned_window, text="Actions with Selected Peer", padding="10")
        paned_window.add(actions_frame, weight=2)

        # Send File
        ttk.Label(actions_frame, text="File Path:").pack(anchor=tk.W, pady=(0, 2))
        self.file_path_entry = ttk.Entry(actions_frame, width=40, state=tk.DISABLED)
        self.file_path_entry.pack(fill=tk.X, expand=True, side=tk.LEFT, padx=(0, 5))
        self.browse_button = ttk.Button(actions_frame, text="Browse", command=self.browse_file, state=tk.DISABLED)
        self.browse_button.pack(side=tk.LEFT)

        self.send_file_button = ttk.Button(actions_frame, text="Send File", command=self.send_file_gui,
                                           state=tk.DISABLED)
        self.send_file_button.pack(anchor=tk.W, pady=5)

        # Send Message
        ttk.Label(actions_frame, text="Message:").pack(anchor=tk.W, pady=(10, 2))
        self.message_entry = ttk.Entry(actions_frame, width=50, state=tk.DISABLED)
        self.message_entry.pack(fill=tk.X, expand=True, pady=(0, 5))
        self.send_message_button = ttk.Button(actions_frame, text="Send Message", command=self.send_message_gui,
                                              state=tk.DISABLED)
        self.send_message_button.pack(anchor=tk.W, pady=5)

        # --- Log / Status Area ---
        log_frame = ttk.LabelFrame(main_frame, text="Log & Status", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.log_area = scrolledtext.ScrolledText(log_frame, height=10, wrap=tk.WORD, state=tk.DISABLED)
        self.log_area.pack(fill=tk.BOTH, expand=True)

    def log(self, message):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)
        logger.info(message)  # Also log to console/file via standard logger

    def start_node(self):
        if self.node:
            self.log("Node already started.")
            return

        try:
            self.local_port = int(self.port_entry.get())
            self.save_dir = self.save_dir_entry.get()
            if not os.path.isdir(self.save_dir):
                os.makedirs(self.save_dir, exist_ok=True)
                self.log(f"Created save directory: {self.save_dir}")
        except ValueError:
            messagebox.showerror("Error", "Invalid port number.")
            return

        self.log(f"Starting P2P node on port {self.local_port}, save directory {self.save_dir}...")

        # Run node start in a separate thread to avoid freezing GUI
        # P2PNode.start() itself is not heavily blocking as it starts its own threads for STUN and messages.

        try:
            self.node = P2PNode(self.local_port, self.save_dir)
            self.node.start()  # This will do STUN discovery

            self.update_own_peer_info()
            self.is_node_started = True
            self.start_node_button.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)
            self.save_dir_entry.config(state=tk.DISABLED)
            self.connect_button.config(state=tk.NORMAL)
            self.quick_connect_button.config(state=tk.NORMAL)  # Enable quick connect button
            self.log("P2P Node started successfully.")
            self.log(f"Node ID: {self.node.node_id}")
            self.log(f"External: {self.node.external_ip}:{self.node.external_port}, NAT: {self.node.nat_type}")
            self.log(f"Listening on local port: {self.node.socket.getsockname()[1]}")

        except Exception as e:
            self.log(f"Error starting P2P node: {e}")
            messagebox.showerror("Node Start Error", f"Failed to start P2P node: {e}")
            self.node = None  # Ensure node is None if start fails
            return

    def update_own_peer_info(self):
        if self.node and self.node.external_ip:
            info = self.node.get_peer_info()
            self.node_id_label.config(text=f"Node ID: {info['node_id']}")
            self.ext_ip_label.config(text=f"External IP: {info['external_ip']}")
            self.ext_port_label.config(text=f"External Port: {info['external_port']}")
            self.nat_type_label.config(text=f"NAT Type: {info['nat_type']}")

            # Update the connection string
            self.connection_string.config(state="normal")
            self.connection_string.delete(0, tk.END)
            self.connection_string.insert(0, f"connect {info['node_id']} {info['external_ip']} {info['external_port']}")
            self.connection_string.config(state="readonly")
        else:
            self.node_id_label.config(text="Node ID: Not available")
            self.ext_ip_label.config(text="External IP: Not available")
            self.ext_port_label.config(text="External Port: Not available")
            self.nat_type_label.config(text="NAT Type: Not available")
            self.connection_string.config(state="normal")
            self.connection_string.delete(0, tk.END)
            self.connection_string.insert(0, "connect <node_id> <external_ip> <external_port>")
            self.connection_string.config(state="readonly")

    def connect_peer(self):
        if not self.node:
            messagebox.showerror("Error", "Node not started.")
            return

        peer_id = self.peer_id_entry.get().strip()
        peer_ip = self.peer_ip_entry.get().strip()
        peer_port_str = self.peer_port_entry.get().strip()

        if not all([peer_id, peer_ip, peer_port_str]):
            messagebox.showerror("Error", "All peer connection fields are required.")
            return

        try:
            peer_port = int(peer_port_str)
        except ValueError:
            messagebox.showerror("Error", "Peer port must be a number.")
            return

        self.log(f"Initiating connection to {peer_id} at {peer_ip}:{peer_port}...")

        # P2PNode.connect_to_peer starts its own retry thread and returns quickly
        if self.node.connect_to_peer(peer_id, peer_ip, peer_port):
            self.log(f"Connection attempt to {peer_id} initiated. Check peer list for status.")
        else:
            self.log(f"Failed to initiate connection to {peer_id}.")
            messagebox.showerror("Connection Error", f"Could not initiate connection to {peer_id}.")

    def on_peer_select(self, event):
        if not self.peers_listbox.curselection():
            self.file_path_entry.config(state=tk.DISABLED)
            self.browse_button.config(state=tk.DISABLED)
            self.send_file_button.config(state=tk.DISABLED)
            self.message_entry.config(state=tk.DISABLED)
            self.send_message_button.config(state=tk.DISABLED)
            return

        self.file_path_entry.config(state=tk.NORMAL)
        self.browse_button.config(state=tk.NORMAL)
        self.send_file_button.config(state=tk.NORMAL)
        self.message_entry.config(state=tk.NORMAL)
        self.send_message_button.config(state=tk.NORMAL)

    def get_selected_peer_id(self) -> Optional[str]:
        selection = self.peers_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "No peer selected from the list.")
            return None

        selected_item = self.peers_listbox.get(selection[0])
        # Assuming format "peer_id (IP:Port)"
        peer_id = selected_item.split(" (")[0]
        return peer_id

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, file_path)

    def send_file_gui(self):
        if not self.node: return
        peer_id = self.get_selected_peer_id()
        if not peer_id: return

        file_path = self.file_path_entry.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", f"File not found: {file_path}")
            return

        if peer_id not in self.node.peers or not self.node.peers[peer_id].get('connected'):
            messagebox.showerror("Error", f"Peer {peer_id} is not connected or does not exist.")
            return

        self.log(f"Attempting to send {os.path.basename(file_path)} to {peer_id}...")
        transfer_id = self.node.send_file(peer_id, file_path)

        if transfer_id:
            self.log(f"File transfer started to {peer_id}. ID: {transfer_id}")
            self.active_transfers[transfer_id] = {
                'peer_id': peer_id,
                'file_name': os.path.basename(file_path),
                'direction': 'sending'
            }
        else:
            self.log(f"Failed to start file transfer to {peer_id}.")
            messagebox.showerror("Transfer Error", f"Could not start file transfer to {peer_id}.")

    def send_message_gui(self):
        if not self.node: return
        peer_id = self.get_selected_peer_id()
        if not peer_id: return

        message = self.message_entry.get()
        if not message:
            messagebox.showwarning("Warning", "Message cannot be empty.")
            return

        if peer_id not in self.node.peers or not self.node.peers[peer_id].get('connected'):
            messagebox.showerror("Error", f"Peer {peer_id} is not connected or does not exist.")
            return

        if self.node.send_message(peer_id, message):
            self.log(f"Sent message to {peer_id}: {message}")
            self.message_entry.delete(0, tk.END)
        else:
            self.log(f"Failed to send message to {peer_id}.")
            messagebox.showerror("Message Error", f"Could not send message to {peer_id}.")

    def update_ui_status(self):
        if self.node and self.is_node_started:
            # Update connected peers list
            current_peers_in_listbox = set(self.peers_listbox.get(0, tk.END))
            actual_connected_peers = set()
            if self.node.peers:
                for pid, pdata in self.node.peers.items():
                    if pdata.get('connected'):
                        peer_display = f"{pid} ({pdata['addr'][0]}:{pdata['addr'][1]})"
                        actual_connected_peers.add(peer_display)
                        if peer_display not in current_peers_in_listbox:
                            self.peers_listbox.insert(tk.END, peer_display)

            # Remove disconnected peers from listbox
            for item in current_peers_in_listbox:
                if item not in actual_connected_peers:
                    try:
                        idx = self.peers_listbox.get(0, tk.END).index(item)
                        self.peers_listbox.delete(idx)
                    except ValueError:
                        pass  # Item already removed

            # Check for incoming messages
            while True:
                msg_data = self.node.get_next_incoming_message()
                if msg_data:
                    self.log(f"[MSG from {msg_data['peer_id']}]: {msg_data['message']}")
                else:
                    break  # No more messages in queue

            # Check active transfer statuses
            completed_transfers = []
            for transfer_id, transfer_info in list(self.active_transfers.items()):
                status = self.node.get_transfer_status(transfer_id)
                if status['status'] == 'unknown':
                    self.log(f"Transfer {transfer_id} ({transfer_info['file_name']}) status unknown or removed.")
                    completed_transfers.append(transfer_id)
                    continue

                # Log progress for active transfers (could be made more sophisticated)
                # For simplicity, only log significant changes or completion/failure.
                # A more complex GUI might have a dedicated transfer progress list.
                if status['status'] != transfer_info.get('last_logged_status') or \
                        abs(status['progress'] - transfer_info.get('last_logged_progress', -100)) > 10:
                    direction = "Sending" if transfer_info['direction'] == 'sending' else "Receiving"
                    self.log(
                        f"Transfer Update ({transfer_id}): {direction} {status['file_name']} to/from {transfer_info['peer_id']} - {status['progress']:.1f}% - {status['status']}")
                    transfer_info['last_logged_status'] = status['status']
                    transfer_info['last_logged_progress'] = status['progress']

                if status['status'] in ['completed', 'failed']:
                    if status['status'] == 'completed':
                        speed_kbps = status.get('speed', 0)
                        self.log(
                            f"Transfer {transfer_id} ({status['file_name']}) COMPLETED. Speed: {speed_kbps:.2f} KB/s")
                    else:
                        self.log(f"Transfer {transfer_id} ({status['file_name']}) FAILED.")
                    completed_transfers.append(transfer_id)

            for tid in completed_transfers:
                if tid in self.active_transfers:
                    del self.active_transfers[tid]

            # Check for incoming transfers not initiated by this GUI (i.e., receiving)
            if self.node.file_transfer:  # Check if file_transfer is initialized
                for transfer_id, tf_data in list(self.node.file_transfer.transfers.items()):
                    if transfer_id not in self.active_transfers and tf_data['direction'] == 'in':
                        if tf_data['status'] == 'receiving' or tf_data['status'] == 'pending':  # pending for init
                            self.log(
                                f"Detected incoming transfer {transfer_id}: {tf_data['file_name']} from {tf_data['peer_id']}")
                            self.active_transfers[transfer_id] = {
                                'peer_id': tf_data['peer_id'],
                                'file_name': tf_data['file_name'],
                                'direction': 'receiving',
                                'last_logged_status': tf_data['status'],
                                'last_logged_progress': 0
                            }

        # Schedule next update
        self.root.after(1000, self.update_ui_status)

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit? This will stop the P2P node."):
            if self.node:
                self.log("Stopping P2P node...")
                # Stop node in a thread to avoid GUI freeze if stop is slow
                threading.Thread(target=self.node.stop, daemon=True).start()
                # Give it a moment, though P2PNode.stop() should be quick
                time.sleep(0.5)
            self.root.destroy()

    def copy_connection_string(self):
        """Copy the connection string to clipboard"""
        if self.node and self.is_node_started:
            conn_string = f"connect {self.node.node_id} {self.node.external_ip} {self.node.external_port}"
            self.root.clipboard_clear()
            self.root.clipboard_append(conn_string)
            self.log("Connection string copied to clipboard")
        else:
            self.log("Node not started - nothing to copy")

    def quick_connect_peer(self):
        """Parse connection string and connect to the peer."""
        if not self.node:
            messagebox.showerror("Error", "Node not started.")
            return

        connection_string = self.connection_entry.get().strip()

        # Parse the connection string - format: "connect <peer_id> <peer_ip> <peer_port>"
        parts = connection_string.strip().split()
        if len(parts) != 4 or parts[0].lower() != "connect":
            messagebox.showerror("Error",
                                 "Invalid connection string format.\nShould be: connect <peer_id> <peer_ip> <peer_port>")
            return

        _, peer_id, peer_ip, peer_port_str = parts

        try:
            peer_port = int(peer_port_str)
        except ValueError:
            messagebox.showerror("Error", "Peer port must be a number.")
            return

        # Fill the manual fields (for user reference)
        self.peer_id_entry.delete(0, tk.END)
        self.peer_id_entry.insert(0, peer_id)

        self.peer_ip_entry.delete(0, tk.END)
        self.peer_ip_entry.insert(0, peer_ip)

        self.peer_port_entry.delete(0, tk.END)
        self.peer_port_entry.insert(0, peer_port_str)

        # Start connection
        self.log(f"Quick connecting to {peer_id} at {peer_ip}:{peer_port}...")

        if self.node.connect_to_peer(peer_id, peer_ip, peer_port):
            self.log(f"Connection attempt to {peer_id} initiated. Check peer list for status.")
            # Clear the connection string for next use
            self.connection_entry.delete(0, tk.END)
            self.connection_entry.insert(0, "connect <peer_id> <peer_ip> <peer_port>")
        else:
            self.log(f"Failed to initiate connection to {peer_id}.")
            messagebox.showerror("Connection Error", f"Could not initiate connection to {peer_id}.")

if __name__ == "__main__":
    root = tk.Tk()
    app = P2PGUI(root)
    root.mainloop()