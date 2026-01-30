import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import time
import json
import base64
from datetime import datetime

CHAT_PORT = 5009
CONNECTION_TIMEOUT = 1.5
RECONNECT_INTERVAL = 3  # seconds
ENCRYPTION_KEY = "0a6yekzSSM2Mi4tjiJ2HVsld5jzp1EMhay9t/SYxlws="  # Shared secret key for encryption

# Your CONTACTS list
CONTACTS = {
    "192.168.212.41": "Sebastiaan",
    "192.168.213.177": "Thomas",
    "192.168.212.140": "Tom",
    "192.168.213.174": "Jasper",
    "192.168.213.13": "Tijmen",
    "192.168.212.53": "Rowan"
}

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.geometry("900x600")
        
        # Main Layout
        self.paned = tk.PanedWindow(root, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        self.paned.pack(fill=tk.BOTH, expand=True)

        # Left Sidebar (Chat List)
        self.left_frame = tk.Frame(self.paned, width=200)
        self.paned.add(self.left_frame)
        
        self.lbl_chats = tk.Label(self.left_frame, text="Chats", font=("Arial", 12, "bold"))
        self.lbl_chats.pack(pady=5)
        
        self.chat_list = tk.Listbox(self.left_frame, font=("Arial", 10))
        self.chat_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.chat_list.bind("<<ListboxSelect>>", self.on_chat_select)

        # Right Side (Conversation)
        self.right_frame = tk.Frame(self.paned)
        self.paned.add(self.right_frame)

        self.lbl_current_chat = tk.Label(self.right_frame, text="Global Chat", font=("Arial", 12, "bold"))
        self.lbl_current_chat.pack(pady=5)

        self.chat_display = scrolledtext.ScrolledText(self.right_frame, state="disabled", width=60, height=20, font=("Arial", 10))
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self.input_frame = tk.Frame(self.right_frame)
        self.input_frame.pack(fill=tk.X, padx=10, pady=10)

        self.entry = tk.Entry(self.input_frame, font=("Arial", 10))
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.entry.bind("<Return>", self.send_message)

        self.btn_send = tk.Button(self.input_frame, text="Send", command=self.send_message)
        self.btn_send.pack(side=tk.LEFT, padx=(10, 0))

        # Network & Data
        self.ip = self.get_local_ip()
        self.name = CONTACTS.get(self.ip, self.ip)

        self.peers = []
        self.peers_lock = threading.Lock()
        
        # Chat History: "Global" -> list of lines, IP -> list of lines
        self.histories = {"Global": []}
        self.current_chat_id = "Global" # "Global" or Peer IP
        
        self.chat_list.insert(tk.END, "Global Chat")
        self.chat_list.selection_set(0)

        self.update_title()
        self.safe_log("Global", f"You are {self.name} ({self.ip})")

        # Start server (everyone hosts)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("0.0.0.0", CHAT_PORT))
        self.server.listen()

        threading.Thread(target=self.accept_peers, daemon=True).start()
        threading.Thread(target=self.connect_to_peers_loop, daemon=True).start()

    # ------------------- UTIL -------------------
    def ip_to_tuple(self, ip):
        return tuple(int(part) for part in ip.split("."))

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except:
            return "127.0.0.1"
        finally:
            s.close()

    def timestamp(self):
        now = datetime.now()
        return now.strftime("[%H:%M:%S]")

    def log(self, chat_id, msg):
        if chat_id not in self.histories:
            self.histories[chat_id] = []
        self.histories[chat_id].append(msg)
        
        if self.current_chat_id == chat_id:
            self.chat_display.config(state="normal")
            self.chat_display.insert(tk.END, msg + "\n")
            self.chat_display.yview(tk.END)
            self.chat_display.config(state="disabled")

    def safe_log(self, chat_id, msg):
        self.root.after(0, self.log, chat_id, msg)

    def update_title(self):
        self.root.title(f"P2P Mesh Chat — You: {self.name}")

    def on_chat_select(self, event):
        selection = self.chat_list.curselection()
        if not selection:
            return
        
        index = selection[0]
        label = self.chat_list.get(index)
        
        if label == "Global Chat":
            new_id = "Global"
        else:
            # Extract IP from "Name (IP)"
            try:
                new_id = label.split("(")[-1].strip(")")
            except:
                new_id = "Global"

        self.current_chat_id = new_id
        self.lbl_current_chat.config(text=label)
        self.refresh_chat_display()

    def refresh_chat_display(self):
        self.chat_display.config(state="normal")
        self.chat_display.delete(1.0, tk.END)
        lines = self.histories.get(self.current_chat_id, [])
        for line in lines:
            self.chat_display.insert(tk.END, line + "\n")
        self.chat_display.yview(tk.END)
        self.chat_display.config(state="disabled")

    # ------------------- ENCRYPTION -------------------
    def encrypt_data(self, data_str):
        # Simple XOR encryption on bytes + Base64
        key_bytes = ENCRYPTION_KEY.encode('utf-8')
        data_bytes = data_str.encode('utf-8')
        encrypted = bytearray()
        for i, b in enumerate(data_bytes):
            encrypted.append(b ^ key_bytes[i % len(key_bytes)])
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_data(self, data_b64):
        try:
            encrypted_bytes = base64.b64decode(data_b64)
            key_bytes = ENCRYPTION_KEY.encode('utf-8')
            decrypted = bytearray()
            for i, b in enumerate(encrypted_bytes):
                decrypted.append(b ^ key_bytes[i % len(key_bytes)])
            return decrypted.decode('utf-8')
        except Exception:
            return None

    # ------------------- JSON SEND/RECEIVE -------------------
    def send_json(self, conn, obj):
        json_str = json.dumps(obj)
        encrypted_str = self.encrypt_data(json_str)
        data = encrypted_str + "\n"
        conn.sendall(data.encode())

    def recv_json(self, conn):
        buffer = ""
        while "\n" not in buffer:
            chunk = conn.recv(1024).decode()
            if not chunk:
                return None
            buffer += chunk
        line, _ = buffer.split("\n", 1)
        
        decrypted_str = self.decrypt_data(line)
        if not decrypted_str:
            return None
            
        return json.loads(decrypted_str)

    # ------------------- PEER MANAGEMENT -------------------
    def is_connected_to_ip(self, ip):
        with self.peers_lock:
            for p in self.peers:
                if p["ip"] == ip:
                    return True
        return False

    def add_peer(self, conn, peer_name, peer_ip):
        with self.peers_lock:
            for p in self.peers:
                if p["ip"] == peer_ip:
                    try:
                        conn.close()
                    except:
                        pass
                    return
            self.peers.append({"conn": conn, "name": peer_name, "ip": peer_ip})

        self.root.after(0, lambda: self.chat_list.insert(tk.END, f"{peer_name} ({peer_ip})"))
        self.safe_log("Global", f"{self.timestamp()} {peer_name} ({peer_ip}) connected")

    def remove_peer(self, conn):
        removed_peer = None
        with self.peers_lock:
            new_peers = []
            for p in self.peers:
                if p["conn"] is conn:
                    removed_peer = p
                else:
                    new_peers.append(p)
            self.peers = new_peers

        if removed_peer:
            self.safe_log("Global", f"{self.timestamp()} {removed_peer['name']} ({removed_peer['ip']}) disconnected")
            self.root.after(0, self.remove_peer_from_list, removed_peer['ip'])

    def remove_peer_from_list(self, ip):
        count = self.chat_list.size()
        for i in range(count):
            text = self.chat_list.get(i)
            if f"({ip})" in text:
                self.chat_list.delete(i)
                break
        if self.current_chat_id == ip:
            self.current_chat_id = "Global"
            self.lbl_current_chat.config(text="Global Chat")
            self.refresh_chat_display()

    # ------------------- SERVER SIDE -------------------
    def accept_peers(self):
        while True:
            try:
                conn, addr = self.server.accept()
                peer_ip = addr[0]

                peer_info = self.recv_json(conn)
                if not peer_info:
                    conn.close()
                    continue

                self.send_json(conn, {"name": self.name, "ip": self.ip, "version": 1})
                conn.settimeout(None)
                peer_name = peer_info["name"]

                self.add_peer(conn, peer_name, peer_ip)

                threading.Thread(
                    target=self.handle_peer,
                    args=(conn, peer_name, peer_ip),
                    daemon=True
                ).start()
            except:
                break

    # ------------------- CLIENT SIDE (OUTGOING CONNECTIONS) -------------------
    def connect_to_peers_loop(self):
        while True:
            for ip, display_name in CONTACTS.items():
                if ip == self.ip:
                    continue

                if self.ip_to_tuple(self.ip) >= self.ip_to_tuple(ip):
                    continue

                if self.is_connected_to_ip(ip):
                    continue

                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(CONNECTION_TIMEOUT)
                    sock.connect((ip, CHAT_PORT))

                    self.send_json(sock, {"name": self.name, "ip": self.ip, "version": 1})
                    peer_info = self.recv_json(sock)
                    if not peer_info:
                        sock.close()
                        continue

                    sock.settimeout(None)
                    peer_name = peer_info["name"]

                    self.add_peer(sock, peer_name, ip)

                    threading.Thread(
                        target=self.handle_peer,
                        args=(sock, peer_name, ip),
                        daemon=True
                    ).start()
                except:
                    try:
                        sock.close()
                    except:
                        pass
                    continue

            time.sleep(RECONNECT_INTERVAL)

    # ------------------- PER-PEER RECEIVE -------------------
    def handle_peer(self, conn, peer_name, peer_ip):
        buffer = ""
        while True:
            try:
                chunk = conn.recv(1024).decode()
                if not chunk:
                    break
                buffer += chunk
                
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if not line.strip():
                        continue
                    
                    decrypted_line = self.decrypt_data(line)
                    if not decrypted_line:
                        # Could not decrypt, maybe garbage or unencrypted?
                        continue

                    try:
                        data = json.loads(decrypted_line)
                    except:
                        continue
                        
                    if data.get("type") == "msg":
                        text = data.get("text", "")
                        sender_name = data.get("from_name", peer_name)
                        ts = data.get("timestamp", self.timestamp())
                        target = data.get("target", "Global")
                        
                        formatted = f"{ts} {sender_name}: {text}"
                        
                        if target == "Global":
                            self.safe_log("Global", formatted)
                        elif target == self.ip:
                            self.safe_log(peer_ip, formatted)
            except:
                break

        self.remove_peer(conn)
        try:
            conn.close()
        except:
            pass

    # ------------------- SEND MESSAGE -------------------
    def send_message(self, event=None):
        msg = self.entry.get().strip()
        if not msg:
            return
        self.entry.delete(0, tk.END)

        timestamp = self.timestamp()
        formatted_local = f"{timestamp} You: {msg}"
        self.safe_log(self.current_chat_id, formatted_local)

        payload = {
            "type": "msg",
            "from_name": self.name,
            "from_ip": self.ip,
            "text": msg,
            "timestamp": timestamp,
            "target": self.current_chat_id
        }
        
        with self.peers_lock:
            dead_conns = []
            if self.current_chat_id == "Global":
                for p in self.peers:
                    try:
                        self.send_json(p["conn"], payload)
                    except:
                        dead_conns.append(p["conn"])
            else:
                for p in self.peers:
                    if p["ip"] == self.current_chat_id:
                        try:
                            self.send_json(p["conn"], payload)
                        except:
                            dead_conns.append(p["conn"])
                        break

        for conn in dead_conns:
            self.remove_peer(conn)
            try:
                conn.close()
            except:
                pass

# ------------------- RUN -------------------
if __name__ == "__main__":
    root = tk.Tk()
    ChatApp(root)
    root.mainloop()
