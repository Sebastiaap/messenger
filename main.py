import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import time

CHAT_PORT = 5009
CONNECTION_TIMEOUT = 1.5
RECONNECT_INTERVAL = 3  # seconds

# Your updated CONTACTS list
CONTACTS = {
    "192.168.212.4": "Sebastiaan",
    "192.168.213.177": "Thomas",
    "192.168.212.140": "Tom",
    "192.168.213.131": "Jasper",
    "192.168.213.13": "Tijmen"
}

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.chat = scrolledtext.ScrolledText(root, state="disabled", width=60, height=20)
        self.chat.pack(padx=10, pady=10)

        self.entry = tk.Entry(root, width=50)
        self.entry.pack(side=tk.LEFT, padx=(10, 0), pady=10)
        self.entry.bind("<Return>", self.send_message)

        tk.Button(root, text="Send", command=self.send_message).pack(side=tk.LEFT, padx=10)

        self.ip = self.get_local_ip()
        self.name = CONTACTS.get(self.ip, self.ip)

        # Peers: list of dicts: {"conn": socket, "name": str, "ip": str}
        self.peers = []
        self.peers_lock = threading.Lock()

        self.safe_log(f"You are {self.name} ({self.ip})")

        self.update_title()

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

    def log(self, msg):
        self.chat.config(state="normal")
        self.chat.insert(tk.END, msg + "\n")
        self.chat.yview(tk.END)
        self.chat.config(state="disabled")

    def safe_log(self, msg):
        self.root.after(0, self.log, msg)

    def update_title(self):
        self.root.title(f"P2P Mesh Chat — You: {self.name}")

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
        self.safe_log(f"{peer_name} ({peer_ip}) connected")

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
            self.safe_log(f"{removed_peer['name']} ({removed_peer['ip']}) disconnected")

    # ------------------- SERVER SIDE -------------------
    def accept_peers(self):
        while True:
            try:
                conn, addr = self.server.accept()
                peer_ip = addr[0]

                try:
                    peer_name = conn.recv(1024).decode()
                    if not peer_name:
                        conn.close()
                        continue
                    conn.sendall(self.name.encode())
                except:
                    conn.close()
                    continue

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

                # NUMERIC IP comparison
                if self.ip_to_tuple(ip) <= self.ip_to_tuple(self.ip):
                    continue

                if self.is_connected_to_ip(ip):
                    continue

                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(CONNECTION_TIMEOUT)
                    sock.connect((ip, CHAT_PORT))

                    sock.sendall(self.name.encode())
                    peer_name = sock.recv(1024).decode()
                    if not peer_name:
                        sock.close()
                        continue

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
        while True:
            try:
                msg = conn.recv(1024).decode()
                if not msg:
                    break
                self.safe_log(msg)
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

        formatted = f"{self.name}: {msg}"

        self.safe_log(formatted)

        with self.peers_lock:
            dead_conns = []
            for p in self.peers:
                conn = p["conn"]
                try:
                    conn.sendall(formatted.encode())
                except:
                    dead_conns.append(conn)

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
