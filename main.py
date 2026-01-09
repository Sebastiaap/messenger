import socket
import threading
import tkinter as tk
from tkinter import scrolledtext

CHAT_PORT = 5009
CONNECTION_TIMEOUT = 1.5

# IP → Name mapping (optional, only for display)
CONTACTS = {
    "192.168.212.4": "Sebastiaan",
    "192.168.213.177": "Thomas",
    "192.168.212.140": "Tom",
    "192.168.213.131": "Jasper"
}

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.chat = scrolledtext.ScrolledText(root, state="disabled", width=60, height=20)
        self.chat.pack(padx=10, pady=10)

        self.entry = tk.Entry(root, width=50)
        self.entry.pack(side=tk.LEFT, padx=(10,0), pady=10)
        self.entry.bind("<Return>", self.send_message)

        tk.Button(root, text="Send", command=self.send_message).pack(side=tk.LEFT, padx=10)

        self.ip = self.get_local_ip()
        self.name = CONTACTS.get(self.ip, self.ip)

        self.sock = None
        self.server = None
        self.peers = []
        self.is_host = False
        self.host_name = None

        self.safe_log(f"You are {self.name} ({self.ip})")

        # Try to join an existing host
        if not self.try_join():
            self.start_host()

    # ------------------- UTIL -------------------
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
        if self.is_host:
            self.root.title(f"P2P Chat — Host: You ({self.name})")
        else:
            self.root.title(f"P2P Chat — Host: {self.host_name}")

    # ------------------- CLIENT -------------------
    def try_join(self):
        for ip, peer_name in CONTACTS.items():
            if ip == self.ip:
                continue
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(CONNECTION_TIMEOUT)
                sock.connect((ip, CHAT_PORT))

                self.sock = sock
                self.sock.sendall(self.name.encode())
                self.host_name = self.sock.recv(1024).decode()
                self.update_title()

                threading.Thread(target=self.receive_messages, daemon=True).start()
                self.safe_log(f"Connected to host {self.host_name}")
                return True
            except:
                continue
        return False

    def receive_messages(self):
        while True:
            try:
                msg = self.sock.recv(1024).decode()
                if not msg:
                    break
                self.safe_log(msg)
            except:
                break

    # ------------------- HOST -------------------
    def start_host(self):
        self.is_host = True
        self.host_name = self.name
        self.update_title()
        self.safe_log("No host found — hosting chat")

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("0.0.0.0", CHAT_PORT))
        self.server.listen()
        threading.Thread(target=self.accept_peers, daemon=True).start()

    def accept_peers(self):
        while True:
            conn, addr = self.server.accept()

            try:
                client_name = conn.recv(1024).decode()
                conn.sendall(self.name.encode())
            except:
                conn.close()
                continue

            self.peers.append((conn, client_name))

            # Send welcome message to the new client
            conn.sendall(f"Welcome {client_name}! Connected to host {self.name}.\n".encode())

            self.broadcast(f"{client_name} joined the chat")

            threading.Thread(target=self.handle_peer, args=(conn, client_name), daemon=True).start()

    def handle_peer(self, conn, client_name):
        while True:
            try:
                msg = conn.recv(1024).decode()
                if not msg:
                    break
                self.broadcast(f"{client_name}: {msg}")
            except:
                break

        self.peers = [p for p in self.peers if p[0] != conn]
        self.broadcast(f"{client_name} left the chat")
        conn.close()

    # ------------------- BROADCAST -------------------
    def broadcast(self, msg):
        self.safe_log(msg)
        for conn, _ in self.peers:
            try:
                conn.sendall(msg.encode())
            except:
                pass

    # ------------------- SEND MESSAGE -------------------
    def send_message(self, event=None):
        msg = self.entry.get().strip()
        if not msg:
            return
        self.entry.delete(0, tk.END)

        if self.is_host:
            self.broadcast(f"{self.name}: {msg}")
        else:
            try:
                self.sock.sendall(msg.encode())
            except:
                self.safe_log("Failed to send message")

# ------------------- RUN -------------------
if __name__ == "__main__":
    root = tk.Tk()
    ChatApp(root)
    root.mainloop()
