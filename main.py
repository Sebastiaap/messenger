import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import uuid
import time

CHAT_PORT = 5009
BUFFER_SIZE = 1024

# 🧾 CONTACT LIST: IP → NAME
CONTACTS = {
    "192.168.212.4": "Sebastiaan",
    "192.168.213.177": "Thomas",
    "192.168.212.140": "Tom",
    "192.168.213.131": "Jasper"
}

class Peer:
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
        self.connections = []  # list of (socket, peer_name)
        self.message_history = set()  # store message IDs to avoid duplicates

        self.safe_log(f"You are {self.name} ({self.ip})")

        # Start listening thread
        threading.Thread(target=self.listen, daemon=True).start()
        # Connect to known peers
        threading.Thread(target=self.connect_to_peers, daemon=True).start()

    # ---------------- UTIL ----------------
    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except:
            return "127.0.0.1"
        finally:
            s.close()

    def safe_log(self, msg):
        self.root.after(0, self.log, msg)

    def log(self, msg):
        self.chat.config(state="normal")
        self.chat.insert(tk.END, msg + "\n")
        self.chat.yview(tk.END)
        self.chat.config(state="disabled")

    # ---------------- LISTEN AS HOST ----------------
    def listen(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", CHAT_PORT))
        server.listen()
        while True:
            conn, addr = server.accept()
            threading.Thread(target=self.handle_connection, args=(conn,), daemon=True).start()

    def handle_connection(self, conn):
        try:
            peer_name = conn.recv(BUFFER_SIZE).decode()
            if not peer_name:
                conn.close()
                return
            # Add to connections if not already
            if (conn, peer_name) not in self.connections:
                self.connections.append((conn, peer_name))
            # Send our name to the peer
            conn.sendall(self.name.encode())

            while True:
                data = conn.recv(BUFFER_SIZE)
                if not data:
                    break
                self.process_message(data.decode(), conn)
        except:
            pass
        # remove connection when done
        self.connections = [c for c in self.connections if c[0] != conn]
        conn.close()

    # ---------------- CONNECT TO PEERS ----------------
    def connect_to_peers(self):
        time.sleep(1)  # short delay to let server start
        for ip, peer_name in CONTACTS.items():
            if ip == self.ip:
                continue
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, CHAT_PORT))
                sock.sendall(self.name.encode())
                remote_name = sock.recv(BUFFER_SIZE).decode()
                self.connections.append((sock, remote_name))
                threading.Thread(target=self.handle_connection, args=(sock,), daemon=True).start()
                self.safe_log(f"Connected to {remote_name}")
            except:
                continue

    # ---------------- SEND MESSAGE ----------------
    def send_message(self, event=None):
        msg_text = self.entry.get().strip()
        if not msg_text:
            return
        self.entry.delete(0, tk.END)
        message_id = str(uuid.uuid4())
        msg = f"{message_id}|{self.name}: {msg_text}"
        self.process_message(msg, None)  # display locally
        self.broadcast(msg, exclude=None)

    # ---------------- PROCESS MESSAGE ----------------
    def process_message(self, msg, sender_conn):
        msg_id, text = msg.split("|", 1)
        if msg_id in self.message_history:
            return  # already processed
        self.message_history.add(msg_id)
        self.safe_log(text)
        self.broadcast(msg, exclude=sender_conn)

    # ---------------- BROADCAST ----------------
    def broadcast(self, msg, exclude):
        for conn, _ in self.connections:
            if conn == exclude:
                continue
            try:
                conn.sendall(msg.encode())
            except:
                pass

if __name__ == "__main__":
    root = tk.Tk()
    root.title("P2P LAN Chat")
    Peer(root)
    root.mainloop()