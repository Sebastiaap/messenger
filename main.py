import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

CHAT_PORT = 5009
TIMEOUT = 2.0

# 🧾 CONTACT LIST: IP → NAME
CONTACTS = {
    "192.168.212.4": "Sebastiaan",
    "192.168.213.177": "Thomas",
    "192.168.212.140": "Tom",
    "192.168.213.131": "Jasper"
}

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P Chat")

        self.chat = scrolledtext.ScrolledText(root, state="disabled", width=60, height=20)
        self.chat.pack(padx=10, pady=10)

        self.entry = tk.Entry(root, width=50)
        self.entry.pack(side=tk.LEFT, padx=(10, 0), pady=10)
        self.entry.bind("<Return>", self.send_message)

        tk.Button(root, text="Send", command=self.send_message).pack(side=tk.LEFT, padx=10)

        self.ip = self.get_local_ip()
        self.name = CONTACTS.get(self.ip, self.ip)

        self.sock = None
        self.peers = []
        self.is_host = False

        self.safe_log(f"You are {self.name} ({self.ip})")

        if not self.try_join():
            self.start_host()

    # ---------- UTIL ----------
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

    # ---------- JOIN ----------
    def try_join(self):
        for ip, host_name in CONTACTS.items():
            if ip == self.ip:
                continue
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(TIMEOUT)
                sock.connect((ip, CHAT_PORT))

                # send our name
                sock.sendall(self.name.encode())

                self.sock = sock
                self.root.title(f"P2P Chat — Host: {host_name}")
                threading.Thread(target=self.receive_messages, daemon=True).start()
                return True
            except:
                continue
        return False

    # ---------- HOST ----------
    def start_host(self):
        self.is_host = True
        self.root.title(f"P2P Chat — Host: You ({self.name})")
        self.safe_log("Hosting chat")

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", CHAT_PORT))
        server.listen()

        threading.Thread(target=self.accept_peers, args=(server,), daemon=True).start()

    def accept_peers(self, server):
        while True:
            conn, addr = server.accept()
            peer_name = conn.recv(1024).decode()
            self.peers.append((conn, peer_name))

            self.broadcast(f"{peer_name} joined the chat")
            threading.Thread(target=self.handle_peer, args=(conn, peer_name), daemon=True).start()

    def handle_peer(self, conn, peer_name):
        while True:
            try:
                msg = conn.recv(1024).decode()
                if not msg:
                    break
                self.broadcast(f"{peer_name}: {msg}")
            except:
                break

        self.peers = [p for p in self.peers if p[0] != conn]
        self.broadcast(f"{peer_name} left the chat")
        conn.close()

    def broadcast(self, msg):
        self.safe_log(msg)
        for conn, _ in self.peers:
            try:
                conn.sendall(msg.encode())
            except:
                pass

    # ---------- CLIENT RECEIVE ----------
    def receive_messages(self):
        while True:
            try:
                msg = self.sock.recv(1024).decode()
                if not msg:
                    break
                self.safe_log(msg)
            except:
                break

    # ---------- SEND ----------
    def send_message(self, event=None):
        msg = self.entry.get()
        if not msg.strip():
            return
        self.entry.delete(0, tk.END)

        if self.is_host:
            self.broadcast(f"{self.name}: {msg}")
        else:
            self.sock.sendall(msg.encode())

root = tk.Tk()
ChatApp(root)
root.mainloop()