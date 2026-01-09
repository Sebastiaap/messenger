import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

CHAT_PORT = 5009
TIMEOUT = 1.5

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
        self.chat = scrolledtext.ScrolledText(root, state="disabled", width=60, height=20)
        self.chat.pack(padx=10, pady=10)

        self.entry = tk.Entry(root, width=50)
        self.entry.pack(side=tk.LEFT, padx=(10, 0), pady=10)
        self.entry.bind("<Return>", self.send_message)

        tk.Button(root, text="Send", command=self.send_message).pack(side=tk.LEFT, padx=10)

        self.ip = self.get_local_ip()
        self.name = CONTACTS.get(self.ip, self.ip)

        self.is_host = False
        self.sock = None
        self.peers = []

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
        for ip in CONTACTS:
            if ip == self.ip:
                continue
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(TIMEOUT)
                sock.connect((ip, CHAT_PORT))
                sock.sendall(self.name.encode())

                self.sock = sock
                threading.Thread(target=self.receive_messages, daemon=True).start()
                self.root.title(f"P2P Chat — Host: {CONTACTS[ip]}")
                return True
            except:
                continue
        return False

    # ---------- HOST ----------
    def start_host(self):
        self.is_host = True
        self.root.title(f"P2P Chat — Host: You ({self.name})")

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", CHAT_PORT))
        server.listen()

        threading.Thread(target=self.accept_peers, args=(server,), daemon=True).start()
        self.safe_log("Hosting chat")

    def accept_peers(self, server):
        while True:
            conn, addr = server.accept()
            name = conn.recv(1024).decode()
            self.peers.append(conn)

            self.broadcast(f"{name} joined the chat")
            threading.Thread(target=self.handle_peer, args=(conn, name), daemon=True).start()

    def handle_peer(self, conn, name):
        while True:
            try:
                msg = conn.recv(1024).decode()
                if not msg:
                    break
                self.broadcast(f"{name}: {msg}")
            except:
                break

        self.peers.remove(conn)
        self.broadcast(f"{name} left the chat")
        conn.close()

    def broadcast(self, msg):
        self.safe_log(msg)
        for peer in self.peers:
            try:
                peer.sendall(msg.encode())
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
