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
    "": ""
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

        self.peers = []
        self.sock = None
        self.is_host = False
        self.host_name = None

        self.log(f"You are {self.name} ({self.ip})")

        if not self.try_join():
            self.start_host()

    # ---------- UTILS ----------
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

    def update_title(self):
        if self.is_host:
            self.root.title(f"P2P Chat — Host: You ({self.name})")
        else:
            self.root.title(f"P2P Chat — Host: {self.host_name}")

    # ---------- JOIN ----------
    def try_join(self):
        for ip, peer_name in CONTACTS.items():
            if ip == self.ip:
                continue
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(TIMEOUT)
                sock.connect((ip, CHAT_PORT))

                self.sock = sock
                self.sock.sendall(self.name.encode())

                # receive host name
                self.host_name = self.sock.recv(1024).decode()
                self.update_title()

                self.log(f"Connected to host {self.host_name}")
                threading.Thread(target=self.receive_messages, daemon=True).start()
                return True
            except:
                continue
        return False

    # ---------- HOST ----------
    def start_host(self):
        self.is_host = True
        self.host_name = self.name
        self.update_title()

        self.log("No host found — hosting chat")

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("0.0.0.0", CHAT_PORT))
        self.server.listen()

        threading.Thread(target=self.accept_peers, daemon=True).start()

    def accept_peers(self):
        while True:
            conn, addr = self.server.accept()
            ip = addr[0]

            if ip not in CONTACTS:
                conn.close()
                continue

            self.peers.append(conn)
            threading.Thread(target=self.handle_peer, args=(conn,), daemon=True).start()

    def handle_peer(self, conn):
        name = conn.recv(1024).decode()

        # send host name back
        conn.sendall(self.name.encode())

        self.broadcast(f"{name} joined the chat")

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
        self.log(msg)
        for peer in self.peers:
            try:
                peer.sendall(msg.encode())
            except:
                pass

    # ---------- RECEIVE ----------
    def receive_messages(self):
        while True:
            try:
                msg = self.sock.recv(1024).decode()
                if not msg:
                    break
                self.log(msg)
            except:
                break

    # ---------- SEND ----------
    def send_message(self, event=None):
        msg = self.entry.get()
        if not msg.strip():
            return
        self.entry.delete(0, tk.END)

        # show your own message immediately
        self.log(f"{self.name}: {msg}")

        if self.is_host:
            # already logged, just send to others
            for peer in self.peers:
                try:
                    peer.sendall(f"{self.name}: {msg}".encode())
                except:
                    pass
        else:
            self.sock.sendall(msg.encode())


root = tk.Tk()
ChatApp(root)
root.mainloop()