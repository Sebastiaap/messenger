import socket
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox

PORT = 5009

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

        self.username = simpledialog.askstring("Username", "Enter your name:")
        self.mode = messagebox.askquestion("Mode", "Host chat?\nYes = Host | No = Join")

        self.peers = []

        if self.mode == "yes":
            self.start_host()
        else:
            self.start_client()

    def log(self, msg):
        self.chat.config(state="normal")
        self.chat.insert(tk.END, msg + "\n")
        self.chat.yview(tk.END)
        self.chat.config(state="disabled")

    # ---------- HOST ----------
    def start_host(self):
        self.log("Hosting chat...")
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("0.0.0.0", PORT))
        self.server.listen()

        threading.Thread(target=self.accept_peers, daemon=True).start()

    def accept_peers(self):
        while True:
            conn, addr = self.server.accept()
            self.peers.append(conn)
            threading.Thread(target=self.handle_peer, args=(conn,), daemon=True).start()

    def handle_peer(self, conn):
        name = conn.recv(1024).decode()
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

    # ---------- CLIENT ----------
    def start_client(self):
        host_ip = simpledialog.askstring("Connect", "Enter host IP:")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host_ip, PORT))
        self.sock.sendall(self.username.encode())

        threading.Thread(target=self.receive_messages, daemon=True).start()

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

        if self.mode == "yes":
            self.broadcast(f"{self.username}: {msg}")
        else:
            self.sock.sendall(msg.encode())

root = tk.Tk()
ChatApp(root)
root.mainloop()
