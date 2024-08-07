import socket
import threading
from dnslib import DNSRecord
import json
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import base64

DNS_SERVER = "212.227.26.128"
DNS_PORT = 5353

def encode_data(data):
    encoded_bytes = base64.urlsafe_b64encode(data.encode('utf-8'))
    return str(encoded_bytes, 'utf-8')

def decode_data(data):
    decoded_bytes = base64.urlsafe_b64decode(data.encode('utf-8'))
    return str(decoded_bytes, 'utf-8')

class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("DNS Chat Client")
        self.master.geometry("600x400")
        self.master.configure(bg='#2b2b2b')

        self.username = ""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))

        self.create_widgets()

    def create_widgets(self):
        self.login_frame = ttk.Frame(self.master, padding="10")
        self.login_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(self.login_frame, text="Username:").grid(row=0, column=0, sticky=tk.W)
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))

        ttk.Button(self.login_frame, text="Login", command=self.login).grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E))

        self.chat_frame = ttk.Frame(self.master, padding="10")

        self.message_area = scrolledtext.ScrolledText(self.chat_frame, state='disabled', wrap=tk.WORD, bg='#3c3f41', fg='white')
        self.message_area.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.message_entry = ttk.Entry(self.chat_frame)
        self.message_entry.grid(row=1, column=0, sticky=(tk.W, tk.E))

        self.send_button = ttk.Button(self.chat_frame, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=1, sticky=(tk.W, tk.E))

        self.chat_frame.grid_columnconfigure(0, weight=1)
        self.chat_frame.grid_rowconfigure(0, weight=1)

    def login(self):
        username = self.username_entry.get()
        self.username = username
        self.send_dns_request(json.dumps({'username': username}))
        self.login_frame.grid_remove()
        self.chat_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_rowconfigure(0, weight=1)
        threading.Thread(target=self.listen_for_messages, daemon=True).start()

    def send_message(self):
        message = self.message_entry.get()
        if not message:
            return
        if len(message) > 63:
            messagebox.showerror("Error", "Message too long (max 63 characters)")
            return

        data = json.dumps({'username': self.username, 'message': message})
        encoded_data = encode_data(data)
        self.send_dns_request(encoded_data)
        self.message_entry.delete(0, tk.END)
        self.add_message(f"You: {message}")

    def send_dns_request(self, data):
        if not data or len(data) > 63:
            messagebox.showerror("Error", "Data too long or empty for DNS label")
            return
        
        qname = f"{data}.bylife.fr"
        try:
            query = DNSRecord.question(qname)
            self.sock.sendto(query.pack(), (DNS_SERVER, DNS_PORT))
        except UnicodeError as e:
            messagebox.showerror("Unicode Error", f"Failed to create DNS request: {e}")

    def listen_for_messages(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(512)
                response = DNSRecord.parse(data)
                message_data = str(response.q.qname).split('.')[0]
                decoded_message = decode_data(message_data)
                message_json = json.loads(decoded_message)
                if 'sender' in message_json and 'message' in message_json:
                    sender = message_json['sender']
                    message = message_json['message']
                    self.add_message(f"{sender}: {message}")
                else:
                    print(f"Invalid message format: {message_json}")
            except Exception as e:
                print(f"Error receiving message: {e}")

    def add_message(self, message):
        self.message_area.configure(state='normal')
        self.message_area.insert(tk.END, message + '\n')
        self.message_area.configure(state='disabled')
        self.message_area.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()
