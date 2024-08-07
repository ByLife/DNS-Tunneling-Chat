import socket
from dnslib import DNSRecord, QTYPE, RR, A, DNSHeader, DNSQuestion
import sqlite3
import rsa
import base64
import json

DNS_IP = '0.0.0.0'
DNS_PORT = 5353

# Initialize RSA keys
with open('server_private_key.pem', 'rb') as f:
    PRIVATE_KEY = rsa.PrivateKey.load_pkcs1(f.read())

with open('public_key.pem', 'rb') as f:
    PUBLIC_KEY = rsa.PublicKey.load_pkcs1(f.read())

# Database setup
conn = sqlite3.connect('chat.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
''')
cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        content TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
''')
conn.commit()

clients = {}

def encrypt_message(message):
    return base64.b64encode(rsa.encrypt(message.encode(), PUBLIC_KEY)).decode()

def decrypt_message(encrypted_message):
    return rsa.decrypt(base64.b64decode(encrypted_message), PRIVATE_KEY).decode()

def handle_request(data, addr, sock):
    global clients
    request = DNSRecord.parse(data)
    qname = str(request.q.qname)
    qtype = QTYPE[request.q.qtype]
    encrypted_message = qname.split('.')[0]

    try:
        decrypted_message = decrypt_message(encrypted_message)
        message_data = json.loads(decrypted_message)
        username = message_data['username']
        message = message_data['message']
        
        print(f"Received DNS request for {qname} ({qtype}) from {addr}")
        print(f"Decrypted message: {message} from user: {username}")

        # Store message in database
        cursor.execute('INSERT INTO messages (sender, content) VALUES (?, ?)', (username, message))
        conn.commit()

        # Register the client
        clients[addr] = username

        # Send message to other clients
        for client_addr in clients:
            if client_addr != addr:
                reply_message = json.dumps({'sender': username, 'message': message})
                encrypted_reply = encrypt_message(reply_message)
                qname_reply = f"{encrypted_reply}.bylife.fr"
                reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=DNSQuestion(qname_reply))
                reply.add_answer(RR(qname_reply, QTYPE.A, rdata=A("212.227.26.128"), ttl=60))
                sock.sendto(reply.pack(), client_addr)
                print(f"Sent message to {client_addr}: {reply_message}")

        if qtype == "A":
            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("212.227.26.128"), ttl=60))
            sock.sendto(reply.pack(), addr)
            print(f"Sent response to {addr}")

    except Exception as e:
        print(f"Error processing message: {e}")

def authenticate_user(username, password):
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    return cursor.fetchone() is not None

def register_user(username, password):
    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((DNS_IP, DNS_PORT))

print(f"DNS server listening on {DNS_IP}:{DNS_PORT}")

while True:
    data, addr = sock.recvfrom(512)
    handle_request(data, addr, sock)