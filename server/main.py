import socket
from dnslib import DNSRecord, QTYPE, RR, A, DNSHeader, DNSQuestion
import sqlite3
import json
import base64

DNS_IP = '0.0.0.0'
DNS_PORT = 5353

print("Server starting...")

# Database setup
conn = sqlite3.connect('chat.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        content TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
''')
conn.commit()
print("Database setup complete.")

clients = {}

def encode_data(data):
    encoded_bytes = base64.urlsafe_b64encode(data.encode('utf-8'))
    return str(encoded_bytes, 'utf-8')

def decode_data(data):
    decoded_bytes = base64.urlsafe_b64decode(data.encode('utf-8'))
    return str(decoded_bytes, 'utf-8')

def handle_request(data, addr, sock):
    global clients
    print(f"Received data from {addr}")
    request = DNSRecord.parse(data)
    qname = str(request.q.qname)
    qtype = QTYPE[request.q.qtype]
    message_data = qname.split('.')[0]

    print(f"Parsed DNS request: qname={qname}, qtype={qtype}")
    print(f"Message data: {message_data}")

    try:
        decoded_message = decode_data(message_data)
        message_json = json.loads(decoded_message)
        print(f"Parsed JSON: {message_json}")
        
        if 'username' in message_json and 'message' not in message_json:
            username = message_json['username']
            if addr not in clients:
                clients[addr] = username

            send_message_history(sock, addr)

        if 'message' in message_json:
            username = message_json['username']
            message = message_json['message']
            
            print(f"Chat message from {username}: {message}")

            # Store message in database
            cursor.execute('INSERT INTO messages (sender, content) VALUES (?, ?)', (username, message))
            conn.commit()
            print(f"Message stored in database")

            # Register the client
            clients[addr] = username
            print(f"Client registered: {addr} -> {username}")

            # Send message to all clients
            for client_addr in clients:
                reply_message = json.dumps({'sender': username, 'message': message})
                encoded_reply = encode_data(reply_message)
                qname_reply = f"{encoded_reply}.bylife.fr"
                reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=DNSQuestion(qname_reply))
                reply.add_answer(RR(qname_reply, QTYPE.A, rdata=A("212.227.26.128"), ttl=60))
                sock.sendto(reply.pack(), client_addr)
                print(f"Sent message to {client_addr}: {reply_message}")

        if qtype == "A":
            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("212.227.26.128"), ttl=60))
            sock.sendto(reply.pack(), addr)
            print(f"Sent DNS response to {addr}")

    except Exception as e:
        print(f"Error processing message: {e}")

def send_message_history(sock, addr):
    cursor.execute('SELECT sender, content FROM messages ORDER BY timestamp DESC LIMIT 50')
    messages = cursor.fetchall()
    messages.reverse()  # Send messages in chronological order
    for sender, content in messages:
        message_json = json.dumps({'sender': sender, 'message': content})
        encoded_message = encode_data(message_json)
        qname = f"{encoded_message}.bylife.fr"
        reply = DNSRecord(DNSHeader(qr=1, aa
