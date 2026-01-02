# server.py
import socket, threading, struct, json, os
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = '127.0.0.1'
PORT = 65432

BASE_DIR = os.path.dirname(__file__)
USERS_FILE = os.path.join(BASE_DIR, "users.json")

with open(USERS_FILE, "r", encoding="utf-8") as f:
    USERS = json.load(f)

# simple in-memory inboxes: {username: [messages]}
inboxes = {}

# sessions: token -> username
sessions = {}
sessions_lock = threading.Lock()

# helper framing functions
def recv_all(sock, n):
    data = b''
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            return None
        data += part
    return data

def recv_message(sock):
    hdr = recv_all(sock, 4)
    if not hdr:
        return None
    (length,) = struct.unpack('!I', hdr)
    return recv_all(sock, length)

def send_message(sock, payload: bytes):
    sock.sendall(struct.pack('!I', len(payload)) + payload)

def handle_client(conn, addr, gui_append):
    """
    Per-connection ephemeral handshake, plus handling of:
    - login: {type: 'login', username, password} -> returns session token
    - send:  {type: 'send', session, from, to, message}
    - fetch: {type: 'fetch', session}
    """
    try:
        # ephemeral server keypair for this connection
        server_priv = X25519PrivateKey.generate()
        server_pub_bytes = server_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # send server public
        conn.sendall(server_pub_bytes)

        # receive client public
        client_pub_bytes = recv_all(conn, 32)
        if not client_pub_bytes:
            conn.close(); return

        client_pub = X25519PublicKey.from_public_bytes(client_pub_bytes)
        shared = server_priv.exchange(client_pub)

        # derive AES key
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake-server')
        aes_key = hkdf.derive(shared)
        aesgcm = AESGCM(aes_key)

        while True:
            packed = recv_message(conn)
            if not packed:
                break
            nonce = packed[:12]; ct = packed[12:]
            try:
                plain = aesgcm.decrypt(nonce, ct, None)
            except Exception as e:
                gui_append(f"[{addr}] decryption failed: {e}")
                continue
            try:
                data = json.loads(plain.decode())
            except Exception as e:
                gui_append(f"[{addr}] invalid json: {e}")
                continue

            typ = data.get('type')
            # ---- login ----
            if typ == 'login':
                username = data.get('username')
                password = data.get('password')
                if username in USERS and USERS[username] == password:
                    # create session token
                    token = os.urandom(16).hex()
                    with sessions_lock:
                        sessions[token] = username
                    resp = json.dumps({'status':'ok','session': token}).encode()
                    rn = os.urandom(12)
                    send_message(conn, rn + aesgcm.encrypt(rn, resp, None))
                    gui_append(f"[{addr}] Authenticated {username} (session {token[:8]}...)")
                else:
                    resp = json.dumps({'status':'fail','error':'invalid credentials'}).encode()
                    rn = os.urandom(12)
                    send_message(conn, rn + aesgcm.encrypt(rn, resp, None))
                    gui_append(f"[{addr}] Auth failed for {username}")
                # continue loop (client may close or reuse token elsewhere)
                continue

            # ---- send / fetch require session token ----
            session = data.get('session')
            if not session:
                resp = json.dumps({'status':'fail','error':'no session'}).encode()
                rn = os.urandom(12)
                send_message(conn, rn + aesgcm.encrypt(rn, resp, None))
                gui_append(f"[{addr}] message without session")
                continue
            with sessions_lock:
                authed_user = sessions.get(session)
            if not authed_user:
                resp = json.dumps({'status':'fail','error':'invalid session'}).encode()
                rn = os.urandom(12)
                send_message(conn, rn + aesgcm.encrypt(rn, resp, None))
                gui_append(f"[{addr}] invalid session used: {session[:8]}...")
                continue

            if typ == 'send':
                sender = data.get('from')
                to = data.get('to')
                text = data.get('message')
                # verify sender matches session user
                if sender != authed_user:
                    resp = json.dumps({'status':'fail','error':'sender mismatch'}).encode()
                    rn = os.urandom(12)
                    send_message(conn, rn + aesgcm.encrypt(rn, resp, None))
                    gui_append(f"[{addr}] sender mismatch: {sender} != {authed_user}")
                    continue
                # verify recipient exists
                if to not in USERS:
                    resp = json.dumps({'status':'fail','error':'recipient unknown'}).encode()
                    rn = os.urandom(12)
                    send_message(conn, rn + aesgcm.encrypt(rn, resp, None))
                    gui_append(f"[{addr}] recipient unknown: {to}")
                    continue
                inboxes.setdefault(to, []).append({'from': sender, 'message': text})
                gui_append(f"[{addr}] Stored message from {sender} -> {to}")
                resp = json.dumps({'status':'ok'}).encode()
                rn = os.urandom(12)
                send_message(conn, rn + aesgcm.encrypt(rn, resp, None))

            elif typ == 'fetch':
                user = authed_user
                msgs = inboxes.get(user, [])
                out = json.dumps({'messages': msgs}).encode()
                rn = os.urandom(12)
                send_message(conn, rn + aesgcm.encrypt(rn, out, None))
                inboxes[user] = []  # clear after fetch
                gui_append(f"[{addr}] Delivered {len(msgs)} messages to {user}")

            else:
                gui_append(f"[{addr}] Unknown type: {typ}")
                resp = json.dumps({'status':'fail','error':'unknown type'}).encode()
                rn = os.urandom(12)
                send_message(conn, rn + aesgcm.encrypt(rn, resp, None))

    finally:
        conn.close()

# GUI thread
def start_gui():
    root = tk.Tk()
    root.title("Simple Mail Server - inboxes")
    st = ScrolledText(root, width=80, height=24, state='disabled')
    st.pack(padx=8, pady=8)

    def gui_append(s):
        st.config(state='normal')
        st.insert(tk.END, s + '\n')
        st.yview_moveto(1.0)
        st.config(state='disabled')

    # networking thread
    def server_thread():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen()
            gui_append(f"Server listening on {HOST}:{PORT}")
            while True:
                conn, addr = s.accept()
                gui_append(f"Accepted connection from {addr}")
                threading.Thread(target=handle_client, args=(conn, addr, gui_append), daemon=True).start()

    threading.Thread(target=server_thread, daemon=True).start()
    root.mainloop()

if __name__ == "__main__":
    start_gui()
