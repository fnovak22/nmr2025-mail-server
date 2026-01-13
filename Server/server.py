import socket, threading, struct, json, os
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime

HOST = '127.0.0.1'
PORT = 50001

BASE_DIR = os.path.dirname(__file__)
USERS_FILE = os.path.join(BASE_DIR, "users.json")

with open(USERS_FILE, "r", encoding="utf-8") as f:
    USERS = json.load(f)

inboxes = {}
sessions = {}
sessions_lock = threading.Lock()

def recv_all_bytes_size(sock, n):
    data = b''
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            return None
        data += part
    return data

def recv_message_full_length(sock):
    hdr = recv_all_bytes_size(sock, 4)
    if not hdr:
        return None
    (length,) = struct.unpack('!I', hdr)
    return recv_all_bytes_size(sock, length)

def send_message(sock, payload: bytes):
    sock.sendall(struct.pack('!I', len(payload)) + payload)

def aesgcm_encrypt_send(aesgcm: AESGCM, conn, data: bytes):
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    send_message(conn, nonce + ciphertext)

def aesgcm_recv_decrypt(aesgcm: AESGCM, conn):
    packed = recv_message_full_length(conn)
    if not packed:
        return None
    nonce_client = packed[:12]
    cyphertext_tag = packed[12:]
    return aesgcm.decrypt(nonce_client, cyphertext_tag, None)

def server_handshake(conn):
    try:
        server_priv = X25519PrivateKey.generate()
        server_pub_bytes = server_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        conn.sendall(server_pub_bytes)

        client_pub_bytes = recv_all_bytes_size(conn, 32)
        if not client_pub_bytes:
            conn.close()
            return None

        client_pub = X25519PublicKey.from_public_bytes(client_pub_bytes)
        shared = server_priv.exchange(client_pub)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake-server'
        )
        aes_key = hkdf.derive(shared)
        print("[DEBUG] AES KEY:", aes_key.hex())

        return AESGCM(aes_key)

    except Exception:
        conn.close()
        return None

def handle_client(conn, addr, gui_append):
    """
    - login: {type: 'login', username, password}
    - send:  {type: 'send', session, from, to, message}
    - fetch: {type: 'fetch', session}
    """
    try:
        aesgcm = server_handshake(conn)
        if aesgcm is None:
            return

        while True:
            try:
                plain = aesgcm_recv_decrypt(aesgcm, conn)
                if plain is None:
                    break
                try:
                    data = json.loads(plain.decode())

                except Exception as e:
                    gui_append(f"[ERROR][{addr}] invalid json: {e}")
                    continue

            except Exception as e:
                gui_append(f"[ERROR][{addr}] decryption failed: {e}")
                continue

            messag_type = data.get('type')
            if messag_type == 'login':
                username = data.get('username')
                password = data.get('password')
                if username in USERS and USERS[username] == password:
                    new_session_token = os.urandom(16).hex()
                    with sessions_lock:
                        sessions[new_session_token] = username
                    resp = json.dumps({'status':'ok','session': new_session_token}).encode()

                    aesgcm_encrypt_send(aesgcm, conn, resp)

                    gui_append(f"[AUTH][{addr}] Authenticated {username} (session {new_session_token[:8]}...)")
                else:
                    resp = json.dumps({'status':'fail','error':'invalid credentials'}).encode()
                    aesgcm_encrypt_send(aesgcm, conn, resp)
                    gui_append(f"[ERROR][{addr}] Auth failed for {username}")
                continue

            session_token = data.get('session')
            if not session_token:
                resp = json.dumps({'status':'fail','error':'no session'}).encode()
                aesgcm_encrypt_send(aesgcm, conn, resp)
                gui_append(f"[ERROR][{addr}] message without session")
                continue
            with sessions_lock:
                authed_user = sessions.get(session_token)
            if not authed_user:
                resp = json.dumps({'status':'fail','error':'invalid session'}).encode()
                aesgcm_encrypt_send(aesgcm, conn, resp)
                gui_append(f"[ERROR][{addr}] invalid session token: {session_token[:8]}...")
                continue

            if messag_type == 'send':
                sender = data.get('from')
                to = data.get('to')
                text = data.get('message')
                if sender != authed_user:
                    resp = json.dumps({'status':'fail','error':'sender mismatch'}).encode()
                    aesgcm_encrypt_send(aesgcm, conn, resp)
                    gui_append(f"[ERROR][{addr}] sender mismatch: {sender} != {authed_user}")
                    continue

                if to not in USERS:
                    resp = json.dumps({'status':'fail','error':'recipient unknown'}).encode()
                    aesgcm_encrypt_send(aesgcm, conn, resp)
                    gui_append(f"[ERROR][{addr}] recipient unknown: {to}")
                    continue
                
                if to not in inboxes:
                    inboxes[to] = []

                inboxes[to].append({'from': sender, 'message': text})
                gui_append(f"[MAIL][{addr}] Stored new message from {sender} -> {to}")
                resp = json.dumps({'status':'ok'}).encode()
                aesgcm_encrypt_send(aesgcm, conn, resp)

            elif messag_type == 'fetch':
                user = authed_user
                msgs = inboxes.get(user, [])
                resp = json.dumps({'messages': msgs}).encode()
                aesgcm_encrypt_send(aesgcm, conn, resp)
                inboxes[user] = []
                gui_append(f"[MAIL][{addr}] Delivered {len(msgs)} messages to {user}")

            else:
                gui_append(f"[ERROR][{addr}] Unknown type: {messag_type}")
                resp = json.dumps({'status':'fail','error':'unknown type'}).encode()
                aesgcm_encrypt_send(aesgcm, conn, resp)

    finally:
        conn.close()

def start_gui():
    root = tk.Tk()
    root.title("Server log")
    root.geometry("800x400")

    st = ScrolledText(root, width=120, height=24, state='disabled')
    st.pack(fill='both', expand=True, padx=8, pady=8)

    def gui_append(s):
        now = datetime.now().strftime('%H:%M:%S')
        st.config(state='normal')
        st.insert(tk.END, f"[{now}] {s}\n")
        st.yview_moveto(1.0)
        st.config(state='disabled')

    def server_thread():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            sock.bind((HOST, PORT))
            sock.listen()

            gui_append(f"[INFO] Server is listening on {HOST}:{PORT}")
            while True:
                conn, addr = sock.accept()
                gui_append(f"[INFO] Accepted connection from {addr}")
                threading.Thread(target=handle_client, args=(conn, addr, gui_append), daemon=True).start()

    threading.Thread(target=server_thread, daemon=True).start()
    root.mainloop()

if __name__ == "__main__":
    start_gui()
