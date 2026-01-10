import socket, struct, json, os, threading, hashlib
from datetime import datetime, timezone
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = '127.0.0.1'
PORT = 50001

BASE_DIR = os.path.dirname(__file__)
MAILS_DIR = os.path.join(BASE_DIR, "mails")
os.makedirs(MAILS_DIR, exist_ok=True)

# prikupi n bajtova sa socketa, jer je to STREAM (TCP) , nije UDP datagram koji ima svoj size
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

def send_message_with_packed_length(sock, payload: bytes):
    sock.sendall(struct.pack('!I', len(payload)) + payload)

def aesgcm_encrypt_send(aesgcm: AESGCM, sock, data: bytes):
    """
    Automatski generira nonce, šifrira data i pošalje preko sock
    """
    nonce = os.urandom(12)                   # generiraj 12-bajtni nonce
    ciphertext = aesgcm.encrypt(nonce, data, None)
    send_message_with_packed_length(sock, nonce + ciphertext)   # šalje nonce + ciphertext

def aesgcm_recv_decrypt(aesgcm: AESGCM, sock):
    packed = recv_message_full_length(sock)
    if not packed:
        return None
    nonce_server = packed[:12]
    cyphertext_tag = packed[12:]
    return aesgcm.decrypt(nonce_server, cyphertext_tag, None)

# Ephemeral per-connection handshake (forward secrecy)
def perform_handshake_and_get_aes(sock):
    server_pub_bytes = recv_all_bytes_size(sock, 32)
    if not server_pub_bytes:
        raise RuntimeError("No server public key received!")
    client_priv = X25519PrivateKey.generate()
    client_pub_bytes = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    sock.sendall(client_pub_bytes)
    server_pub = X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared = client_priv.exchange(server_pub) #shared = server_pub ^ client_priv
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake-server'
    )
    aes_key = hkdf.derive(shared)
    return AESGCM(aes_key)

# ---------- Local mail storage helpers ----------
def user_mailfile(username):
    return os.path.join(MAILS_DIR, f"{username}.json")

def load_local_mails(username):
    path = user_mailfile(username)
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_local_mails(username, mails):
    path = user_mailfile(username)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(mails, f, ensure_ascii=False, indent=2)

def make_msg_id(from_user, subject, content, timestamp):
    base = (str(from_user) + (subject or "") + (content or "") + (timestamp or "")).encode('utf-8')
    return hashlib.sha256(base).hexdigest()

def normalize_incoming(m):
    frm = m.get('from', '')
    message = m.get('message')
    if isinstance(message, dict):
        subject = message.get('subject', '')
        content = message.get('content', '')
        timestamp = message.get('timestamp') or datetime.now(timezone.utc).isoformat()
    else:
        subject = ''
        content = str(message or '')
        timestamp = datetime.now(timezone.utc).isoformat()
    mid = make_msg_id(frm, subject, content, timestamp)
    return {
        'id': mid,
        'from': frm,
        'subject': subject,
        'content': content,
        'timestamp': timestamp,
        'read': False
    }

# ---------- GUI ----------
class MailClientGUI:
    def __init__(self, root, username, session_token):
        self.root = root
        self.username = username
        self.session = session_token

        root.title(f"Mail Client - {self.username}")
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=6, pady=6)

        self.build_inbox_tab()
        self.build_send_tab()

        # load local mails at startup
        local = load_local_mails(self.username)
        self.load_mails_into_tree(self.username, local)

    # ----- Inbox Tab -----
    def build_inbox_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Inbox")

        top = ttk.Frame(frame)
        top.pack(fill='x', padx=6, pady=6)
        ttk.Label(top, text=f"Logged in as: {self.username}").pack(side='left')
        ttk.Button(top, text="Fetch mail", command=self.fetch_mail).pack(side='left', padx=8)

        mid = ttk.Frame(frame)
        mid.pack(fill='both', expand=True, padx=6, pady=6)

        cols = ('subject', 'from', 'timestamp', 'read')
        self.tree = ttk.Treeview(mid, columns=cols, show='headings', selectmode='browse')
        self.tree.heading('subject', text='Subject')
        self.tree.heading('from', text='From')
        self.tree.heading('timestamp', text='Timestamp')
        self.tree.heading('read', text='Read')
        self.tree.column('subject', width=200)
        self.tree.column('from', width=100)
        self.tree.column('timestamp', width=160)
        self.tree.column('read', width=50, anchor='center')
        self.tree.pack(side='left', fill='both', expand=True)

        self.tree.bind("<Double-1>", self.on_tree_double)

        right = ttk.Frame(mid)
        right.pack(side='right', fill='both', expand=True)
        ttk.Label(right, text="Content:").pack(anchor='nw')
        self.content_box = ScrolledText(right, width=40, height=15)
        self.content_box.pack(fill='both', expand=True)

        self.current_mails = []
        self.current_username = self.username

    def fetch_mail(self):
        threading.Thread(target=self._fetch_mail_worker, daemon=True).start()

    def _fetch_mail_worker(self):
        try:
            #SOCK STREAM = TCP
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((HOST, PORT))

                aesgcm = perform_handshake_and_get_aes(sock)
                payload = json.dumps({'type':'fetch','session': self.session}).encode()

                aesgcm_encrypt_send(aesgcm, sock, payload)

                plain = aesgcm_recv_decrypt(aesgcm, sock)
                if plain is None:
                    messagebox.showerror("Error", "No response from server.")
                    return
                
                data = json.loads(plain.decode())
                msgs = data.get('messages', [])

                normalized = [normalize_incoming(m) for m in msgs]

                local = load_local_mails(self.username)
                local_ids = {m['id']: m for m in local}
                for nm in normalized:
                    if nm['id'] in local_ids:
                        nm['read'] = local_ids[nm['id']].get('read', False)
                    else:
                        local.append(nm)
                try:
                    local.sort(key=lambda x: x.get('timestamp',''), reverse=True)
                except Exception:
                    pass
                save_local_mails(self.username, local)
                self.root.after(0, lambda: self.load_mails_into_tree(self.username, local))
                messagebox.showinfo("Fetched", f"Fetched {len(normalized)} messages. Local total: {len(local)}")
        except Exception as e:
            messagebox.showerror("Error", f"Fetch failed: {e}")

    def load_mails_into_tree(self, username, mail_list):
        self.tree.delete(*self.tree.get_children())
        self.current_mails = mail_list
        self.current_username = username
        for m in mail_list:
            read_flag = '✓' if m.get('read') else ''
            subj = m.get('subject') or '(no subject)'
            frm = m.get('from') or ''
            ts = m.get('timestamp') or ''
            self.tree.insert('', 'end', iid=m['id'], values=(subj, frm, ts, read_flag))
        self.content_box.delete('1.0', tk.END)

    def on_tree_double(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        mid = sel[0]
        m = next((x for x in self.current_mails if x['id'] == mid), None)
        if not m:
            return
        m['read'] = not bool(m.get('read'))
        read_flag = '✓' if m['read'] else ''
        self.tree.set(mid, 'read', read_flag)
        self.content_box.delete('1.0', tk.END)
        display = f"From: {m.get('from')}\nSubject: {m.get('subject')}\nTime: {m.get('timestamp')}\n\n{m.get('content')}"
        self.content_box.insert(tk.END, display)
        save_local_mails(self.current_username, self.current_mails)

    # ----- Send Tab -----
    def build_send_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Send")

        frm = ttk.Frame(frame)
        frm.pack(fill='x', padx=6, pady=6)
        ttk.Label(frm, text="From:").grid(row=0, column=0, sticky='w')
        self.send_from = ttk.Entry(frm, width=30)
        self.send_from.grid(row=0, column=1, padx=6, pady=4)
        self.send_from.insert(0, self.username)
        self.send_from.config(state='disabled')

        ttk.Label(frm, text="To:").grid(row=1, column=0, sticky='w')
        self.send_to = ttk.Entry(frm, width=30)
        self.send_to.grid(row=1, column=1, padx=6, pady=4)

        ttk.Label(frm, text="Subject:").grid(row=2, column=0, sticky='w')
        self.send_subject = ttk.Entry(frm, width=50)
        self.send_subject.grid(row=2, column=1, padx=6, pady=4)

        ttk.Label(frm, text="Content:").grid(row=3, column=0, sticky='nw')
        self.send_content = ScrolledText(frm, width=60, height=10)
        self.send_content.grid(row=3, column=1, padx=6, pady=4)

        btn = ttk.Button(frm, text="Send", command=self.do_send)
        btn.grid(row=4, column=1, sticky='e', pady=6)

    def do_send(self):
        frm = self.username
        to = self.send_to.get().strip()
        subject = self.send_subject.get().strip()
        content = self.send_content.get("1.0", tk.END).strip()
        if not frm or not to or not subject or not content:
            messagebox.showwarning("Missing", "All fields (From, To, Subject, Content) must be filled.")
            return
        threading.Thread(target=self._send_worker, args=(frm,to,subject,content), daemon=True).start()

    def _send_worker(self, frm, to, subject, content):
        try:
            with socket.create_connection((HOST, PORT), timeout=5) as sock:
                aesgcm = perform_handshake_and_get_aes(sock)
                timestamp = datetime.now(timezone.utc).isoformat()
                payload = {
                    'type': 'send',
                    'session': self.session,
                    'from': frm,
                    'to': to,
                    'message': {
                        'subject': subject,
                        'content': content,
                        'timestamp': timestamp
                    }
                }
                bytes_to_send = json.dumps(payload).encode()
                aesgcm_encrypt_send(aesgcm, sock, bytes_to_send)
                
                plain = aesgcm_recv_decrypt(aesgcm, sock)
                if plain is None:
                    messagebox.showwarning("Unknown send status", "Server did not send status.")
                    return

                resp = json.loads(plain.decode())
                if resp.get('status') == 'ok':
                    self.root.after(0, lambda: self.clear_send_fields())
                    messagebox.showinfo("Sent", "Message sent successfully.")
                    return
                else:
                    messagebox.showerror("Error", f"Send failed: {resp.get('error')}")
                    return
                    
        except Exception as e:
            messagebox.showerror("Error", f"Send failed: {e}")

    def clear_send_fields(self):
        self.send_to.delete(0, tk.END)
        self.send_subject.delete(0, tk.END)
        self.send_content.delete('1.0', tk.END)

# ---------- Login helper ----------
def attempt_login(username, password):
    try:
        with socket.create_connection((HOST, PORT), timeout=5) as sock:
            aesgcm = perform_handshake_and_get_aes(sock)
            payload = json.dumps({'type':'login','username':username,'password':password}).encode()

            aesgcm_encrypt_send(aesgcm, sock, payload)

            plain = aesgcm_recv_decrypt(aesgcm, sock)
            if plain is None:
                return False, "No response"

            data = json.loads(plain.decode())
            if data.get('status') == 'ok':
                return True, data.get('session')
            else:
                return False, data.get('error', 'auth failed')
    except Exception as e:
        return False, str(e)

def main():
    root = tk.Tk()
    root.withdraw()  # hide during login
    while True:
        username = simpledialog.askstring("Login", "Username:", parent=root)
        if username is None:
            return
        password = simpledialog.askstring("Login", "Password:", show='*', parent=root)
        if password is None:
            return
        ok, result = attempt_login(username, password)
        if ok:
            session = result
            root.deiconify()
            break
        else:
            messagebox.showerror("Login failed", f"Login failed: {result}")

    try:
        style = ttk.Style(root)
        style.theme_use('clam')
    except Exception:
        pass
    app = MailClientGUI(root, username, session)
    root.mainloop()

if __name__ == "__main__":
    main()
