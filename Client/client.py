import socket, struct, json, os, threading, hashlib
from datetime import datetime, timezone
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
from PIL import Image, ImageTk

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import errno

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 50001

BASE_DIR = os.path.dirname(__file__)
MAILS_DIR = os.path.join(BASE_DIR, "mails")
GIF_PATH = os.path.join(BASE_DIR, "loader.gif")
os.makedirs(MAILS_DIR, exist_ok=True)

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
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    send_message_with_packed_length(sock, nonce + ciphertext)

def aesgcm_recv_decrypt(aesgcm: AESGCM, sock):
    packed = recv_message_full_length(sock)
    if not packed:
        return None
    nonce_server = packed[:12]
    cyphertext_tag = packed[12:]
    return aesgcm.decrypt(nonce_server, cyphertext_tag, None)

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
    shared = client_priv.exchange(server_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake-server'
    )
    aes_key = hkdf.derive(shared)
    #print("[DEBUG] AES KEY:", aes_key.hex())
    return AESGCM(aes_key)

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

def save_local_mails(username, mails_list):
    path_to_json = user_mailfile(username)
    with open(path_to_json, "w", encoding="utf-8") as mail_file:
        json.dump(mails_list, mail_file, ensure_ascii=False, indent=2)

def generate_message_hash(from_user, subject, content, timestamp):
    base = (str(from_user) + (subject or "") + (content or "") + (timestamp or "")).encode('utf-8')
    return hashlib.sha256(base).hexdigest()

def normalize_incoming_mail(mail_json):
    frm = mail_json.get('from', '')
    message = mail_json.get('message')
    subject = message.get('subject', '')
    content = message.get('content', '')
    timestamp = message.get('timestamp') or datetime.now(timezone.utc).isoformat()
    message_id = generate_message_hash(frm, subject, content, timestamp)
    return {
        'id': message_id,
        'from': frm,
        'subject': subject,
        'content': content,
        'timestamp': timestamp,
        'read': False
    }

def format_timestamp(timestamp):
    try:
        date_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return date_time.strftime('%d.%m.%Y. %H:%M')
    except Exception:
        return timestamp

class MailClientGUI:
    def __init__(self, root, username, session_token):
        self.root = root
        self.username = username
        self.session = session_token

        root.title(f"Mail Client - {self.username}")
        self.notebook = ttk.Notebook(root)
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        self.notebook.pack(fill='both', expand=True, padx=6, pady=6)

        self.build_inbox_tab()
        self.build_send_tab()

        local = load_local_mails(self.username)
        self.load_mails_into_tree(self.username, local)

    def build_inbox_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Inbox")

        top = ttk.Frame(frame)
        top.pack(fill='x', padx=6, pady=6)
        ttk.Label(top, text=f"Logged in as: {self.username}").pack(side='left')
        ttk.Button(top, text="Fetch mail", command=self.fetch_mail).pack(side='left', padx=8)
        ttk.Button(top, text="Mark as Unread", command=self.mark_as_unread).pack(side='left', padx=8)
        ttk.Button(top, text="Delete", command=self.delete_selected_mail).pack(side='left', padx=8)
        self.status_label = ttk.Label(top, text="", foreground="red")
        self.status_label.pack(side='left', padx=8)
        self.status_label.pack_forget()
        ttk.Button(top, text="Logout", command=self.logout).pack(side='right')

        mid = ttk.Frame(frame)
        mid.pack(fill='both', expand=True, padx=6, pady=6)

        cols = ('select', 'subject', 'from', 'timestamp', 'read')
        self.tree = ttk.Treeview(mid, columns=cols, show='headings', selectmode='extended')
        self.tree.heading('select', text='')
        self.tree.heading('subject', text='Subject')
        self.tree.heading('from', text='From')
        self.tree.heading('timestamp', text='Timestamp')
        self.tree.heading('read', text='Read')
        self.tree.column('select', width=30, anchor='center')
        self.tree.column('subject', width=200)
        self.tree.column('from', width=100)
        self.tree.column('timestamp', width=160)
        self.tree.column('read', width=50, anchor='center')
        self.tree.pack(side='left', fill='both', expand=True)

        self.tree.bind("<Button-1>", self.on_tree_click)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        right = ttk.Frame(mid)
        right.pack(side='right', fill='both', expand=True)
        ttk.Label(right, text="Content:").pack(anchor='nw')
        self.content_box = ScrolledText(right, width=40, height=15)
        self.content_box.pack(fill='both', expand=True)

        self.current_mails = []
        self.current_username = self.username

        self.loader_label = ttk.Label(top)
        self.loader_label.pack(side='left', padx=8)
        self.loader_label.pack_forget()

        self.loader_gif = Image.open(GIF_PATH)
        self.loader_frames = []
        desired_size = (24, 24)
        try:
            while True:
                frame = self.loader_gif.copy().resize(desired_size, Image.LANCZOS)
                self.loader_frames.append(ImageTk.PhotoImage(frame))
                self.loader_gif.seek(len(self.loader_frames))
        except EOFError:
            pass
        self.loader_gif.seek(0)
        self.loader_frame_index = 0
        self.loader_animating = False

    def logout(self):
        if not messagebox.askyesno("Logout", "Are you sure?"):
            return

        self.root.withdraw()

        self.username = None
        self.session = None

        self.root.after(0, self.show_login_again)

    def show_login_again(self):
        for w in self.root.winfo_children():
            w.destroy()

        while True:
            login = LoginDialog(self.root)
            self.root.wait_window(login)

            if not login.result:
                self.root.destroy()
                return

            username, session = login.result
            self.root.deiconify()
            MailClientGUI(self.root, username, session)
            return

    def on_tab_changed(self, event):
        self.status_label.pack_forget()
        self.send_status_label.config(text="")

        for mid in list(getattr(self, 'selected_ids', [])):
            self.tree.set(mid, 'select', '\u2610')
        self.selected_ids.clear()

        self.content_box.delete('1.0', tk.END)

        self.tree.selection_remove(self.tree.selection())

    def show_loader(self):
        self.loader_label.pack(side='left', padx=8)
        self.loader_animating = True
        self.animate_loader()

    def hide_loader(self):
        self.loader_animating = False
        self.loader_label.pack_forget()

    def animate_loader(self):
        if not self.loader_animating:
            return
        frame = self.loader_frames[self.loader_frame_index]
        self.loader_label.config(image=frame)
        self.loader_frame_index = (self.loader_frame_index + 1) % len(self.loader_frames)
        self.root.after(80, self.animate_loader) 

    def delete_selected_mail(self):
        if not self.selected_ids:
            self.status_label.config(text="No messages selected.")
            self.status_label.pack(side='left', padx=8)
            return
        self.current_mails = [m for m in self.current_mails if m['id'] not in self.selected_ids]
        save_local_mails(self.current_username, self.current_mails)
        self.load_mails_into_tree(self.current_username, self.current_mails)
        self.content_box.delete('1.0', tk.END)

    def mark_as_unread(self):
        if not self.selected_ids:
            self.status_label.config(text="No messages selected.")
            self.status_label.pack(side='left', padx=8)
            return
        changed = False
        for mid in self.selected_ids:
            m = next((x for x in self.current_mails if x['id'] == mid), None)
            if m and m.get('read'):
                m['read'] = False
                self.tree.set(mid, 'read', '')
                changed = True
        if changed:
            save_local_mails(self.current_username, self.current_mails)
        for mid in list(self.selected_ids):
            self.tree.set(mid, 'select', '\u2610')
        self.selected_ids.clear()

    def fetch_mail(self):
        self.show_loader()
        threading.Thread(target=self.fetch_mail_thread, daemon=True).start()

    def show_fetch_error(self, message):
        try:
            self.status_label.pack(side='left', padx=8)
            self.hide_loader()
            self.status_label.config(text=f"Fetch failed: {message}")
        except tk.TclError:
            pass

    def fetch_mail_thread(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((SERVER_ADDRESS, SERVER_PORT))

                aesgcm = perform_handshake_and_get_aes(sock)
                payload = json.dumps({'type':'fetch','session': self.session}).encode()

                aesgcm_encrypt_send(aesgcm, sock, payload)

                plain = aesgcm_recv_decrypt(aesgcm, sock)
                if plain is None:
                    self.root.after(0, lambda: self.show_fetch_error("No response from server"))
                    return
                
                data = json.loads(plain.decode())
                msgs = data.get('messages', [])

                normalized_incoming_mail = [normalize_incoming_mail(m) for m in msgs]

                local = load_local_mails(self.username)
                local_ids = {m['id']: m for m in local}
                for normalized_mail in normalized_incoming_mail:
                    if normalized_mail['id'] in local_ids:
                        continue
                    else:
                        local.append(normalized_mail)
                try:
                    local.sort(key=lambda x: x.get('timestamp',''), reverse=True)
                except Exception:
                    pass
                save_local_mails(self.username, local)
                self.root.after(0, lambda: self.load_mails_into_tree(self.username, local))
                self.root.after(600, self.hide_loader)

        except (socket.timeout, ConnectionRefusedError, socket.gaierror):
            self.root.after(0, lambda: self.show_fetch_error("Failed to connect to server"))

        except OSError as e:
            if getattr(e, 'errno', None) in (
                errno.ECONNREFUSED,
                errno.ENETUNREACH,
                errno.EHOSTUNREACH,
                errno.ECONNRESET
            ):
                self.root.after(0, lambda: self.show_fetch_error("Failed to connect to server"))
            else:
                self.root.after(0, lambda: self.show_fetch_error("Unexpected error"))

        except Exception:
            self.root.after(0, lambda: self.show_fetch_error("Unexpected error"))


    def load_mails_into_tree(self, username, mail_list):
        self.tree.delete(*self.tree.get_children())
        self.current_mails = mail_list
        self.current_username = username
        self.selected_ids = set()
        for m in mail_list:
            read_flag = '✓' if m.get('read') else ''
            subj = m.get('subject') or '(no subject)'
            frm = m.get('from') or ''
            ts = format_timestamp(m.get('timestamp') or '')
            self.tree.insert('', 'end', iid=m['id'], values=('\u2610', subj, frm, ts, read_flag))
        self.content_box.delete('1.0', tk.END)

    def on_tree_select(self, event):
        self.status_label.pack_forget()
        sel = self.tree.selection()
        if not sel:
            return
        mid = sel[0]
        m = next((x for x in self.current_mails if x['id'] == mid), None)
        if not m:
            return
        if not m.get('read'):
            m['read'] = True
            self.tree.set(mid, 'read', '✓')
            save_local_mails(self.current_username, self.current_mails)
        self.content_box.delete('1.0', tk.END)
        display = f"From: {m.get('from')}\nSubject: {m.get('subject')}\nTime: {format_timestamp(m.get('timestamp'))}\n\n{m.get('content')}"
        self.content_box.insert(tk.END, display)

    def on_tree_click(self, event):
        self.status_label.pack_forget()
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        col = self.tree.identify_column(event.x)
        if col != "#1":
            return
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return
        if row_id in self.selected_ids:
            self.selected_ids.remove(row_id)
            self.tree.set(row_id, 'select', '\u2610')
        else:
            self.selected_ids.add(row_id)
            self.tree.set(row_id, 'select', '\u2611')

    def build_send_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Send")

        frm = ttk.Frame(frame)
        frm.pack(fill='both', expand=True, padx=6, pady=6)

        ttk.Label(frm, text="From:").grid(row=0, column=0, sticky='w')
        self.send_from = ttk.Entry(frm)
        self.send_from.grid(row=0, column=1, sticky='ew', padx=6, pady=4)
        self.send_from.insert(0, self.username)
        self.send_from.config(state='disabled')

        ttk.Label(frm, text="To:").grid(row=1, column=0, sticky='w')
        self.send_to = ttk.Entry(frm)
        self.send_to.grid(row=1, column=1, sticky='ew', padx=6, pady=4)

        ttk.Label(frm, text="Subject:").grid(row=2, column=0, sticky='w')
        self.send_subject = ttk.Entry(frm)
        self.send_subject.grid(row=2, column=1, sticky='ew', padx=6, pady=4)

        ttk.Label(frm, text="Content:").grid(row=3, column=0, sticky='nw')
        self.send_content = ScrolledText(frm)
        self.send_content.grid(row=3, column=1, sticky='nsew', padx=6, pady=4)

        btn_status_frame = ttk.Frame(frm)
        btn_status_frame.grid(row=4, column=1, sticky='ew', pady=6)
        btn_status_frame.columnconfigure(0, weight=1)
        btn_status_frame.columnconfigure(1, weight=0)

        self.send_status_label = ttk.Label(btn_status_frame, text="", anchor='w', foreground='red')
        self.send_status_label.grid(row=0, column=0, sticky='w')

        btn = ttk.Button(btn_status_frame, text="Send", command=self.do_send)
        btn.grid(row=0, column=1, sticky='e', padx=(8,0))

        frm.columnconfigure(1, weight=1)
        frm.rowconfigure(3, weight=1)

    def set_send_status(self, text, is_error=True):
        color = 'red' if is_error else 'black'
        self.send_status_label.config(text=text, foreground=color)

    def do_send(self):
        frm = self.username
        to = self.send_to.get().strip()
        subject = self.send_subject.get().strip()
        content = self.send_content.get("1.0", tk.END).strip()
        if not frm or not to or not subject or not content:
            self.set_send_status("All fields (From, To, Subject, Content) must be filled!", is_error=True)
            return
        self.set_send_status("Sending...", is_error=False)
        threading.Thread(target=self.send_mail_thread, args=(frm,to,subject,content), daemon=True).start()

    def send_mail_thread(self, frm, to, subject, content):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((SERVER_ADDRESS, SERVER_PORT))

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
                print("A")
                aesgcm_encrypt_send(aesgcm, sock, bytes_to_send)
                print("B")
                
                plain = aesgcm_recv_decrypt(aesgcm, sock)
                if plain is None:
                    self.root.after(0, lambda: self.set_send_status("Server did not send status.", is_error=True))
                    return

                resp = json.loads(plain.decode())
                if resp.get('status') == 'ok':
                    self.root.after(0, lambda: [self.clear_send_fields(), self.set_send_status("Sent successfully.", is_error=False)])
                    return
                else:
                    self.root.after(0, lambda: self.set_send_status(f"Send failed: {resp.get('error')}", is_error=True))
                    return
                    
        except (socket.timeout, ConnectionRefusedError, socket.gaierror):
            self.root.after(
                0,
                lambda: self.set_send_status("Send failed: Failed to connect to server", is_error=True)
            )

        except OSError as e:
            if getattr(e, 'errno', None) in (
                errno.ECONNREFUSED,
                errno.ENETUNREACH,
                errno.EHOSTUNREACH,
                errno.ECONNRESET
            ):
                self.root.after(
                    0,
                    lambda: self.set_send_status("Send failed: Failed to connect to server", is_error=True)
                )
            else:
                self.root.after(
                    0,
                    lambda: self.set_send_status("Send failed: Unexpected error", is_error=True)
                )

        except Exception as e:
            self.root.after(
                    0,
                    lambda: self.set_send_status("Send failed: Unexpected error", is_error=True)
                )

    def clear_send_fields(self):
        self.send_to.delete(0, tk.END)
        self.send_subject.delete(0, tk.END)
        self.send_content.delete('1.0', tk.END)
        self.set_send_status("", is_error=False)

def attempt_login(username, password):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect((SERVER_ADDRESS, SERVER_PORT))

            aesgcm = perform_handshake_and_get_aes(sock)
            payload = json.dumps({'type':'login','username':username,'password':password}).encode()

            aesgcm_encrypt_send(aesgcm, sock, payload)

            plain = aesgcm_recv_decrypt(aesgcm, sock)
            if plain is None:
                return False, "No response from server"

            data = json.loads(plain.decode())
            if data.get('status') == 'ok':
                return True, data.get('session')
            else:
                return False, data.get('error', 'auth failed')
            
    except (socket.timeout, ConnectionRefusedError, socket.gaierror):
        return False, "Cant connect to server"
    
    except OSError as e:
        if getattr(e, 'errno', None) in (
            errno.ECONNREFUSED,
            errno.ENETUNREACH,
            errno.EHOSTUNREACH,
            errno.ECONNRESET
        ):
            return False, "Login error: Cant connect to server"
        return False, "Login error: Unable to login"
    
    except Exception as e:
        #print("Unexpected login error:", repr(e))
        return False, "Login error: Unable to login"
    
class LoginDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.result = None

        self.title("Login")
        self.resizable(False, False)

        self.logging_in = False
        self.login_response = None

        self.deiconify()
        self.lift()
        self.attributes("-topmost", True)

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill='both', expand=True)

        ttk.Label(frm, text="Username:").grid(row=0, column=0, sticky='w', pady=(0,6))
        self.ent_user = ttk.Entry(frm, width=30)
        self.ent_user.grid(row=0, column=1, pady=(0,6))

        ttk.Label(frm, text="Password:").grid(row=1, column=0, sticky='w', pady=(0,6))
        self.ent_pwd = ttk.Entry(frm, width=30, show='*')
        self.ent_pwd.grid(row=1, column=1, pady=(0,6))

        btn_frame = ttk.Frame(frm)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=(8,0), sticky='e')
        self.ok_btn = ttk.Button(btn_frame, text="OK", command=self.on_ok)
        self.ok_btn.pack(side='right', padx=(0,6))
        self.cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.on_cancel)
        self.cancel_btn.pack(side='right')

        self.status_label = ttk.Label(frm, text="", anchor='w')
        self.status_label.grid(row=4, column=0, columnspan=2, sticky='we', pady=(8,0))

        self.bind("<Return>", lambda: self.on_ok())
        self.bind("<Escape>", lambda: self.on_cancel())

        self.grab_set()

        self.ent_user.focus_set()
        self.update_idletasks()
        self.center_over_parent()

    def center_over_parent(self):
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.geometry(f"+{x}+{y}")
        self.deiconify()
        self.lift()

    def on_ok(self):
        if self.logging_in:
            return
        username = self.ent_user.get()
        password = self.ent_pwd.get()
        if not username or not password:
            self.set_status("Please enter username and password")
            return

        self.set_controls_state('disabled')
        self.logging_in = True
        self.set_status("Logging in...")

        self.login_response = None

        threading.Thread(target=self.login_thread, args=(username, password), daemon=True).start()

        self.after(100, self.check_login_response)

    def on_cancel(self):
        if self.logging_in:
            return
        self.result = None
        self.grab_release()
        self.destroy()

    def login_thread(self, username, password):
        try:
            ok, result = attempt_login(username, password)
        except Exception:
            ok, result = False, "Unexpected error"
        self.login_response = (ok, result, username)

    def check_login_response(self):
        if not getattr(self, 'winfo_exists', lambda: True)():
            return

        if self.login_response is None:
            self.after(100, self.check_login_response)
            return

        ok, result, username = self.login_response
        self.login_response = None
        self.logging_in = False

        if ok:
            self.result = (username, result)
            self.grab_release()
            self.destroy()
            return
        else:
            self.set_status(f"Login failed: {result}", is_error=True)
            self.set_controls_state('normal')
            self.ent_pwd.focus_set()

    def set_controls_state(self, state):
        btn_state = ['disabled'] if state == 'disabled' else ['!disabled']
        entry_state = state

        self.ok_btn.state(btn_state)
        self.cancel_btn.state(btn_state)
        self.ent_user.config(state=entry_state)
        self.ent_pwd.config(state=entry_state)

    def set_status(self, text, is_error=False):
        try:
            if is_error:
                self.status_label.config(text=text, foreground='red')
            else:
                self.status_label.config(text=text, foreground='black')
        except Exception:
            pass

def main():
    root = tk.Tk()
    
    try:
        style = ttk.Style(root)
        style.theme_use('clam')
    except Exception:
        pass

    root.withdraw()

    while True:
        login = LoginDialog(root)
        root.wait_window(login)

        if not login.result:
            return

        username, session = login.result
        root.deiconify()
        break


    app = MailClientGUI(root, username, session)
    root.mainloop()


if __name__ == "__main__":
    main()
