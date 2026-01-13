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
    """
    Automatski generira nonce, šifrira data i pošalje preko sock
    """
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

    print("[DEBUG] AES KEY:", aes_key.hex())
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

def save_local_mails(username, mails):
    path = user_mailfile(username)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(mails, f, ensure_ascii=False, indent=2)

def make_msg_id(from_user, subject, content, timestamp):
    base = (str(from_user) + (subject or "") + (content or "") + (timestamp or "")).encode('utf-8')
    return hashlib.sha256(base).hexdigest()

def normalize_incoming_mail(m):
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

def format_timestamp(ts):
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return dt.strftime('%d.%m.%Y. %H:%M')
    except Exception:
        return ts

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
        if not messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            return

        self.root.withdraw()

        self.username = None
        self.session = None

        self.root.after(0, self._show_login_again)

    def _show_login_again(self):
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
        threading.Thread(target=self._fetch_mail_worker, daemon=True).start()

    def _fetch_mail_worker(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((SERVER_ADDRESS, SERVER_PORT))

                aesgcm = perform_handshake_and_get_aes(sock)
                payload = json.dumps({'type':'fetch','session': self.session}).encode()

                aesgcm_encrypt_send(aesgcm, sock, payload)

                plain = aesgcm_recv_decrypt(aesgcm, sock)
                if plain is None:
                    messagebox.showerror("Error", "No response from server.")
                    return
                
                data = json.loads(plain.decode())
                msgs = data.get('messages', [])

                normalized = [normalize_incoming_mail(m) for m in msgs]

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
                self.root.after(600, self.hide_loader)
        except Exception as e:
            self.root.after(600, self.hide_loader)
            messagebox.showerror("Error", f"Fetch failed: {e}")

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

        btn = ttk.Button(frm, text="Send", command=self.do_send)
        btn.grid(row=4, column=1, sticky='e', pady=6)

        frm.columnconfigure(1, weight=1)
        frm.rowconfigure(3, weight=1)

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
                aesgcm_encrypt_send(aesgcm, sock, bytes_to_send)
                
                plain = aesgcm_recv_decrypt(aesgcm, sock)
                if plain is None:
                    messagebox.showwarning("Unknown send status", "Server did not send status.")
                    return

                resp = json.loads(plain.decode())
                if resp.get('status') == 'ok':
                    self.root.after(0, lambda: self.clear_send_fields())
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

def attempt_login(username, password):
    """
    Pokušaj login-a. Za probleme s konekcijom vraća čistu poruku
    'Login error: Cant connect to server' umjesto sirovog WinError/OS poruke.
    """
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
        return False, "Login error: Cant connect to server"
    except OSError as e:
        if getattr(e, 'errno', None) in (
            errno.ECONNREFUSED, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNRESET
        ):
            return False, "Login error: Cant connect to server"
        return False, "Login error: Unable to login"
    except Exception as e:
        print("Unexpected login error:", repr(e))
        return False, "Login error: Unable to login"
    
class LoginDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.result = None

        self.title("Login")
        self.resizable(False, False)

        self._logging = False
        self._login_response = None

        try:
            if getattr(self.parent, 'winfo_ismapped', None) and self.parent.winfo_ismapped():
                self.transient(self.parent)
        except Exception:
            pass

        self.deiconify()
        self.lift()
        try:
            self.attributes("-topmost", True)
            self.after(100, lambda: self.attributes("-topmost", False))
        except Exception:
            pass

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

        self.bind("<Return>", lambda e: self.on_ok())
        self.bind("<Escape>", lambda e: self.on_cancel())

        try:
            self.grab_set()
        except Exception:
            pass

        self.ent_user.focus_set()
        self.update_idletasks()
        self.center_over_parent()

    def center_over_parent(self):
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        try:
            if getattr(self.parent, 'winfo_ismapped', None) and self.parent.winfo_ismapped():
                pw = self.parent.winfo_width()
                ph = self.parent.winfo_height()
                px = self.parent.winfo_rootx()
                py = self.parent.winfo_rooty()
                x = px + max(0, (pw - w) // 2)
                y = py + max(0, (ph - h) // 2)
            else:
                sw = self.winfo_screenwidth()
                sh = self.winfo_screenheight()
                x = max(0, (sw - w) // 2)
                y = max(0, (sh - h) // 2)
            self.geometry(f"+{x}+{y}")
            self.deiconify()
            self.lift()
        except Exception:
            sw = self.winfo_screenwidth()
            sh = self.winfo_screenheight()
            x = max(0, (sw - w) // 2)
            y = max(0, (sh - h) // 2)
            self.geometry(f"+{x}+{y}")
            self.deiconify()
            self.lift()

    def on_ok(self):
        if self._logging:
            return
        username = self.ent_user.get()
        password = self.ent_pwd.get()
        if not username or not password:
            self.set_status("Please enter username and password")
            return

        self._set_controls_state('disabled')
        self._logging = True
        self.set_status("Logging in...")

        self._login_response = None

        threading.Thread(target=self._login_worker, args=(username, password), daemon=True).start()

        self.after(100, self._poll_login_response)

    def on_cancel(self):
        if self._logging:
            return
        self.result = None
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

    def _login_worker(self, username, password):
        try:
            ok, result = attempt_login(username, password)
        except Exception as e:
            ok, result = False, str(e)
        self._login_response = (ok, result, username)

    def _poll_login_response(self):
        """
        Called on the main thread via after(): checks whether worker filled
        self._login_response. If not, schedule another check.
        """
        if not getattr(self, 'winfo_exists', lambda: True)():
            return

        if self._login_response is None:
            self.after(100, self._poll_login_response)
            return

        ok, result, username = self._login_response
        self._login_response = None
        self._logging = False

        if ok:
            self.result = (username, result)
            try:
                self.grab_release()
            except Exception:
                pass
            self.destroy()
            return
        else:
            self.set_status(f"Login failed: {result}", is_error=True)
            self._set_controls_state('normal')
            self.ent_pwd.focus_set()

    def _set_controls_state(self, state):
        try:
            if state == 'disabled':
                try:
                    self.ok_btn.state(['disabled'])
                except Exception:
                    self.ok_btn.config(state='disabled')
                try:
                    self.cancel_btn.state(['disabled'])
                except Exception:
                    self.cancel_btn.config(state='disabled')
                try:
                    self.ent_user.config(state='disabled')
                    self.ent_pwd.config(state='disabled')
                except Exception:
                    pass
            else:
                try:
                    self.ok_btn.state(['!disabled'])
                except Exception:
                    self.ok_btn.config(state='normal')
                try:
                    self.cancel_btn.state(['!disabled'])
                except Exception:
                    self.cancel_btn.config(state='normal')
                try:
                    self.ent_user.config(state='normal')
                    self.ent_pwd.config(state='normal')
                except Exception:
                    pass
        except Exception:
            pass

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
