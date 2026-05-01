import sqlite3
import os
import getpass
import hashlib
from typing import List, Optional
from crypto import generate_salt, encrypt, decrypt

DB_PATH = 'passman.db'
# We will store master salt and verifier in meta table, and per-password salt+blob in passwords table.

class Database:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self._ensure_schema()

    def _ensure_schema(self):
        cur = self.conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value BLOB
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                service TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                secret BLOB NOT NULL
            )
        ''')
        self.conn.commit()

    # --- Master password helpers ---
    def _set_meta(self, key: str, value: bytes):
        cur = self.conn.cursor()
        cur.execute('REPLACE INTO meta(key, value) VALUES (?, ?)', (key, value))
        self.conn.commit()

    def _get_meta(self, key: str) -> Optional[bytes]:
        cur = self.conn.cursor()
        cur.execute('SELECT value FROM meta WHERE key = ?', (key,))
        row = cur.fetchone()
        return row[0] if row else None

    def _hash_master(self, master_password: str, salt: bytes) -> bytes:
        # Use PBKDF2 to produce verifier (store as bytes)
        dk = hashlib.pbkdf2_hmac('sha256', master_password.encode('utf-8'), salt, 390000)
        return dk

    def has_master(self) -> bool:
        return self._get_meta('master_salt') is not None

    def init_master_password(self):
        if self.has_master():
            print("Master password already set.")
            return
        while True:
            pw = getpass.getpass("Enter new master password: ")
            pw2 = getpass.getpass("Confirm master password: ")
            if not pw:
                print("Master password cannot be empty.")
                continue
            if pw != pw2:
                print("Passwords do not match. Try again.")
                continue
            break
        salt = generate_salt()
        verifier = self._hash_master(pw, salt)
        self._set_meta('master_salt', salt)
        self._set_meta('master_verifier', verifier)
        print("Master password initialized.")

    def verify_master(self, master_password: str) -> bool:
        salt = self._get_meta('master_salt')
        verifier = self._get_meta('master_verifier')
        if not salt or not verifier:
            return False
        check = self._hash_master(master_password, salt)
        return hashlib.compare_digest(check, verifier)

    # --- Password operations ---
    def add_password(self, service: str, password_plain: str):
        if not self.has_master():
            print("Master password not initialized. Run: python passman.py init")
            return
        master_pw = getpass.getpass("Enter master password: ")
        master_salt = self._get_meta('master_salt')
        if not self.verify_master(master_pw):
            print("Master password incorrect.")
            return
        salt = generate_salt()  # salt used to derive Fernet key for this entry
        secret = encrypt(password_plain, master_pw, salt)
        cur = self.conn.cursor()
        try:
            cur.execute('INSERT INTO passwords(service, salt, secret) VALUES (?, ?, ?)', (service, salt, secret))
            self.conn.commit()
            print(f"Added password for '{service}'.")
        except sqlite3.IntegrityError:
            print(f"Service '{service}' already exists. Use update to change password.")

    def get_password(self, service: str) -> Optional[str]:
        if not self.has_master():
            print("Master password not initialized. Run: python passman.py init")
            return None
        master_pw = getpass.getpass("Enter master password: ")
        if not self.verify_master(master_pw):
            print("Master password incorrect.")
            return None
        cur = self.conn.cursor()
        cur.execute('SELECT salt, secret FROM passwords WHERE service = ?', (service,))
        row = cur.fetchone()
        if not row:
            return None
        salt, secret = row
        try:
            return decrypt(secret, master_pw, salt)
        except Exception as e:
            print("Failed to decrypt. Possibly wrong master password or corrupted data.")
            return None

    def list_services(self) -> List[str]:
        cur = self.conn.cursor()
        cur.execute('SELECT service FROM passwords ORDER BY service')
        rows = cur.fetchall()
        return [r[0] for r in rows]

    def update_password(self, service: str, new_password: str):
        if not self.has_master():
            print("Master password not initialized. Run: python passman.py init")
            return
        master_pw = getpass.getpass("Enter master password: ")
        if not self.verify_master(master_pw):
            print("Master password incorrect.")
            return
        cur = self.conn.cursor()
        cur.execute('SELECT service FROM passwords WHERE service = ?', (service,))
        if not cur.fetchone():
            print(f"No entry for service '{service}'. Use add to create it.")
            return
        salt = generate_salt()
        secret = encrypt(new_password, master_pw, salt)
        cur.execute('UPDATE passwords SET salt = ?, secret = ? WHERE service = ?', (salt, secret, service))
        self.conn.commit()
        print(f"Updated password for '{service}'.")

    def delete_password(self, service: str):
        cur = self.conn.cursor()
        cur.execute('DELETE FROM passwords WHERE service = ?', (service,))
        if cur.rowcount:
            self.conn.commit()
            print(f"Deleted '{service}'.")
        else:
            print(f"No entry for service '{service}'.")
