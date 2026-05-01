import os
import base64
from typing import Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

BACKEND = default_backend()
ITERATIONS = 390000  # secure default
SALT_SIZE = 16

def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte key from password+salt using PBKDF2-HMAC-SHA256.
    Returns urlsafe_base64-encoded key suitable for Fernet.
    """
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=BACKEND
    )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)

def get_fernet(password: str, salt: bytes) -> Fernet:
    key = derive_key(password, salt)
    return Fernet(key)

def encrypt(password_plain: str, master_password: str, salt: bytes) -> bytes:
    f = get_fernet(master_password, salt)
    return f.encrypt(password_plain.encode('utf-8'))

def decrypt(token: bytes, master_password: str, salt: bytes) -> str:
    f = get_fernet(master_password, salt)
    return f.decrypt(token).decode('utf-8')
