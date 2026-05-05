import base64
import secrets
from typing import Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_message(message: str, password: str) -> Tuple[bytes, bytes]:
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(message.encode("utf-8"))
    return salt, encrypted


def decrypt_message(encrypted: bytes, password: str, salt: bytes) -> str:
    key = derive_key(password, salt)
    f = Fernet(key)
    decrypted = f.decrypt(encrypted)
    return decrypted.decode("utf-8")
