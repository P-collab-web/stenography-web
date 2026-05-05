import base64
import secrets
from typing import Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Generates a secure key from a password using PBKDF2.

    The salt is used to make the key more secure and avoid attacks.
    This key will later be used with Fernet for encryption.

    Parameters:
        password (str): User password
        salt (bytes): Random salt

    Returns:
        bytes: Encoded key for encryption
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_message(message: str, password: str) -> Tuple[bytes, bytes]:
    """
    Encrypts a message using a password.

    A random salt is generated and used to create the encryption key.

    Parameters:
        message (str): Message to encrypt
        password (str): Password

    Returns:
        Tuple[bytes, bytes]: (salt, encrypted message)
    """
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(message.encode("utf-8"))
    return salt, encrypted


def decrypt_message(encrypted: bytes, password: str, salt: bytes) -> str:
    """
    Decrypts a message using the password and salt.

    If the password is incorrect, an error will be raised.

    Parameters:
        encrypted (bytes): Encrypted message
        password (str): Password used for encryption
        salt (bytes): Salt used to generate the key

    Returns:
        str: Decrypted message
    """
    key = derive_key(password, salt)
    f = Fernet(key)
    decrypted = f.decrypt(encrypted)
    return decrypted.decode("utf-8")