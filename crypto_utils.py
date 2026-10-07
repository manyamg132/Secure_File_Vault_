import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =========================================================
# SHA-256
# =========================================================

def calculate_sha256(data: bytes) -> str:
    """
    Calculate SHA-256 hash of the given data.
    """

    return hashlib.sha256(data).hexdigest()


# =========================================================
# Generate random salt
# =========================================================

def generate_salt() -> bytes:
    """
    Generate a secure random 16-byte salt.
    """

    return os.urandom(16)


# =========================================================
# Generate random nonce
# =========================================================

def generate_nonce() -> bytes:
    """
    Generate a secure random 12-byte nonce for AES-GCM.
    """

    return os.urandom(12)


# =========================================================
# Derive AES-256 key from password
# =========================================================

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from the user's password
    using PBKDF2-HMAC-SHA256.
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000
    )

    return kdf.derive(password.encode("utf-8"))


# =========================================================
# AES-256-GCM ENCRYPTION
# =========================================================

def encrypt_data(data: bytes, password: str):
    """
    Encrypt data using AES-256-GCM.
    """

    # Generate random salt
    salt = generate_salt()

    # Generate AES-256 key
    key = derive_key(password, salt)

    # Generate random nonce
    nonce = generate_nonce()

    # Create AES-GCM cipher
    aesgcm = AESGCM(key)

    # Encrypt data
    encrypted_data = aesgcm.encrypt(
        nonce,
        data,
        None
    )

    # Calculate SHA-256 of original data
    sha256_hash = calculate_sha256(data)

    return encrypted_data, salt, nonce, sha256_hash


# =========================================================
# AES-256-GCM DECRYPTION
# =========================================================

def decrypt_data(
    encrypted_data: bytes,
    password: str,
    salt: bytes,
    nonce: bytes
):
    """
    Decrypt data using AES-256-GCM.
    """

    # Generate the same AES-256 key
    key = derive_key(password, salt)

    # Create AES-GCM cipher
    aesgcm = AESGCM(key)

    # Decrypt the data
    decrypted_data = aesgcm.decrypt(
        nonce,
        encrypted_data,
        None
    )

    return decrypted_data