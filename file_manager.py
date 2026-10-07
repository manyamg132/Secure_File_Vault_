import os
import json
import base64
import hashlib

from crypto_utils import derive_key, generate_salt, generate_nonce
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =========================================================
# SHA-256 FILE HASH
# =========================================================

def calculate_file_sha256(file_path):
    """
    Calculate the SHA-256 hash of a file.
    """

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


# =========================================================
# ENCRYPT FILE
# =========================================================

def encrypt_file(file_path, password):
    """
    Encrypt a file using AES-256-GCM.
    """

    # Check whether file exists
    if not os.path.exists(file_path):
        raise FileNotFoundError("File not found.")

    # Read original file
    with open(file_path, "rb") as file:
        file_data = file.read()

    # Calculate SHA-256 of original file
    original_hash = calculate_file_sha256(file_path)

    # Generate random salt
    salt = generate_salt()

    # Derive AES-256 key
    key = derive_key(password, salt)

    # Generate random nonce
    nonce = generate_nonce()

    # Create AES-GCM cipher
    aesgcm = AESGCM(key)

    # Encrypt file data
    encrypted_data = aesgcm.encrypt(
        nonce,
        file_data,
        None
    )

    # Create vault file path
    vault_path = file_path + ".vault"

    # Create metadata
    metadata = {
        "version": 1,
        "original_filename": os.path.basename(file_path),
        "original_sha256": original_hash,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "algorithm": "AES-256-GCM",
        "key_derivation": "PBKDF2-HMAC-SHA256",
        "kdf_iterations": 600000
    }

    # Convert metadata to JSON
    metadata_json = json.dumps(metadata).encode("utf-8")

    # Store metadata length
    metadata_length = len(metadata_json)

    # Write vault file
    with open(vault_path, "wb") as vault:

        # First 8 bytes contain metadata length
        vault.write(metadata_length.to_bytes(8, "big"))

        # Write metadata
        vault.write(metadata_json)

        # Write encrypted file data
        vault.write(encrypted_data)

    return vault_path, original_hash


# =========================================================
# DECRYPT FILE
# =========================================================

def decrypt_file(vault_path, password):
    """
    Decrypt a .vault file.
    """

    if not os.path.exists(vault_path):
        raise FileNotFoundError("Vault file not found.")

    # Read vault file
    with open(vault_path, "rb") as vault:

        # Read metadata length
        metadata_length_bytes = vault.read(8)

        if len(metadata_length_bytes) != 8:
            raise ValueError("Invalid vault file.")

        metadata_length = int.from_bytes(
            metadata_length_bytes,
            "big"
        )

        # Read metadata
        metadata_json = vault.read(metadata_length)

        metadata = json.loads(
            metadata_json.decode("utf-8")
        )

        # Read encrypted data
        encrypted_data = vault.read()

    # Decode salt and nonce
    salt = base64.b64decode(
        metadata["salt"]
    )

    nonce = base64.b64decode(
        metadata["nonce"]
    )

    # Derive AES-256 key
    key = derive_key(password, salt)

    # Create AES-GCM cipher
    aesgcm = AESGCM(key)

    # Decrypt
    decrypted_data = aesgcm.decrypt(
        nonce,
        encrypted_data,
        None
    )

    # Determine output filename
    original_filename = metadata["original_filename"]

    directory = os.path.dirname(vault_path)

    decrypted_filename = (
        "decrypted_" + original_filename
    )

    decrypted_path = os.path.join(
        directory,
        decrypted_filename
    )

    # Save decrypted file
    with open(decrypted_path, "wb") as file:

        file.write(decrypted_data)

    return decrypted_path, metadata["original_sha256"]


# =========================================================
# VERIFY FILE INTEGRITY
# =========================================================

def verify_file_integrity(file_path, expected_hash):
    """
    Compare the SHA-256 hash of a file
    with the expected hash.
    """

    actual_hash = calculate_file_sha256(
        file_path
    )

    return actual_hash == expected_hash