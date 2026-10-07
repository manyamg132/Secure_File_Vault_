import base64
import hashlib
import hmac
import os


PASSWORD_ITERATIONS = 600_000


def hash_password(password):
    salt = os.urandom(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS
    )

    return (
        base64.b64encode(password_hash).decode("utf-8"),
        base64.b64encode(salt).decode("utf-8")
    )


def verify_password(password, stored_hash, stored_salt):
    try:
        expected_hash = base64.b64decode(stored_hash)
        salt = base64.b64decode(stored_salt)

        actual_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PASSWORD_ITERATIONS
        )

        return hmac.compare_digest(
            actual_hash,
            expected_hash
        )

    except Exception:
        return False
