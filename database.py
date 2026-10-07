import os
import sqlite3
from datetime import datetime

from config import DATABASE_FILE


def get_connection():
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE,
            mobile TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            email_verified INTEGER NOT NULL DEFAULT 0,
            mobile_verified INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            purpose TEXT NOT NULL,
            method TEXT NOT NULL,
            destination TEXT NOT NULL,
            otp_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            used INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_filename TEXT NOT NULL,
            vault_path TEXT NOT NULL UNIQUE,
            original_sha256 TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    connection.commit()
    connection.close()


def create_user(
    name,
    email,
    mobile,
    password_hash,
    password_salt
):
    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO users (
                name,
                email,
                mobile,
                password_hash,
                password_salt,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            name,
            email or None,
            mobile or None,
            password_hash,
            password_salt,
            datetime.now().isoformat(timespec="seconds")
        ))

        connection.commit()
        return cursor.lastrowid

    except sqlite3.IntegrityError:
        return None

    finally:
        connection.close()


def get_user_by_login(login_value):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM users
        WHERE email = ? OR mobile = ?
        LIMIT 1
    """, (login_value, login_value))

    user = cursor.fetchone()
    connection.close()

    return user


def get_user_by_id(user_id):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (user_id,))

    user = cursor.fetchone()
    connection.close()

    return user


def save_otp(
    user_id,
    purpose,
    method,
    destination,
    otp_hash,
    created_at,
    expires_at
):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO otp_codes (
            user_id,
            purpose,
            method,
            destination,
            otp_hash,
            created_at,
            expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        purpose,
        method,
        destination,
        otp_hash,
        created_at,
        expires_at
    ))

    connection.commit()
    otp_id = cursor.lastrowid
    connection.close()

    return otp_id


def get_active_otp(user_id, purpose, method):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM otp_codes
        WHERE user_id = ?
          AND purpose = ?
          AND method = ?
          AND used = 0
        ORDER BY id DESC
        LIMIT 1
    """, (user_id, purpose, method))

    otp = cursor.fetchone()
    connection.close()

    return otp


def increment_otp_attempts(otp_id):
    connection = get_connection()

    connection.execute("""
        UPDATE otp_codes
        SET attempts = attempts + 1
        WHERE id = ?
    """, (otp_id,))

    connection.commit()
    connection.close()


def mark_otp_used(otp_id):
    connection = get_connection()

    connection.execute("""
        UPDATE otp_codes
        SET used = 1
        WHERE id = ?
    """, (otp_id,))

    connection.commit()
    connection.close()


def mark_user_verified(user_id, method):
    connection = get_connection()

    if method == "email":
        connection.execute("""
            UPDATE users
            SET email_verified = 1
            WHERE id = ?
        """, (user_id,))

    elif method == "sms":
        connection.execute("""
            UPDATE users
            SET mobile_verified = 1
            WHERE id = ?
        """, (user_id,))

    connection.commit()
    connection.close()


def save_vault_file(
    user_id,
    original_filename,
    vault_path,
    original_sha256
):
    connection = get_connection()

    connection.execute("""
        INSERT OR REPLACE INTO vault_files (
            user_id,
            original_filename,
            vault_path,
            original_sha256,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        user_id,
        original_filename,
        vault_path,
        original_sha256,
        datetime.now().isoformat(timespec="seconds")
    ))

    connection.commit()
    connection.close()


def get_vault_owner(vault_path):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM vault_files
        WHERE vault_path = ?
        LIMIT 1
    """, (vault_path,))

    record = cursor.fetchone()
    connection.close()

    return record
