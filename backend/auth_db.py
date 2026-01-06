# auth_db.py — FINAL & CORRECT AUTH MODULE
# Users + Email OTP verification
# No admin approval required

import sqlite3
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from werkzeug.security import generate_password_hash, check_password_hash
from db_helpers import DB_PATH


# ------------------------------------------------------------
# Database Connection Helper
# ------------------------------------------------------------
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ------------------------------------------------------------
# Database Initialization
# ------------------------------------------------------------
def init_auth_db():
    conn = get_conn()
    cur = conn.cursor()

    # Users table (WITH is_verified)
    cur.execute("""
       CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT,
    role TEXT NOT NULL CHECK(role IN ('user','admin')),
    is_active INTEGER NOT NULL DEFAULT 0,
    is_verified INTEGER NOT NULL DEFAULT 0,
    totp_secret TEXT,
    created_at TEXT NOT NULL
)

    """)

    # Email OTP table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS twofa_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()

    # Seed default admin
    cur.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    if not cur.fetchone():
        import os
        email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@example.com")
        password = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin123!")
        now = datetime.utcnow().isoformat()

        cur.execute("""
            INSERT INTO users (
                email, password_hash, full_name,
                role, is_active, is_verified, created_at
            )
            VALUES (?, ?, ?, 'admin', 1, 1, ?)
        """, (
            email,
            generate_password_hash(password),
            "Default Admin",
            now
        ))
        conn.commit()
        print(f"✅ Default admin created: {email} / {password}")

    conn.close()


# ------------------------------------------------------------
# User Helpers
# ------------------------------------------------------------
def create_user(email, password, full_name):
    conn = get_conn()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()

    try:
        cur.execute("""
            INSERT INTO users (
                email, password_hash, full_name,
                role, is_active, is_verified, created_at
            )
            VALUES (?, ?, ?, 'user', 1, 0, ?)
        """, (
            email,
            generate_password_hash(password),
            full_name,
            now
        ))
        conn.commit()
        return {"ok": True, "user_id": cur.lastrowid}
    except sqlite3.IntegrityError:
        return {"ok": False, "error": "Email already registered"}
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def verify_password(user: Dict[str, Any], password: str) -> bool:
    return check_password_hash(user["password_hash"], password)


def mark_user_verified(user_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET is_verified = 1 WHERE id = ?",
        (int(user_id),)
    )
    conn.commit()
    conn.close()


# ------------------------------------------------------------
# Email OTP (Verification)
# ------------------------------------------------------------
def create_email_otp(user_id: int, minutes_valid: int = 5) -> str:
    conn = get_conn()
    cur = conn.cursor()

    code = f"{secrets.randbelow(1_000_000):06d}"
    expires_at = (datetime.utcnow() + timedelta(minutes=minutes_valid)).isoformat()

    cur.execute("""
        INSERT INTO twofa_codes (user_id, code, expires_at, used)
        VALUES (?, ?, ?, 0)
    """, (
        int(user_id),
        code,
        expires_at
    ))

    conn.commit()
    conn.close()
    return code


def verify_email_otp(user_id: int, code: str) -> bool:
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, expires_at, used
        FROM twofa_codes
        WHERE user_id = ? AND code = ?
        ORDER BY id DESC
        LIMIT 1
    """, (
        int(user_id),
        code
    ))

    row = cur.fetchone()
    if not row:
        conn.close()
        return False

    if row["used"]:
        conn.close()
        return False

    if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
        conn.close()
        return False

    cur.execute(
        "UPDATE twofa_codes SET used = 1 WHERE id = ?",
        (row["id"],)
    )
    conn.commit()
    conn.close()

    return True   # ✅ THIS WAS MISSING



    # ------------------------------------------------------------
# Account Activation (OTP verified)
# ------------------------------------------------------------
def activate_user(user_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET is_active = 1, is_verified = 1 WHERE id = ?",
        (int(user_id),)
    )
    conn.commit()
    conn.close()
    return True



def store_totp_secret(user_id: int, secret: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET totp_secret = ? WHERE id = ?",
        (secret, user_id)
    )
    conn.commit()
    conn.close()

def activate_user(user_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET is_active = 1 WHERE id = ?",
        (user_id,)
    )
    conn.commit()
    conn.close()


def store_totp_secret(user_id: int, secret: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET totp_secret = ? WHERE id = ?",
        (secret, int(user_id))
    )
    conn.commit()
    conn.close()


def get_user_by_id(user_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (int(user_id),))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def list_users():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, email, full_name, role, is_active, is_verified, created_at
        FROM users
        ORDER BY created_at DESC
    """)
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def set_user_active(user_id: int, active: bool):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if active else 0, int(user_id)))
    conn.commit()
    conn.close()


def delete_user(user_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (int(user_id),))
    conn.commit()
    conn.close()


def admin_reset_password(user_id: int, new_password: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), int(user_id)),
    )
    conn.commit()
    conn.close()


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (int(user_id),))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None



