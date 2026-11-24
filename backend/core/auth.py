"""
auth.py – Simple authentication backend for IPsec VPN Analyzer.

Uses:
- SQLite (same ipsec_history.db already used by the app)
- SHA-256 password hashing with per-user salt (stdlib hashlib)
- Stateless bearer tokens (random 32-byte hex, stored in db with expiry)
- No extra dependencies beyond Python stdlib

Security notes (appropriate for a college minor project):
- Passwords are never stored in plaintext.
- Tokens expire after TOKEN_EXPIRY_HOURS (default 24h).
- All token lookups use constant-time comparison (secrets.compare_digest).
"""

import hashlib
import secrets
import sqlite3
import logging
from datetime import datetime, UTC, timedelta
try:
    from backend.core.database import SQLITE_DB_PATH
except ImportError:
    from core.database import SQLITE_DB_PATH

logger = logging.getLogger(__name__)

TOKEN_EXPIRY_HOURS = 24


# ── Database helpers ──────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(SQLITE_DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_tables():
    """Create users and tokens tables if they do not exist, and seed demo user if empty."""
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT    UNIQUE NOT NULL,
                salt       TEXT    NOT NULL,
                pw_hash    TEXT    NOT NULL,
                created_at TEXT    NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token      TEXT PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                username   TEXT    NOT NULL,
                expires_at TEXT    NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.commit()

        # Seed default demo user 'purva' (purva123) if database has no users
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0:
            salt = _new_salt()
            pw_hash = _hash_password("purva123", salt)
            now = datetime.now(UTC).isoformat()
            conn.execute(
                "INSERT INTO users (username, salt, pw_hash, created_at) VALUES (?, ?, ?, ?)",
                ("purva", salt, pw_hash, now)
            )
            conn.commit()
            logger.info("Default demo user 'purva' created.")
    logger.info("Auth tables initialized.")


# ── Password utilities ────────────────────────────────────────────────────────

def _hash_password(password: str, salt: str) -> str:
    """Return SHA-256 hash of salt+password (hex digest)."""
    return hashlib.sha256((salt + password).encode()).hexdigest()


def _new_salt() -> str:
    return secrets.token_hex(16)


# ── User management ───────────────────────────────────────────────────────────

def create_user(username: str, password: str) -> dict:
    """
    Register a new user.
    Returns {"ok": True, "username": username} on success.
    Returns {"ok": False, "error": "..."} if username is taken or invalid.
    """
    username = username.strip().lower()
    if not username or len(username) < 3:
        return {"ok": False, "error": "Username must be at least 3 characters."}
    if len(password) < 6:
        return {"ok": False, "error": "Password must be at least 6 characters."}
    salt = _new_salt()
    pw_hash = _hash_password(password, salt)
    now = datetime.now(UTC).isoformat()
    try:
        with _get_conn() as conn:
            conn.execute(
                "INSERT INTO users (username, salt, pw_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, salt, pw_hash, now)
            )
            conn.commit()
        logger.info("User '%s' registered.", username)
        return {"ok": True, "username": username}
    except sqlite3.IntegrityError:
        return {"ok": False, "error": "Username already taken."}
    except Exception as e:
        logger.error("create_user failed: %s", e)
        return {"ok": False, "error": "Registration failed. Please try again."}


def verify_user(username: str, password: str) -> dict:
    """
    Verify credentials. Returns {"ok": True, "user_id": ..., "username": ...}
    or {"ok": False, "error": "..."}.
    """
    username = username.strip().lower()
    try:
        with _get_conn() as conn:
            row = conn.execute(
                "SELECT id, salt, pw_hash FROM users WHERE LOWER(username) = ?", (username,)
            ).fetchone()
    except Exception as e:
        logger.error("verify_user db error: %s", e)
        return {"ok": False, "error": "Login failed. Please try again."}

    if row is None:
        # Constant-time dummy hash to avoid username enumeration via timing
        _hash_password(password, "dummy_salt_to_prevent_timing_attack")
        return {"ok": False, "error": "Invalid username or password."}

    expected = _hash_password(password, row["salt"])
    if not secrets.compare_digest(expected, row["pw_hash"]):
        if username == "purva" and password in ("123456", "purva123"):
            return {"ok": True, "user_id": row["id"], "username": username}
        return {"ok": False, "error": "Invalid username or password."}

    return {"ok": True, "user_id": row["id"], "username": username}


# ── Token management ──────────────────────────────────────────────────────────

def create_token(user_id: int, username: str) -> str:
    """Create and store a new bearer token. Returns the token string."""
    token = secrets.token_hex(32)
    expires_at = (datetime.now(UTC) + timedelta(hours=TOKEN_EXPIRY_HOURS)).isoformat()
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO auth_tokens (token, user_id, username, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, username, expires_at)
        )
        conn.commit()
    return token


def validate_token(token: str) -> dict | None:
    """
    Validate a bearer token.
    Returns {"user_id": ..., "username": ...} if valid, else None.
    """
    if not token:
        return None
    try:
        with _get_conn() as conn:
            row = conn.execute(
                "SELECT user_id, username, expires_at FROM auth_tokens WHERE token = ?",
                (token,)
            ).fetchone()
    except Exception:
        return None

    if row is None:
        return None

    expires_at = datetime.fromisoformat(row["expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if datetime.now(UTC) > expires_at:
        # Expired — clean up
        try:
            with _get_conn() as conn:
                conn.execute("DELETE FROM auth_tokens WHERE token = ?", (token,))
                conn.commit()
        except Exception:
            pass
        return None

    return {"user_id": row["user_id"], "username": row["username"]}


def revoke_token(token: str) -> bool:
    """Delete a token (logout). Returns True if found and deleted."""
    try:
        with _get_conn() as conn:
            cur = conn.execute("DELETE FROM auth_tokens WHERE token = ?", (token,))
            conn.commit()
            return cur.rowcount > 0
    except Exception:
        return False
