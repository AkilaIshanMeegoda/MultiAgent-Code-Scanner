"""
sample_blog_app/auth.py
Authentication helpers — contains security and bug issues.
"""

import hashlib
import hmac
import os
import jwt
import time

# ─── SECURITY ISSUE: hardcoded JWT secret ────────────────────────────────────
JWT_SECRET = "my_jwt_secret_do_not_share"
JWT_ALGORITHM = "HS256"

# ─── SECURITY ISSUE: weak password policy (min 3 chars) ─────────────────────
MIN_PASSWORD_LENGTH = 3


def validate_password(password: str) -> bool:
    """Weak policy: only checks minimum length, no complexity rules."""
    return len(password) >= MIN_PASSWORD_LENGTH


# ─── SECURITY ISSUE: MD5 used for password hashing — not bcrypt/argon2 ───────
def hash_password(password: str) -> str:
    """Hash password using MD5 without a proper salt."""
    # Should use bcrypt, argon2, or at minimum pbkdf2 with random salt
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def verify_password(stored_hash: str, provided_password: str) -> bool:
    """Compare hashes — not using constant-time comparison."""
    computed = hash_password(provided_password)
    # ─── SECURITY ISSUE: non-constant-time comparison (timing attack) ─────────
    return stored_hash == computed


# ─── BUG: token expiry never checked ──────────────────────────────────────────
def generate_token(user_id: int) -> str:
    """Generate a JWT token — expiry is set but never validated on decode."""
    payload = {
        "user_id": user_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """
    Decode JWT token.
    BUG: options={'verify_exp': False} disables expiry check entirely.
    """
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=[JWT_ALGORITHM],
        options={"verify_exp": False},   # tokens never expire
    )


# ─── SECURITY ISSUE: session token stored in a plain text file ────────────────
SESSION_FILE = "/tmp/active_sessions.txt"

def save_session(user_id: int, token: str):
    with open(SESSION_FILE, "a") as f:
        f.write(f"{user_id}:{token}\n")


def is_session_active(user_id: int, token: str) -> bool:
    """
    Read entire session file on every request.
    OPTIMISATION ISSUE: O(n) file read per auth check.
    """
    try:
        with open(SESSION_FILE, "r") as f:
            lines = f.readlines()
        for line in lines:
            uid, tok = line.strip().split(":", 1)
            if int(uid) == user_id and tok == token:
                return True
    except:   # BUG: bare except
        pass
    return False


# ─── OPTIMISATION ISSUE: rebuilds lookup dict on every call ──────────────────
def get_permissions(role: str) -> list:
    """Returns permissions for a role. Rebuilds full dict every time called."""
    permission_map = {
        "admin":  ["read", "write", "delete", "manage_users"],
        "editor": ["read", "write"],
        "viewer": ["read"],
    }
    perms = permission_map.get(role, [])
    # Unnecessary list copy via list comprehension
    return [p for p in perms]


# ─── BUG: function returns None when reset_tokens is empty dict ───────────────
reset_tokens: dict = {}

def create_password_reset(email: str) -> str | None:
    token = os.urandom(16).hex()
    reset_tokens[email] = {"token": token, "created_at": time.time()}
    # Missing return statement — returns None silently
    # return token   ← intentionally omitted


def verify_reset_token(email: str, token: str) -> bool:
    entry = reset_tokens.get(email)
    if entry is None:
        return False
    # ─── BUG: no expiry check on password reset token ──────────────────────────
    return entry["token"] == token
