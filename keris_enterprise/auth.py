"""Autentikasi & RBAC untuk keris-enterprise.

Password di-hash dengan PBKDF2-HMAC-SHA256 (stdlib `hashlib`). Role:
- `admin`    : semua akses + manajemen user
- `pentester`: jalankan scan, edit project, lihat semua
- `viewer`   : hanya baca
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Dict, List, Optional

from keris_enterprise.db import EnterpriseDB

ITERATIONS = 200_000


class Role:
    ADMIN = "admin"
    PENTESTER = "pentester"
    VIEWER = "viewer"
    ALL = (ADMIN, PENTESTER, VIEWER)
    LEVEL = {VIEWER: 1, PENTESTER: 2, ADMIN: 3}


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2${ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt_hex, dk_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iters))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


class UserStore:
    """CRUD user + sesi token berbasis HMAC (JWT-like)."""

    def __init__(self, db: EnterpriseDB, secret: str = ""):
        self.db = db
        self.secret = secret or secrets.token_hex(32)
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT,
                email TEXT,
                role TEXT,
                created_at REAL
            )
        """)

    def create_user(self, username: str, password: str,
                    role: str = Role.VIEWER, email: str = "") -> Dict:
        role = role if role in Role.ALL else Role.VIEWER
        uid = f"u-{secrets.token_hex(4)}"
        self.db.execute(
            "INSERT INTO users(id,username,password_hash,email,role,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (uid, username, hash_password(password), email, role, time.time()))
        return {"id": uid, "username": username, "role": role, "email": email}

    def list_users(self) -> List[Dict]:
        return self.db.query(
            "SELECT id,username,email,role,created_at FROM users ORDER BY username")

    def get_user(self, username: str) -> Optional[Dict]:
        rows = self.db.query(
            "SELECT id,username,password_hash,email,role FROM users "
            "WHERE username=?", (username,))
        return rows[0] if rows else None

    def update_role(self, username: str, role: str) -> bool:
        if role not in Role.ALL:
            return False
        self.db.execute("UPDATE users SET role=? WHERE username=?",
                        (role, username))
        return True

    def delete_user(self, username: str) -> bool:
        self.db.execute("DELETE FROM users WHERE username=?", (username,))
        return True

    def authenticate(self, username: str, password: str) -> Optional[Dict]:
        user = self.get_user(username)
        if not user or not verify_password(password, user["password_hash"]):
            return None
        return {"id": user["id"], "username": username, "role": user["role"],
                "email": user["email"]}

    def issue_token(self, user: Dict, ttl: int = 3600) -> str:
        header = _b64(json.dumps({"alg": "HS256"}).encode())
        payload = _b64(json.dumps({"sub": user["username"],
                                   "role": user["role"],
                                   "exp": int(time.time()) + ttl}).encode())
        signing = f"{header}.{payload}"
        sig = _b64(hmac.new(self.secret.encode(), signing.encode(),
                            hashlib.sha256).digest())
        return f"{signing}.{sig}"

    def verify_token(self, token: str) -> Optional[Dict]:
        try:
            header, body, sig = token.split(".")
            signing = f"{header}.{body}"
            expected = hmac.new(self.secret.encode(), signing.encode(),
                                hashlib.sha256).digest()
            if not hmac.compare_digest(expected, _unb64(sig)):
                return None
            payload = json.loads(_unb64(body))
            if int(payload.get("exp", 0)) < int(time.time()):
                return None
            return payload
        except Exception:
            return None

    def require(self, token: str, min_level: int = 1) -> Optional[Dict]:
        payload = self.verify_token(token)
        if not payload:
            return None
        if Role.LEVEL.get(payload.get("role", ""), 0) < min_level:
            return None
        return payload