"""JWT sederhana berbasis HMAC (zero-dep) untuk farm auth."""

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional

FARM_SECRET_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "farm-secret.txt")
ALGO = "HS256"


def read_secret(path: Optional[str] = None) -> str:
    """Baca atau buat secret bersama untuk master-worker."""
    secret = os.environ.get("KERIS_FARM_SECRET", "")
    if secret:
        return secret
    path = path or FARM_SECRET_FILE
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    secret = hashlib.sha256(os.urandom(32)).hexdigest()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(secret)
    except OSError:
        pass
    return secret


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def create_token(payload: Dict[str, Any], secret: str,
                 ttl: int = 86400) -> str:
    """Buat JWT (HS256)."""
    full = dict(payload)
    full["exp"] = int(time.time()) + ttl
    header = _b64(json.dumps({"alg": ALGO, "typ": "JWT"}).encode())
    body = _b64(json.dumps(full).encode())
    signing = f"{header}.{body}"
    sig = _b64(hmac.new(secret.encode(), signing.encode(),
                        hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def verify_token(token: str, secret: str) -> Optional[Dict[str, Any]]:
    """Verifikasi JWT; return payload bila valid, None bila tidak."""
    try:
        header, body, sig = token.split(".")
        signing = f"{header}.{body}"
        expected = hmac.new(secret.encode(), signing.encode(),
                            hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(sig)):
            return None
        payload = json.loads(_unb64(body))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


def require_auth(token: str, secret: str, role: str = "worker") -> Optional[Dict]:
    """Cek token; return payload bila role cocok."""
    payload = verify_token(token, secret)
    if not payload:
        return None
    if role and payload.get("role") != role:
        return None
    return payload