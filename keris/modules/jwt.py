"""Decoder & analisis JWT: struktur, algoritma, weak secret, expiry."""

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
from typing import List, Optional

from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

# Wordlist kecil untuk mencoba weak secret (signature HS256/HS384/HS512)
WEAK_SECRETS = [
    "secret", "password", "123456", "12345678", "qwerty", "admin", "changeme",
    "key", "jwt", "jwtsecret", "mysecret", "supersecret", "secretkey",
    "your-256-bit-secret", "your-secret-key", "test", "test123", "letmein",
    "login", "token", "superadmin", "12345", "1234", "000000",
]

_ALG_SIGNING = {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256"}


def _b64_decode(segment: str) -> bytes:
    segment = segment.encode("utf-8")
    pad = len(segment) % 4
    if pad:
        segment += b"=" * (4 - pad)
    return base64.urlsafe_b64decode(segment)


def decode_jwt(token: str) -> Optional[dict]:
    """Decode header & payload JWT menjadi dict. None jika format tidak valid."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64_decode(parts[0]).decode("utf-8", errors="replace"))
        payload = json.loads(_b64_decode(parts[1]).decode("utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return {"header": header, "payload": payload, "parts": parts}


def _hmac_valid(parts: List[str], secret: str, alg: str) -> bool:
    alg_map = {
        "HS256": (hashlib.sha256, 64),
        "HS384": (hashlib.sha384, 96),
        "HS512": (hashlib.sha512, 128),
    }
    if alg not in alg_map:
        return False
    digestmod, block = alg_map[alg]
    signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
    try:
        sig = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    except (binascii.Error, ValueError):
        return False
    expected = hmac.new(secret.encode("utf-8"), signing_input, digestmod).digest()
    return hmac.compare_digest(sig, expected)


def analyze_jwt(token: str) -> List[Finding]:
    """Analisis keamanan JWT. Mengembalikan daftar Finding (info/laporan)."""
    findings = []
    decoded = decode_jwt(token)
    if decoded is None:
        return [Finding(
            "INFO", "JWT tidak valid formatnya",
            "jwt-token", "Token tidak memenuhi format header.payload.signature.",
            token[:80],
        )]

    header = decoded["header"]
    payload = decoded["payload"]
    parts = decoded["parts"]
    alg = str(header.get("alg", "none"))

    # 1. algoritma none / blank
    if alg.lower() == "none" or not alg:
        findings.append(Finding(
            "HIGH", "JWT algoritma 'none'",
            "jwt-header",
            "Header mengizinkan algoritma 'none' — token dapat dipalsukan tanpa signature.",
            f"alg: {alg!r}",
        ))

    # 2. algorithm confusion: HS* digunakan dengan key publik
    if alg in ("RS256", "RS384", "RS512"):
        # cek apakah token sebenarnya HS256-compatible (confusion attack)
        try:
            if _hmac_valid(parts, "null", "HS256"):
                findings.append(Finding(
                    "HIGH", "JWT algorithm confusion (RS -> HS)",
                    "jwt-signature",
                    "Token RS* cocok diverifikasi sebagai HS256 dengan secret 'null'. "
                    "Server mungkin rentan terhadap key confusion.",
                    "signature valid dengan HS256 + secret 'null'",
                ))
        except Exception:
            pass

    # 3. weak secret (HS256/384/512)
    if alg in _ALG_SIGNING:
        for secret in WEAK_SECRETS:
            if _hmac_valid(parts, secret, alg):
                findings.append(Finding(
                    "HIGH", "JWT weak secret (signature mudah ditebak)",
                    "jwt-signature",
                    f"Signature token valid dengan secret `{secret}` (alg {alg}). "
                    "Attacker dapat memalsukan token apa pun.",
                    f"alg: {alg}, secret: {secret}",
                ))
                break

    # 4. expiry & not-before
    exp = payload.get("exp")
    if isinstance(exp, str):
        try:
            exp = float(exp)
        except ValueError:
            exp = None
    now = time.time()
    if exp is None:
        findings.append(Finding(
            "MEDIUM", "JWT tanpa masa berlaku (exp)",
            "jwt-payload",
            "Klaim `exp` tidak ada - token tidak pernah kedaluwarsa.",
            f"payload keys: {list(payload)[:10]}",
        ))
    elif isinstance(exp, (int, float)) and exp < now:
        findings.append(Finding(
            "INFO", "JWT sudah kedaluwarsa",
            "jwt-payload",
            "Token sudah lewat waktu kedaluwarsa (exp).",
            f"exp: {exp}, now: {int(now)}",
        ))
    if isinstance(payload.get("nbf"), str):
        try:
            payload["nbf"] = float(payload["nbf"])
        except ValueError:
            pass
    if isinstance(payload.get("nbf"), (int, float)) and payload["nbf"] > now:
        findings.append(Finding(
            "INFO", "JWT not-before di masa depan",
            "jwt-payload",
            "Token belum aktif menurut klaim nbf.",
            f"nbf: {payload['nbf']}",
        ))

    # 5. data sensitif di payload (bukan kerentanan, tapi INFO)
    sensitive = {"password", "secret", "api_key", "apikey", "token", "private_key", "admin", "role"}
    leaked = [k for k in sensitive if k in payload]
    if leaked:
        findings.append(Finding(
            "LOW", "JWT payload berisi data sensitif",
            "jwt-payload",
            "Payload memuat nilai yang berpotensi sensitif.",
            f"keys: {leaked}",
        ))

    if not findings:
        findings.append(Finding(
            "INFO", "JWT tervalidasi (tidak ada isu signifikan)",
            "jwt-token",
            "Struktur JWT valid; tidak ada isu otomatis terdeteksi.",
            f"alg: {alg}",
        ))
    return findings


def extract_jwts(text: str) -> List[str]:
    """Ekstrak token JWT dari teks (regex)."""
    # JWT: tiga segmen base64url dipisah titik; segmen header/body >= 8 char
    pat = re.compile(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
    found = set()
    for m in pat.findall(text):
        token = m.strip()
        if decode_jwt(token) is not None:
            found.add(token)
    return sorted(found)
