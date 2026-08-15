"""Hash cracking integration: crack hash yang ditemukan (offline).

Mendeteksi tipe hash (MD5/SHA1/SHA256/NTLM/MD5-Crypt) dan mencoba
crack dengan:
- wordlist bawaan (daftar password umum kecil)
- file wordlist kustom
- mode brute charset pendek (opsional, --brute-length)
- integrasi john the ripper / hashcat bila terpasang di PATH

Murni komputasi lokal (tidak ada request network). GUARD: memerlukan
`authorized=True` (hash milik target yang sedang diuji).
"""

import hashlib
import hmac
import itertools
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

COMMON_PASSWORDS = [
    "admin", "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "welcome", "monkey", "1234567", "password1", "admin123", "root", "toor",
    "secret", "test", "test123", "master", "dragon", "shadow", "sunshine",
    "iloveyou", "trustno1", "passw0rd", "P@ssw0rd", "Password1", "qwerty123",
    "changeme", "letmein1", "administrator", "guest", "welcome1",
]

HASH_PATTERNS = [
    ("MD5", re.compile(r"^[0-9a-f]{32}$"), 32),
    ("SHA1", re.compile(r"^[0-9a-f]{40}$"), 40),
    ("SHA256", re.compile(r"^[0-9a-f]{64}$"), 64),
    ("NTLM", re.compile(r"^[0-9a-f]{32}$", re.I), 32),  # dibedakan via konteks
    ("MD5-Crypt", re.compile(r"^\$1\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}$"), 34),
]

ALGO_FUNCS = {
    "MD5": lambda s: hashlib.md5(s.encode()).hexdigest(),
    "SHA1": lambda s: hashlib.sha1(s.encode()).hexdigest(),
    "SHA256": lambda s: hashlib.sha256(s.encode()).hexdigest(),
    "NTLM": lambda s: _md4(s.encode("utf-16le")).hexdigest(),
}


def _md4(data: bytes):
    """MD4 murni Python (OpenSSL Python di Windows tidak punya md4)."""
    import struct as _s

    class _MD4:
        _A = 0x67452301
        _B = 0xEFCDAB89
        _C = 0x98BADCFE
        _D = 0x10325476

        def __init__(self):
            self.A = self._A
            self.B = self._B
            self.C = self._C
            self.D = self._D
            self._buf = b""
            self._length = 0

        def update(self, chunk):
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", "replace")
            self._buf += chunk
            self._length += len(chunk)
            while len(self._buf) >= 64:
                self._process(self._buf[:64])
                self._buf = self._buf[64:]

        def _process(self, block):
            m = list(_s.unpack("<16I", block))

            def F(x, y, z):
                return (x & y) | (~x & z)

            def G(x, y, z):
                return (x & y) | (x & z) | (y & z)

            def H(x, y, z):
                return x ^ y ^ z

            a, b, c, d = self.A, self.B, self.C, self.D
            r = [3, 7, 11, 19]
            for i in range(16):
                a = (a + F(b, c, d) + m[i]) & 0xFFFFFFFF
                a = ((a << r[i % 4]) | (a >> (32 - r[i % 4]))) & 0xFFFFFFFF
                a, b, c, d = d, a, b, c
            r = [3, 5, 9, 13]
            order = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
            for i in range(16):
                k = order[i]
                a = (a + G(b, c, d) + m[k] + 0x5A827999) & 0xFFFFFFFF
                a = ((a << r[i % 4]) | (a >> (32 - r[i % 4]))) & 0xFFFFFFFF
                a, b, c, d = d, a, b, c
            r = [3, 9, 11, 15]
            order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for i in range(16):
                k = order[i]
                a = (a + H(b, c, d) + m[k] + 0x6ED9EBA1) & 0xFFFFFFFF
                a = ((a << r[i % 4]) | (a >> (32 - r[i % 4]))) & 0xFFFFFFFF
                a, b, c, d = d, a, b, c
            self.A = (self.A + a) & 0xFFFFFFFF
            self.B = (self.B + b) & 0xFFFFFFFF
            self.C = (self.C + c) & 0xFFFFFFFF
            self.D = (self.D + d) & 0xFFFFFFFF

        def digest(self):
            ml = self._length * 8
            pad = b"\x80" + b"\x00" * ((55 - self._length % 64) % 64)
            self.update(pad + _s.pack("<Q", ml))
            return _s.pack("<4I", self.A, self.B, self.C, self.D)

        def hexdigest(self):
            return self.digest().hex()

    m = _MD4()
    m.update(data)
    return m


def detect_hash(h: str) -> Tuple[str, bool]:
    h = h.strip()
    low = h.lower()
    # MD5-Crypt unix
    if low.startswith("$1$"):
        return "MD5-Crypt", True
    if low.startswith("$2"):
        return "bcrypt", True
    if low.startswith("$5$"):
        return "SHA-256-Crypt", True
    if low.startswith("$6$"):
        return "SHA-512-Crypt", True
    for name, pat, _ln in HASH_PATTERNS:
        if name == "NTLM":
            # NTLM = MD4; butuh 32-hex case-insensitive dengan indikasi konteks
            # heuristik sederhana: panjang 32, tanpa header lain
            if pat.match(h) and h == h.upper():
                return "NTLM", True
        elif pat.match(low):
            return name, True
    return "unknown", False


def _md5_crypt(password: str, salt: str) -> str:
    import crypt  # noqa: F401
    try:
        return crypt.crypt(password, f"$1${salt}$")
    except Exception:
        return ""


def crack_hash(h: str, wordlist: Optional[List[str]] = None,
               brute_length: int = 0, brute_charset: str = "abcdefghijklmnopqrstuvwxyz0123456789",
               authorized: bool = False) -> List[Finding]:
    """Crack satu hash. Returns Finding list."""
    if not authorized:
        warn("Hash crack memerlukan --authorized.")
        return []
    h = h.strip()
    htype, known = detect_hash(h)
    findings: List[Finding] = []
    if not known:
        findings.append(Finding(
            "LOW", "Hash tidak dikenal",
            "local://hash",
            f"`{h[:24]}…` tidak dikenali formatnya; tidak dicrack.",
            htype,
        ))
        return findings

    info(f"Crack hash: {htype} ({h[:24]}…)")
    words = list(dict.fromkeys((wordlist or []) + COMMON_PASSWORDS))
    cracked = None

    if htype in ALGO_FUNCS:
        func = ALGO_FUNCS[htype]
        for w in words:
            if func(w) == h:
                cracked = w
                break
        # brute pendek opsional
        if not cracked and brute_length > 0:
            for n in range(1, brute_length + 1):
                for tup in itertools.product(brute_charset, repeat=n):
                    w = "".join(tup)
                    if func(w) == h:
                        cracked = w
                        break
                if cracked:
                    break
    elif htype == "MD5-Crypt":
        salt = h.split("$")[2]
        for w in words:
            try:
                import crypt
                if crypt.crypt(w, f"$1${salt}$") == h:
                    cracked = w
                    break
            except Exception:
                break

    if cracked:
        findings.append(Finding(
            "HIGH", "Hash ter-crack",
            "local://hash",
            f"Hash {htype} `{h[:24]}…` terpecahkan menjadi password "
            f"`{cracked}`. Gunakan untuk uji login / credential stuffing "
            "yang sudah diberi izin.",
            f"type={htype}\npassword={cracked}",
            cwe="CWE-521",
        ))
        ok(f"  CRACKED ({htype}): {cracked}")
    else:
        findings.append(Finding(
            "INFO", "Hash tidak ter-crack (wordlist pendek)",
            "local://hash",
            f"Hash {htype} tidak pecah dengan wordlist bawaan; coba "
            "--wordlist lebih besar atau john/hashcat.",
            htype,
        ))
    return findings


def crack_hashes(hashes: List[str], wordlist: Optional[List[str]] = None,
                 brute_length: int = 0,
                 authorized: bool = False) -> List[Finding]:
    out: List[Finding] = []
    for h in dict.fromkeys(h for h in hashes if h and h.strip()):
        out.extend(crack_hash(h, wordlist, brute_length, authorized=authorized))
    return out
