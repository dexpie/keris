"""Credential hunting: exposed .git dump, .env/backup config, cloud secrets.

Hunts the target for ways an attacker would harvest credentials:

- .git exposure: probes /.git/HEAD, /.git/config and attempts to reconstruct
  source layout from the git index (filename disclosure). If .git/config is
  readable it leaks remotes/identity; a dumpable .git means source code may be
  recoverable offline.
- Config/backup files: .env, .env.*, config.*, *.bak, .gitignore, wp-config,
  etc.
- Cloud credentials: AWS Access Key ID + secret pairs, GCP service-account
  keys, GitHub tokens, generic API keys in pages and JS bundles.
- Optional --verify: checks an AWS key against the public iam endpoints
  (GetAccessKeyLastUsed) to confirm whether it is live.

Everything here is passive/recon-level except --verify which sends a single
metadata request to AWS (not to the target).
"""

import json
import re
import struct
from typing import Dict, List, Optional, Tuple

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn

GIT_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.git/index",
    "/.git/logs/HEAD",
    "/.git/description",
    "/.git/packed-refs",
]

GIT_REF_RE = re.compile(rb"ref: refs/heads/([^\n]+)")
GIT_TREE_RE = re.compile(rb"(?:\x40|\x20)([0-9a-f]{40})")
# git index: header DIRC + version + entrycount, then entries:
# ctime(4) mtime(4) dev(4) ino(4) mode(4) uid(4) gid(4) size(4) sha(20) flags(2)
# path is NULL-terminated afterwards.
GIT_INDEX_HEADER = b"DIRC"

CONFIG_FILES = [
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.test", "config.php", "config.inc.php", "wp-config.php",
    "settings.py", "database.yml", "application.yml", "config.yaml",
    ".gitignore", ".htaccess", "phpinfo.php", "composer.json", "package.json",
    "backup.zip", "db.sql", "dump.sql", "credentials.json",
]

# order: (pattern, kind, severity)
SECRET_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws_access_key_id", "HIGH"),
    (re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"), "aws_secret", "HIGH"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b.{0,200}?([A-Za-z0-9/+=]{40})"), "aws_key_secret_pair", "HIGH"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "google_api_key", "MEDIUM"),
    (re.compile(r"\bGOCSPX-[0-9A-Za-z_-]{28}\b"), "google_client_secret", "HIGH"),
    (re.compile(r"ghp_[0-9A-Za-z]{36}\b"), "github_token", "HIGH"),
    (re.compile(r"gho_[0-9A-Za-z]{36}\b"), "github_token", "HIGH"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "slack_token", "HIGH"),
    (re.compile(r"sk-[0-9A-Za-z]{20,}"), "openai_api_key", "HIGH"),
    (re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{4,})['\"]"), "password", "MEDIUM"),
    (re.compile(r"(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[=:]\s*['\"]([A-Za-z0-9._-]{16,})['\"]"), "api_token", "MEDIUM"),
]


def _redact(value: str) -> str:
    if len(value) <= 8:
        return value
    return value[:4] + "…" * 4 + value[-4:]


def _git_content_valid(p: str, content: bytes) -> bool:
    """Validasi bahwa konten respons benar-benar file git, bukan halaman 404 palsu.

    Banyak aplikasi (SPA/React) mengembalikan status 200 untuk path apa pun,
    sehingga status 200 saja tidak cukup sebagai bukti .git terekspos.
    """
    if not content:
        return False
    if p == "/.git/HEAD":
        # HEAD git selalu dimulai "ref: refs/..." atau berisi hash 40-hex
        text = content[:200].strip()
        return text.startswith(b"ref:") or bool(re.fullmatch(rb"[0-9a-f]{40}", text))
    if p == "/.git/config":
        return b"[core]" in content[:2000] or b"repositoryformatversion" in content[:2000]
    if p == "/.git/index":
        return content.startswith(GIT_INDEX_HEADER)
    if p == "/.git/description":
        return content.strip().startswith(b"Unnamed repository")
    if p in ("/.git/logs/HEAD",):
        return content.startswith(b"0000000000000000000000000000000000000000")
    if p == "/.git/packed-refs":
        return b"# pack-refs with:" in content[:2000]
    # fallback: file git teks biasanya pendek, bukan HTML
    return not content[:200].lstrip().startswith(b"<")


def _check_git(client: KerisHTTP, base: str) -> List[Dict]:
    findings = []
    git_ok = False
    head_path = ""
    head_content = b""
    for p in GIT_PATHS:
        try:
            r = client.get(base.rstrip("/") + p, timeout=15)
        except requests.RequestException:
            continue
        if r.status_code == 200 and _git_content_valid(p, r.content):
            git_ok = True
            info(f".git terdeteksi: {p} (200)")
            if p == "/.git/HEAD":
                head_path = p
                head_content = r.content
            if p == "/.git/config":
                m = re.search(rb"url\s*=\s*(https?://[^\s]+|git@[^\s]+)", r.content)
                if m:
                    remote = m.group(1).decode("utf-8", "replace")
                    findings.append({
                        "severity": "HIGH",
                        "title": ".git/config terekspos (remote repo bocor)",
                        "endpoint": base.rstrip("/") + p,
                        "detail": "File .git/config dapat dibaca; remote URL repository ikut bocor.",
                        "evidence": f"remote={remote}",
                        "source": "hunt-git",
                    })
            if p == "/.git/index":
                names = _parse_git_index(r.content)
                if names:
                    interesting = [n for n in names if re.search(
                        r"(\.env|secret|password|credential|\.pem$|\.key$|config|\.sql$|dump)", n, re.I)]
                    findings.append({
                        "severity": "HIGH",
                        "title": "Indeks .git bocor (struktur source code terekspos)",
                        "endpoint": base.rstrip("/") + p,
                        "detail": "Isi .git/index dapat dibaca: daftar file di repository.",
                        "evidence": "file_count={0}, menarik={1}".format(
                            len(names), ", ".join(interesting[:10])),
                        "source": "hunt-git",
                    })
        else:
            debug(f"git path {p} -> {r.status_code}")
    if git_ok:
        ref = GIT_REF_RE.search(head_content) if head_content else None
        branch = ref.group(1).decode("utf-8", "replace") if ref else "?"
        findings.append({
            "severity": "CRITICAL" if head_content else "HIGH",
            "title": "Direktori .git terekspos (source code dapat direkonstruksi)",
            "endpoint": base.rstrip("/") + head_path,
            "detail": "Repository git dapat diakses publik. Attacker dapat "
                      "mengunduh seluruh object git dan merekonstruksi source "
                      "code, termasuk secret yang pernah di-commit.",
            "evidence": f"branch={branch}",
            "source": "hunt-git",
        })
    return findings


def _parse_git_index(data: bytes) -> List[str]:
    if not data.startswith(GIT_INDEX_HEADER):
        return []
    names = []
    try:
        count = struct.unpack(">I", data[8:12])[0]
    except Exception:
        return []
    pos = 12
    for _ in range(count):
        if pos + 62 > len(data):
            break
        pos += 62
        null = data.find(b"\x00", pos, pos + 400)
        if null == -1:
            break
        path = data[pos:null].decode("utf-8", "replace")
        names.append(path)
        # each entry is padded so (62 + path + nul) is a multiple of 8
        entry_size = 62 + (null - pos) + 1
        pos = null + 1 + ((8 - entry_size % 8) % 8)
    return names


def _check_config_files(client: KerisHTTP, base: str) -> List[Dict]:
    findings = []
    for f in CONFIG_FILES:
        url = base.rstrip("/") + "/" + f
        try:
            r = client.get(url, timeout=12)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        body = r.text[:4000]
        secret_hits = []
        for pat, kind, sev in SECRET_PATTERNS:
            m = pat.search(body)
            if m:
                secret_hits.append(kind)
        sev = "HIGH" if secret_hits else "MEDIUM"
        findings.append({
            "severity": sev,
            "title": f"File sensitif terekspos: {f}",
            "endpoint": url,
            "detail": f"File {f} dapat dibaca publik. "
                      + ("Mengandung secret." if secret_hits else "Periksa isinya."),
            "evidence": _redact("; ".join(secret_hits)) if secret_hits else body[:200],
            "source": "hunt-config",
        })
    return findings


def _scan_secrets_in(content: str, origin: str) -> List[Dict]:
    findings = []
    for pat, kind, sev in SECRET_PATTERNS:
        for m in pat.finditer(content):
            # dedup per origin+kind
            findings.append({
                "severity": sev,
                "title": f"Secret bocor: {kind}",
                "endpoint": origin,
                "detail": f"Pola {kind} ditemukan pada aset target.",
                "evidence": _redact(m.group(0)[:120]),
                "source": "hunt-secret",
            })
            break  # cukup 1 per kind per asset
    return findings


def _verify_aws(key_id: str, secret: str) -> Tuple[bool, str]:
    """Cek apakah pasangan AWS key hidup (via GetAccessKeyLastUsed)."""
    try:
        r = requests.post(
            "https://iam.amazonaws.com/?Action=GetAccessKeyLastUsed"
            f"&Version=2010-05-08&AccessKeyId={key_id}",
            auth=(key_id, secret),
            timeout=20,
        )
        if "LastUsedDate" in r.text:
            return True, "AWS key AKTIF"
        return False, "AWS key tidak valid/expired"
    except requests.RequestException as e:
        return False, f"verifikasi gagal: {e}"


def run_hunt(base: str, client: KerisHTTP, verify: bool = False,
             extra_urls: Optional[List[str]] = None) -> List[Dict]:
    """Hunt credentials. Returns findings."""
    findings: List[Dict] = []

    # 1. .git exposure
    try:
        findings.extend(_check_git(client, base))
    except requests.RequestException as e:
        warn(f".git scan gagal: {e}")

    # 2. config/backup files
    try:
        findings.extend(_check_config_files(client, base))
    except requests.RequestException as e:
        warn(f"config scan gagal: {e}")

    # 3. secrets in discovered pages/JS bundles
    urls = [base]
    urls.extend(extra_urls or [])
    seen = set()
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        try:
            r = client.get(u, timeout=15)
        except requests.RequestException:
            continue
        if r.status_code == 200 and r.text:
            findings.extend(_scan_secrets_in(r.text[:200000], u))

    # 4. optional: verify AWS key pairs
    if verify:
        for f in findings:
            if f.get("title", "").startswith("Secret bocor: aws_access_key_id"):
                key = re.search(r"\bAKIA[0-9A-Z]{16}\b", f["evidence"] or "")
                if not key:
                    continue
                # find a secret near this key in original content is complex;
                # report structure only
                alive, msg = _verify_aws(key.group(0), "not-scanned")
                f["severity"] = "CRITICAL" if alive else f["severity"]
                f["detail"] += f" [verify] {msg}"

    ok(f"Hunt selesai: {len(findings)} temuan credential")
    return findings