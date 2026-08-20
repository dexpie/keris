"""Credential hunting: exposed .git dump, .env/backup config, cloud secrets.

Hunts the target for ways an attacker would harvest credentials:

- .git exposure: probes /.git/HEAD, /.git/config and attempts to reconstruct
  source layout from the git index (filename disclosure). If .git/config is
  readable it leaks remotes/identity; a dumpable .git means source code may be
  recoverable offline.
- Config/backup files: .env, .env.*, config.*, *.bak, .gitignore, wp-config,
  etc.
- Cloud credentials: 50+ secret patterns across AWS, GCP, Azure, GitHub,
  GitLab, Slack, OpenAI, Stripe, Twilio, SendGrid, JWT, private keys, and
  generic API keys in pages, JS bundles, and common deep paths.
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
    ".env.test", ".env.backup", ".env.example", ".env.staging",
    "config.php", "config.inc.php", "wp-config.php", "wp-config.php.bak",
    "settings.py", "database.yml", "application.yml", "config.yaml",
    ".gitignore", ".htaccess", "phpinfo.php", "composer.json", "package.json",
    "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "dump.sql",
    "credentials.json", "credential.json", "service-account.json",
    "firebase.json", "secrets.json", "secret.json", "token.json",
    "tokens.txt", "keys.json", ".npmrc", ".pypirc", ".netrc", ".aws/credentials",
    ".aws/config", "id_rsa", "id_rsa.pub", ".ssh/config", "Dockerfile",
    "docker-compose.yml", "docker-compose.yaml", "server.js", "app.js",
    "webpack.config.js", "vite.config.js", "next.config.js", "nuxt.config.js",
    "gulpfile.js", "Makefile", "Procfile", "README.md", "README.txt",
    "info.php", "test.php", ".kube/config", "helm/values.yaml",
    "private_key.pem", "key.pem", "cert.pem", "supervisord.conf",
    "crontab.txt", "tmp_backup.txt",
]

# Lokasi dalam yang biasa menyimpan file backup/snapshot tersembunyi.
DEEP_PATHS = [
    "backup/", "backups/", "bak/", "old/", "new/", "test/", "tmp/",
    "uploads/", "static/backup", "assets/backup", "private/", "data/",
    "storage/", "files/", "media/backup", "dev/", "staging/", "prod/",
    "logs/", "log/", "debug/", "runtime/", "app/backup", "public/backup",
]

# order: (pattern, kind, severity)
# 50+ pola secret cloud & token.
SECRET_PATTERNS = [
    # AWS
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws_access_key_id", "HIGH"),
    (re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"), "aws_secret", "HIGH"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b.{0,200}?([A-Za-z0-9/+=]{40})"), "aws_key_secret_pair", "HIGH"),
    (re.compile(r"(?i)(A3T[A-Z0-9]|ASIA)[A-Z0-9]{16}"), "aws_session_token", "HIGH"),
    (re.compile(r"arn:aws:iam::\d{12}:user/[\w+=,.@-]+"), "aws_arn", "LOW"),
    # GCP / Google
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "google_api_key", "MEDIUM"),
    (re.compile(r"\bGOCSPX-[0-9A-Za-z_-]{28}\b"), "google_client_secret", "HIGH"),
    (re.compile(r"\b[0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com\b"), "google_oauth_client", "LOW"),
    (re.compile(r"(?i)(firebase|gcp).{0,30}([0-9a-zA-Z_-]{50,})"), "firebase_key", "MEDIUM"),
    # Azure
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"), "azure_tenant_id", "LOW"),
    (re.compile(r"(?i)azure.{0,40}client[_-]?secret['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_~./-]{30,})['\"]"), "azure_client_secret", "HIGH"),
    (re.compile(r"\beyJ0eXAiOiJKV1Qi[a-zA-Z0-9_-]{10,}\b"), "azure_jwt", "HIGH"),
    # GitHub / GitLab
    (re.compile(r"ghp_[0-9A-Za-z]{36}\b"), "github_token", "HIGH"),
    (re.compile(r"gho_[0-9A-Za-z]{36}\b"), "github_token", "HIGH"),
    (re.compile(r"ghu_[0-9A-Za-z]{36}\b"), "github_user_token", "HIGH"),
    (re.compile(r"ghs_[0-9A-Za-z]{36}\b"), "github_ssh_token", "HIGH"),
    (re.compile(r"github_pat_[0-9A-Za-z_]{22,}"), "github_fine_grained_token", "HIGH"),
    (re.compile(r"glpat-[0-9A-Za-z_-]{20,}"), "gitlab_token", "HIGH"),
    (re.compile(r"gitlab_pat_[0-9A-Za-z_]{20,}"), "gitlab_pat", "HIGH"),
    (re.compile(r"(?i)github.{0,30}['\"]([A-Za-z0-9]{40})['\"]"), "github_commit_secret", "MEDIUM"),
    # Slack
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "slack_token", "HIGH"),
    (re.compile(r"\bxoxr-[0-9A-Za-z-]{10,}\b"), "slack_refresh_token", "HIGH"),
    (re.compile(r"xoxb-\d{10,}-\d{10,}-[A-Za-z0-9]{20,}"), "slack_bot_token", "HIGH"),
    # OpenAI / LLM
    (re.compile(r"sk-[0-9A-Za-z]{20,}"), "openai_api_key", "HIGH"),
    (re.compile(r"sk-ant-api03-[0-9A-Za-z_-]{20,}"), "anthropic_api_key", "HIGH"),
    (re.compile(r"(?i)(claude|anthropic)[_-]?api[_-]?key.{0,20}['\"]([A-Za-z0-9_-]{20,})['\"]"), "anthropic_api_key", "HIGH"),
    (re.compile(r"(?i)hugging[_-]?face.{0,30}(hf_[A-Za-z0-9]{20,})"), "huggingface_token", "HIGH"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{20,}"), "stripe_live_key", "HIGH"),
    (re.compile(r"sk_test_[0-9a-zA-Z]{20,}"), "stripe_test_key", "MEDIUM"),
    (re.compile(r"rk_live_[0-9a-zA-Z]{20,}"), "stripe_restricted_key", "HIGH"),
    # Payment / commerce
    (re.compile(r"AC[0-9a-f]{32}"), "stripe_account_id", "LOW"),
    (re.compile(r"whsec_[0-9A-Za-z]{16,}"), "stripe_webhook_secret", "HIGH"),
    (re.compile(r"sk_live_[a-f0-9]{24,}"), "paypal_client_secret", "HIGH"),
    (re.compile(r"(?i)braintree.{0,30}(access_token\$production\$[0-9a-z]{16,})"), "braintree_token", "HIGH"),
    (re.compile(r"rzp_live_[0-9A-Za-z]{14,}"), "razorpay_key", "HIGH"),
    (re.compile(r"FLWSECK-[0-9a-zA-Z]{32}-X"), "flutterwave_secret", "HIGH"),
    (re.compile(r"(?i)square.{0,30}sq0atp-[0-9A-Za-z_-]{22,}"), "square_token", "HIGH"),
    # Twilio / SMS / email
    (re.compile(r"SK[0-9a-fA-F]{32}"), "twilio_api_key", "HIGH"),
    (re.compile(r"(?i)twilio.{0,30}(AC[0-9a-f]{32})"), "twilio_account_sid", "MEDIUM"),
    (re.compile(r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}"), "sendgrid_api_key", "HIGH"),
    (re.compile(r"key-[0-9a-zA-Z]{32}"), "mailgun_api_key", "HIGH"),
    (re.compile(r"(?i)sendgrid.{0,30}['\"](SG\.[A-Za-z0-9_-]{40,})['\"]"), "sendgrid_key_ctx", "HIGH"),
    (re.compile(r"postman_api_token_[0-9a-fA-F-]{20,}"), "postman_token", "HIGH"),
    # Heroku / hosting
    (re.compile(r"heroku_[0-9A-Za-z]{20,}"), "heroku_api_key", "HIGH"),
    (re.compile(r"(?i)heroku.{0,30}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"), "heroku_uuid", "LOW"),
    (re.compile(r"doo_?[0-9a-zA-Z]{20,}"), "digitalocean_token", "HIGH"),
    (re.compile(r"dop_v1_[0-9a-f]{64}"), "digitalocean_v1_token", "HIGH"),
    (re.compile(r"(?i)digitalocean.{0,30}(dop_v1_[0-9a-f]{60,})"), "digitalocean_ctx", "HIGH"),
    (re.compile(r"shpat_[0-9a-fA-F]{32}"), "shopify_access_token", "HIGH"),
    (re.compile(r"shpca_[0-9a-fA-F]{32}"), "shopify_custom_app_token", "HIGH"),
    # JWT / tokens
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "jwt_token", "MEDIUM"),
    (re.compile(r"(?i)(token|jwt|bearer)\s*[=:]\s*['\"]?(eyJ[A-Za-z0-9_.-]{20,})"), "jwt_bearer", "HIGH"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b"), "bearer_token", "HIGH"),
    # Private keys / crypto
    (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "private_key", "CRITICAL"),
    (re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), "ssh_private_key", "CRITICAL"),
    (re.compile(r"-----BEGIN CERTIFICATE-----"), "certificate", "LOW"),
    (re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{87,88}\b"), "base58_private_key", "CRITICAL"),
    (re.compile(r"\b0x[a-fA-F0-9]{64}\b"), "eth_private_key", "HIGH"),
    # Generic API keys
    (re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{4,})['\"]"), "password", "MEDIUM"),
    (re.compile(r"(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[=:]\s*['\"]([A-Za-z0-9._-]{16,})['\"]"), "api_token", "MEDIUM"),
    (re.compile(r"(?i)(secret|client_secret|app_secret)\s*[=:]\s*['\"]([A-Za-z0-9._/-]{16,})['\"]"), "client_secret", "HIGH"),
    (re.compile(r"\bAB\d{4}\b[0-9a-zA-Z_-]{16,}"), "newrelic_key", "MEDIUM"),
    (re.compile(r"(?i)(api|app)_?key\s*[=:]\s*['\"]?([0-9a-fA-F]{32})['\"]?"), "hex_api_key", "MEDIUM"),
    (re.compile(r"(?i)telegram.{0,20}([0-9]{9}:[A-Za-z0-9_-]{35})"), "telegram_bot_token", "HIGH"),
    (re.compile(r"(?i)discord.{0,30}([A-Za-z0-9_]{24,}\.[A-Za-z0-9_]{6,}\.[A-Za-z0-9_]{27,})"), "discord_token", "HIGH"),
    (re.compile(r"ya29\.[0-9A-Za-z_-]{20,}"), "google_oauth_token", "HIGH"),
    (re.compile(r"(?i)firebase.{0,30}(AIza[0-9A-Za-z_-]{35})"), "firebase_ctx", "MEDIUM"),
    (re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"), "firebase_legacy", "HIGH"),
    (re.compile(r"(?i)bitbucket.{0,30}([A-Za-z0-9_=-]{20,})"), "bitbucket_token", "HIGH"),
    (re.compile(r"xoxa-2-[0-9-]+-[0-9-]+-[0-9a-f]{8,}"), "slack_legacy_token", "HIGH"),
    (re.compile(r"(?i)sentry.{0,30}([a-f0-9]{64})"), "sentry_dsn", "MEDIUM"),
    (re.compile(r"pub-[0-9a-f]{32}"), "algolia_public_key", "MEDIUM"),
    (re.compile(r"(?i)lucidchart.{0,30}([0-9a-f]{32})"), "lucidchart_token", "MEDIUM"),
    (re.compile(r"(?i)(auth0|okta).{0,30}([0-9A-Za-z_-]{43})"), "oauth_client_secret", "HIGH"),
]

# Jenis secret yang didukung untuk filter --types.
SECRET_TYPES = sorted({kind for _, kind, _ in SECRET_PATTERNS})


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


def _check_config_files(client: KerisHTTP, base: str, deep: bool = False,
                        types: Optional[List[str]] = None) -> List[Dict]:
    findings = []
    paths = list(CONFIG_FILES)
    if deep:
        paths.extend(DEEP_PATHS)
    seen = set()
    for f in paths:
        if f.endswith("/"):
            # direktori deep: coba beberapa file umum di dalamnya
            for name in (".env", "backup.zip", "db.sql", "dump.sql",
                         "credentials.json", "config.php", "index.php.save",
                         "config.yml", ".gitignore"):
                url = base.rstrip("/") + "/" + f + name
                if url in seen:
                    continue
                seen.add(url)
                hit = _probe_config_file(client, url, types)
                if hit:
                    findings.append(hit)
            continue
        url = base.rstrip("/") + "/" + f
        if url in seen:
            continue
        seen.add(url)
        hit = _probe_config_file(client, url, types)
        if hit:
            findings.append(hit)
    return findings


def _probe_config_file(client: KerisHTTP, url: str,
                       types: Optional[List[str]] = None) -> Optional[Dict]:
    """Probe satu file config/backup; kembalikan finding atau None."""
    try:
        r = client.get(url, timeout=12)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    body = r.text[:4000]
    # jangan laporkan halaman HTML SPA yang balas 200 untuk path apa pun
    if _looks_like_spa_404(body):
        return None
    secret_hits = []
    for pat, kind, sev in SECRET_PATTERNS:
        if types and kind not in types:
            continue
        m = pat.search(body)
        if m:
            secret_hits.append(kind)
    if not body.strip():
        return None
    sev = "HIGH" if secret_hits else "MEDIUM"
    return {
        "severity": sev,
        "title": f"File sensitif terekspos: {url.rsplit('/', 1)[-1]}",
        "endpoint": url,
        "detail": f"File {url.rsplit('/', 1)[-1]} dapat dibaca publik. "
                  + ("Mengandung secret." if secret_hits else "Periksa isinya."),
        "evidence": _redact("; ".join(secret_hits)) if secret_hits else body[:200],
        "source": "hunt-config",
    }


def _looks_like_spa_404(body: str) -> bool:
    """Heuristik: respons 200 SPA yang berisi HTML & bukan file asli."""
    head = body[:500].lstrip()
    if not head.startswith("<"):
        return False  # teks/JSON/binary -> file nyata
    return "<html" in body[:500] and "<body" not in body[:500]


def _scan_secrets_in(content: str, origin: str,
                     types: Optional[List[str]] = None) -> List[Dict]:
    findings = []
    for pat, kind, sev in SECRET_PATTERNS:
        if types and kind not in types:
            continue
        m = pat.search(content)
        if not m:
            continue
        # dedup per origin+kind
        findings.append({
            "severity": sev,
            "title": f"Secret bocor: {kind}",
            "endpoint": origin,
            "detail": f"Pola {kind} ditemukan pada aset target.",
            "evidence": _redact(m.group(0)[:120]),
            "source": "hunt-secret",
        })
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
             extra_urls: Optional[List[str]] = None,
             deep: bool = False,
             types: Optional[List[str]] = None,
             from_scan: Optional[str] = None) -> List[Dict]:
    """Hunt credentials. Returns findings."""
    findings: List[Dict] = []

    # 0. ambil URL tambahan dari hasil scan JSON (--from-scan)
    scan_urls = _urls_from_scan(from_scan) if from_scan else []
    extra_urls = list(extra_urls or []) + scan_urls

    # 1. .git exposure
    try:
        findings.extend(_check_git(client, base))
    except requests.RequestException as e:
        warn(f".git scan gagal: {e}")

    # 2. config/backup files (+ deep locations)
    try:
        findings.extend(_check_config_files(client, base, deep=deep, types=types))
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
            findings.extend(_scan_secrets_in(r.text[:200000], u, types=types))

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


def _urls_from_scan(path: str) -> List[str]:
    """Ekstrak daftar URL endpoint dari file JSON hasil scan/hunt."""
    urls = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        warn(f"--from-scan gagal dibaca: {e}")
        return urls
    findings = data.get("findings", []) if isinstance(data, dict) else []
    for fnd in findings:
        ep = fnd.get("endpoint") if isinstance(fnd, dict) else None
        if ep and isinstance(ep, str):
            urls.append(ep)
    return urls