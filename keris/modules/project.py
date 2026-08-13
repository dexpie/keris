"""Self-audit proyek: scan kode lokal untuk pola kerentanan umum.

Dirancang untuk dua pemakaian:
  1. CLI: `keris project scan <dir>` menghasilkan laporan Markdown/JSON.
  2. Agent AI (Claude Code, Codex, dll): `keris project scan <dir> --json`
     menghasilkan JSON yang mudah dibaca dan diambil tindakan.

Ini STATIC analysis berbasis pola (bukan bukti eksekusi). Hasilnya adalah
titik perhatian yang harus diverifikasi manusia.
"""

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from keris.core.logger import debug, info, ok, warn

# Ekstensi yang di-scan
SCAN_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go", ".java",
    ".c", ".cpp", ".cs", ".sql", ".sh", ".env",
}

# Folder yang dilewati
SKIP_DIRS = {".git", "node_modules", "vendor", "venv", ".venv", "dist",
             "build", "__pycache__", ".next", ".nuxt", ".idea", ".vscode",
             "coverage", "target", ".tox", "minified"}

# Pola kerentanan: (nama, pola regex, severity, deskripsi)
PATTERNS: List[dict] = [
    {"name": "SQL injection (string concatenation)",
     "regex": r"(SELECT|INSERT|UPDATE|DELETE|WHERE).{0,80}\+\s*[a-zA-Z_$#\"]",
     "severity": "HIGH",
     "desc": "Query SQL dibangun dengan concatenation - rawan SQL injection."},
    {"name": "SQL injection (f-string/format)",
     "regex": r"((SELECT|INSERT|UPDATE|DELETE|WHERE).{0,60}(f[\"']|\.format\()).{0,120}",
     "severity": "HIGH",
     "desc": "Query SQL memakai f-string/format dengan variabel."},
    {"name": "Shell execution (os.system/subprocess/shell)",
     "regex": r"(os\.system|subprocess\.(call|run|Popen)|eval|exec|spawn|shell\s*=\s*True)",
     "severity": "MEDIUM",
     "desc": "Eksekusi shell/command — pastikan input tidak dapat dikendalikan user."},
    {"name": "Hardcoded secret",
     "regex": r"(?i)(password|passwd|pwd|secret|api[_-]?key|token|private[_-]?key|access[_-]?key)\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']",
     "severity": "HIGH",
     "desc": "Kemungkinan secret tertanam di kode. Gunakan env variable / secret manager."},
    {"name": "Hardcoded AWS key",
     "regex": r"(AKIA|ASIA)[0-9A-Z]{16}",
     "severity": "CRITICAL",
     "desc": "Access key AWS terdeteksi. Cabut segera dan rotasi kredensial."},
    {"name": "Hardcoded private key",
     "regex": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
     "severity": "CRITICAL",
     "desc": "Kunci privat tertanam di repositori."},
    {"name": "Insecure deserialization",
     "regex": r"(pickle\.loads?|yaml\.load\s*\(|json\.loads?\s*\(|unserialize\s*\(|marshal\.loads)",
     "severity": "MEDIUM",
     "desc": "Deserialisasi input — rawan RCE bila input dari user."},
    {"name": "Command injection (subprocess shell)",
     "regex": r"subprocess\.[a-z]+\([^)]*(shell\s*=\s*True|cmd)",
     "severity": "HIGH",
     "desc": "Perintah shell dijalankan — rawan command injection."},
    {"name": "XSS (innerHTML / dangerouslySetInnerHTML / document.write)",
     "regex": r"(innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|v-html)",
     "severity": "MEDIUM",
     "desc": "Rendering HTML dari variabel — rawan XSS bila input user."},
    {"name": "Insecure redirect",
     "regex": r"(window\.location\s*=\s*|location\.href\s*=\s*|redirect\s*\().*(param|query|searchParams|req\.query)",
     "severity": "MEDIUM",
     "desc": "Redirect menggunakan input — rawan open redirect."},
    {"name": "Insecure file inclusion",
     "regex": r"(include\s*\(|require\s*\(|file_get_contents\s*\(|readfile\s*\().*(\$|#|\{|%)",
     "severity": "HIGH",
     "desc": "Inklusi/akses file dengan variabel — rawan LFI/path traversal."},
    {"name": "HTTP tanpa verifikasi TLS",
     "regex": r"(verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*,\s*false|rejectUnauthorized:\s*false)",
     "severity": "MEDIUM",
     "desc": "Verifikasi TLS dimatikan — rawan man-in-the-middle."},
    {"name": "CORS wildcard + credentials",
     "regex": r"(Access-Control-Allow-Origin.{0,20}\*|allowedOrigins.{0,20}\*).{0,80}(credentials|cookies)",
     "severity": "MEDIUM",
     "desc": "CORS terlalu longgar dengan kredensial — rawan serangan cross-origin."},
    {"name": "eval/Function constructor (JS)",
     "regex": r"(new\s+Function\s*\(|eval\s*\()",
     "severity": "MEDIUM",
     "desc": "Evaluasi kode dinamis — rawan code injection."},
    {"name": "Weak auth: basic auth hardcoded",
     "regex": r"(?i)(Authorization\s*:\s*['\"]Basic|b['\"]?Basic\s)",
     "severity": "LOW",
     "desc": "Basic auth digunakan — cek kredensial tidak di-hardcode."},
    {"name": "Debug mode production",
     "regex": r"(DEBUG\s*=\s*True|debug\s*=\s*True|app\.debug\s*=\s*True)",
     "severity": "MEDIUM",
     "desc": "Mode debug aktif — bisa membocorkan info & merusak performa."},
    {"name": "Date/time non-UTC",
     "regex": r"(datetime\.now\(\)|date\(\s*\)\s*\.format|time\.localtime)",
     "severity": "LOW",
     "desc": "Waktu lokal digunakan untuk log/validasi — pertimbangkan UTC."},
    {"name": "Regex catastrophic backtracking",
     "regex": r"\((?:[^)]*\+[^)]*|[^)]*\*[^)]*)\)\{2,\}",
     "severity": "LOW",
     "desc": "Pola regex bersarang kuantifier — rawan ReDoS."},
]


def _is_binary(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(1024)
    except OSError:
        return True


def _scan_file(path: str, root: str) -> List[dict]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return []
    lines = content.split("\n")
    findings = []
    for rule in PATTERNS:
        try:
            rx = re.compile(rule["regex"])
        except re.error:
            continue
        for m in rx.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            ctx_start = max(0, line_no - 2)
            context = "\n".join(lines[ctx_start:line_no + 1])
            findings.append({
                "file": os.path.relpath(path, root).replace("\\", "/"),
                "line": line_no,
                "severity": rule["severity"],
                "rule": rule["name"],
                "desc": rule["desc"],
                "snippet": m.group(0)[:300],
                "context": context[:600],
            })
    return findings


def scan_project(root: str, max_files: int = 2000) -> dict:
    """Scan direktori proyek dan kembalikan hasil temuan."""
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise NotADirectoryError(f"Bukan direktori: {root}")
    info(f"Scanning proyek: {root}")

    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SCAN_EXTS:
                files.append(os.path.join(dirpath, fn))
        if len(files) >= max_files:
            break
    files = files[:max_files]
    ok(f"Memeriksa {len(files)} file")

    all_findings: List[dict] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_scan_file, f, root) for f in files]
        for fut in as_completed(futures):
            all_findings.extend(fut.result())

    # urutkan: severity, lalu file, lalu line
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda f: (sev_order.get(f["severity"], 9), f["file"], f["line"]))

    summary = {
        "files_scanned": len(files),
        "total": len(all_findings),
        **{s: sum(1 for f in all_findings if f["severity"] == s)
           for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")},
    }
    ok(f"Selesai: {len(all_findings)} titik perhatian ({summary.get('CRITICAL', 0)} critical, "
       f"{summary.get('HIGH', 0)} high)")
    return {"root": root, "summary": summary, "findings": all_findings}
