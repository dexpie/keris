"""Client-side SAST: static analysis of downloaded source/JS bundles.

- **Analyzer JS & kode**: deteksi sink berbahaya (eval, innerHTML, exec,
  shell command, SQLi), kredensial hardcoded, kripto lemah, path traversal,
  dan insecure transport di file source/asset yang bisa diunduh.
- **Library CVE DB**: cocokkan versi dependency yang terdeteksi terhadap
  database CVE offline (`jsdeps.CVE_DB` + tabel SAST_CVE_DB tambahan).
- **SBOM CycloneDX**: hasilkan inventory dependency dalam format JSON
  CycloneDX 1.4 untuk supply-chain visibility.

Semua murni statis/lokal — tidak ada request aktif ke target.
"""

import json
import os
import re
import uuid
from typing import Any, Dict, List, Optional

from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

# --- pola analisis statis ---------------------------------------------------

SAST_PATTERNS: List[tuple] = [
    # (regex, severity, title, detail)
    (re.compile(r"\beval\s*\("), "HIGH", "Penggunaan eval() berbahaya",
     "eval() mengeksekusi string sebagai kode; berisiko code injection (CWE-95)."),
    (re.compile(r"\bnew\s+Function\s*\("), "HIGH", "Dynamic Function() constructor",
     "Function() mengeksekusi string sebagai kode (CWE-95)."),
    (re.compile(r"document\.write\s*\("), "MEDIUM", "document.write dengan input dinamis",
     "Rentan DOM XSS bila input tidak disanitasi (CWE-79)."),
    (re.compile(r"\.innerHTML\s*="), "MEDIUM", "innerHTML assignment",
     "Menetapkan innerHTML dengan input tak ternetralisir memungkinkan XSS (CWE-79)."),
    (re.compile(r"child_process\.(exec|spawn|execSync|spawnSync)\s*\("),
     "HIGH", "Shell command execution",
     "Perintah OS dibangun dari input; risiko command injection (CWE-78)."),
    (re.compile(r"\bos\.system\s*\("), "HIGH", "os.system() call",
     "Mengeksekusi perintah shell; berisiko command injection (CWE-78)."),
    (re.compile(r"subprocess\.(call|run|Popen)\s*\("), "MEDIUM",
     "Subprocess call", "Pastikan argumen tidak memakai shell tidak aman (CWE-78)."),
    (re.compile(r"(?i)select\s+.+from\s+.+(?:where|;|\")", re.DOTALL),
     "HIGH", "SQL query string", "Query SQL dibangun manual; berisiko SQL injection bila input "
     "digabung langsung (CWE-89)."),
    (re.compile(r"(?i)execute\s*\([\"'](?:select|insert|update|delete|drop)"),
     "HIGH", "Raw SQL execution", "Eksekusi SQL mentah; hindari bila input tak terparameterisasi (CWE-89)."),
    (re.compile(r"md5\s*\("), "LOW", "Hash MD5", "MD5 lemah untuk hashing password (CWE-327)."),
    (re.compile(r"sha1\s*\("), "LOW", "Hash SHA-1", "SHA-1 lemah untuk keamanan (CWE-327)."),
    (re.compile(r"DES\s*\.(createCipher|createDecipher)"), "HIGH", "DES encryption",
     "DES/3DES sudah tidak aman; gunakan AES-GCM (CWE-327)."),
    (re.compile(r"\.\./\.\./|os\.path\.join\s*\([^)]*\.\./"), "MEDIUM",
     "Path traversal risk", "Konstruksi path memakai ../ dapat dimanipulasi (CWE-22)."),
    (re.compile(r"http://[a-zA-Z0-9./_-]+"), "MEDIUM", "HTTP plaintext endpoint",
     "Endpoint HTTP tanpa TLS dapat disadap (CWE-319)."),
    (re.compile(r"allowall=true|rejectunauthorized\s*=\s*false|checkcertificate\s*=\s*false", re.I),
     "HIGH", "TLS verification disabled", "Verifikasi sertifikat dimatikan (CWE-295)."),
    (re.compile(r"(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*[\"']([^\"']{8,})[\"']"),
     "MEDIUM", "Kredensial hardcoded", "Secret tertanam di source; rotasi dan pindahkan ke vault (CWE-798)."),
    (re.compile(r"pickle\.loads?|yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.(FullLoader|UnsafeLoader)"),
     "HIGH", "Unsafe deserialization", "Deserialisasi data tak tepercaya bisa RCE (CWE-502)."),
    (re.compile(r"XMLParser\s*\(\s*\)|etree\.fromstring|lxml\.fromstring"),
     "MEDIUM", "XML parsing", "Parsing XML tanpa proteksi entity dapat XXE (CWE-611)."),
]

# --- CVE DB tambahan untuk analisis statis (selain jsdeps.CVE_DB) ------------

SAST_CVE_DB: Dict[str, List[tuple]] = {
    "fastapi": [("0.100.0", "MEDIUM", "Dependency Confusion / insecure default")],
    "flask": [("2.2.4", "MEDIUM", "Open redirect (CVE-2023-25577)")],
    "django": [("4.2.0", "HIGH", "Denial of service via file uploads (CVE-2023-41164)")],
    "requests": [("2.31.0", "MEDIUM", "Proxy auth leak (CVE-2023-32681)")],
    "urllib3": [("2.0.6", "HIGH", "HTTP request smuggling (CVE-2023-45803)")],
    "certifi": [("2023.7.22", "HIGH", "Expired/compromised root certificates (CVE-2023-37920)")],
    "werkzeug": [("3.0.0", "HIGH", "DoS via large multipart (CVE-2023-46136)")],
    "jinja2": [("3.1.2", "LOW", "XML attribute injection (CVE-2024-22195)")],
    "pillow": [("10.0.0", "HIGH", "Buffer overflow on TIFF (CVE-2023-44271)")],
    "openssl": [("1.1.1", "HIGH", "Multiple CVEs; upgrade to 3.x")],
}

from keris.modules.jsdeps import CVE_DB as _JSDEP_CVE_DB  # noqa: E402

CVE_DB: Dict[str, List[tuple]] = {**_JSDEP_CVE_DB, **SAST_CVE_DB}


def _parse_version(ver: str) -> tuple:
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(ver).strip().lstrip("^~v"))
    if not m:
        return (0,)
    return tuple(int(g) for g in m.groups() if g is not None)


def _sev_order(s: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(s, 9)


def check_cve_for(pkg: str, version: str) -> Optional[tuple]:
    """Kembalikan (severity, desc) bila versi paket rentan."""
    if not version or pkg not in CVE_DB:
        return None
    cur = _parse_version(version)
    best = None
    for limit, sev, desc in CVE_DB[pkg]:
        if cur and cur <= _parse_version(limit):
            if best is None or _sev_order(sev) < _sev_order(best[0]):
                best = (sev, desc)
    return best


def analyze_source(text: str, filename: str = "source",
                   origin: str = "") -> List[Finding]:
    """Analisis statis teks sumber; kembalikan daftar Finding."""
    findings: List[Finding] = []
    seen = set()
    for pattern, sev, title, detail in SAST_PATTERNS:
        if not pattern.search(text):
            continue
        if title in seen:
            continue
        seen.add(title)
        findings.append(Finding(
            sev, f"[SAST] {title}", origin or filename,
            detail, f"file: {filename}", cwe=detail.split("(CWE-")[-1].split(")")[0],
        ))
    return findings


def extract_dependencies(text: str, filename: str) -> Dict[str, str]:
    """Ekstrak paket+versi dari package.json / lockfile / pyproject / requirements."""
    pkgs: Dict[str, str] = {}
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for section in ("dependencies", "devDependencies", "peerDependencies",
                            "optionalDependencies", "packages"):
                deps = data.get(section) or {}
                if isinstance(deps, dict):
                    for name, ver in deps.items():
                        if isinstance(ver, str):
                            pkgs[name] = ver
    except Exception:
        pass
    if "requirements" in filename.lower() or filename.lower().endswith(".txt"):
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "==" not in line:
                continue
            name, _, ver = line.partition("==")
            pkgs[name.strip()] = ver.strip()
    return pkgs


def check_dependencies(packages: Dict[str, str]) -> List[Finding]:
    """Cek versi dependency terhadap CVE DB offline."""
    findings: List[Finding] = []
    for name, ver in sorted(packages.items()):
        base = name.rsplit("/", 1)[-1].lower()
        hit = check_cve_for(base, ver)
        if not hit:
            continue
        sev, desc = hit
        findings.append(Finding(
            sev, f"Dependency rentan: {base}@{ver}", "sbom",
            f"Versi {base}@{ver} rentan terhadap CVE yang diketahui ({desc}). "
            "Perbarui ke versi aman terbaru.",
            f"paket: {base}@{ver}",
        ))
    return findings


def build_sbom(packages: Dict[str, str], target: str = "") -> Dict[str, Any]:
    """Bangun dokumen SBOM JSON versi CycloneDX 1.4."""
    components = []
    for name, ver in sorted(packages.items()):
        components.append({
            "type": "library",
            "bom-ref": str(uuid.uuid4())[:12],
            "name": name,
            "version": ver,
            "purl": f"pkg:pypi/{name}@{ver}",
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": "",
            "component": {"type": "application", "name": target or "keris-sast"},
        },
        "components": components,
    }


def analyze_directory(path: str, target: str = "",
                      json_output: str = "") -> Dict[str, Any]:
    """Analisis statis seluruh file dalam direktori (source/SBOM scan)."""
    findings: List[Finding] = []
    packages: Dict[str, str] = {}
    files_scanned = 0
    for root, _dirs, names in os.walk(path):
        for name in names:
            fpath = os.path.join(root, name)
            if not _is_source_file(name):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read(1000000)
            except OSError:
                continue
            files_scanned += 1
            rel = os.path.relpath(fpath, path)
            findings.extend(analyze_source(text, rel, fpath))
            if name in ("package.json", "package-lock.json", "yarn.lock",
                        "requirements.txt", "Pipfile", "pyproject.toml"):
                packages.update(extract_dependencies(text, name))
    findings.extend(check_dependencies(packages))
    sbom = build_sbom(packages, target or path)
    result = {
        "target": target or path,
        "files_scanned": files_scanned,
        "findings": [f.to_dict() for f in findings],
        "dependency_count": len(packages),
        "packages": packages,
        "sbom": sbom,
    }
    if json_output:
        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
    return result


_SOURCE_EXTS = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".php", ".rb",
    ".go", ".java", ".cs", ".cpp", ".c", ".h", ".sh", ".bash", ".ps1",
    ".html", ".htm", ".vue", ".json", ".yml", ".yaml", ".toml", ".ini",
    ".conf", ".cfg", ".env", ".txt",
}


def _is_source_file(name: str) -> bool:
    ext = os.path.splitext(name)[1].lower()
    if ext in _SOURCE_EXTS:
        return True
    return name in (".env", "Dockerfile", "Makefile", "Procfile",
                    ".htaccess", "wp-config.php")


def sbom_markdown(sbom: Dict[str, Any]) -> str:
    """Render ringkasan SBOM sebagai markdown."""
    lines = ["## SBOM (CycloneDX 1.4)", ""]
    comps = sbom.get("components", [])
    lines.append(f"**Component:** {sbom.get('metadata', {}).get('component', {}).get('name', '')}")
    lines.append(f"**Total dependency:** {len(comps)}")
    lines.append("")
    lines.append("| Package | Version | PURL |")
    lines.append("|---|---|---|")
    for c in comps:
        lines.append(f"| {c['name']} | {c.get('version', '')} | {c.get('purl', '')} |")
    return "\n".join(lines)