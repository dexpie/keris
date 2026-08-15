"""Remediation plan generator: langkah perbaikan berprioritas per temuan.

Menghasilkan rencana aksi untuk klien/developer berdasarkan temuan:
dikelompokkan berdasarkan severity dan kategori, dengan langkah konkret
yang bisa langsung diikuti. Ditujukan agar laporan tidak hanya 'ada
masalah' tetapi juga 'ini cara memperbaikinya'.
"""

from typing import Dict, List, Optional

from keris.modules.riskscore import risk_score

# Pemetaan kategori temuan -> langkah remediasi
REMEDIATION_STEPS: Dict[str, List[str]] = {
    "SQL injection": [
        "Gunakan prepared statement / parameterized query di semua akses DB",
        "Terapkan whitelist input untuk parameter yang masuk ke query",
        "Batasi hak akses database user aplikasi (least privilege)",
    ],
    "XSS": [
        "Encode output sesuai konteks (HTML/attribute/JS/URL) - gunakan library seperti DOMPurify",
        "Terapkan Content-Security-Policy yang ketat (nonce/hash untuk script inline)",
        "Validasi input sisi server; jangan hanya andalkan validasi klien",
    ],
    "SSRF": [
        "Validasi & whitelist host/IP tujuan untuk setiap request keluar",
        "Blokir akses ke metadata cloud (169.254.169.254) dan IP internal",
        "Gunakan allowlist URL/domain ketat, bukan blocklist",
    ],
    "Information Disclosure": [
        "Hapus informasi versi dari header (Server, X-Powered-By)",
        "Amankan file sensitive (.env, .git, backup) agar tidak bisa diakses publik",
        "Redaksi data pribadi dari respons API yang tidak perlu",
    ],
    "Security Misconfiguration": [
        "Terapkan security headers (HSTS, CSP, X-Frame-Options, etc.)",
        "Disable directory listing dan fitur debug di produksi",
        "Tinjau default credentials & akun layanan yang tidak dipakai",
    ],
    "Broken Authentication": [
        "Terapkan rate limiting & account lockout pada endpoint login",
        "Wajibkan password kuat + 2FA untuk akun berprivilege",
        "Gunakan mekanisme reset password yang aman (token sekali pakai, tidak bisa di-enum)",
    ],
    "Access Control": [
        "Terapkan otorisasi berbasis role/permission di sisi server untuk semua endpoint",
        "Uji akses horizontal & vertikal (IDOR) secara berkala",
        "Jangan mengandalkan kerahasiaan URL/ID sebagai kontrol akses",
    ],
    "Sensitive Data": [
        "Gunakan TLS/HTTPS penuh (HSTS) untuk semua komunikasi",
        "Enkripsi data sensitif saat diam (at rest) dan saat transit",
        "Minimalkan penyimpanan data sensitif; gunakan tokenisasi",
    ],
    "Race Condition": [
        "Tambahkan kunci transaksional / lock pada operasi sekali-pakai (database-level lock)",
        "Jadikan operasi idempoten: cek status sebelum apply",
        "Gunakan unique constraint untuk mencegah double-use",
    ],
    "dependency-cve": [
        "Perbarui library ke versi aman terbaru (sesuai CVE yang muncul)",
        "Gunakan tool otomatis (dependabot/renovate) untuk update berkala",
        "Audit dependency tree; hapus library yang tidak terpakai",
    ],
    "JWT": [
        "Ganti secret JWT dengan kunci acak yang panjang (>= 32 bytes)",
        "Set alg ke HS256/RS256 secara eksplisit; tolak alg=none",
        "Validasi exp/iat/nbf; revoke mekanisme untuk token yang bocor",
    ],
    "Cache Poisoning": [
        "Jangan cache respons yang bergantung pada header Host/X-Forwarded-Host",
        "Gunakan cache key yang mencakup semua input yang memengaruhi output",
        "Validasi header proxy terhadap allowlist host",
    ],
    "favicon": [
        "Pertimbangkan untuk menghapus atau mengubah favicon unik yang menandai produk",
    ],
    "Cookie Security": [
        "Set flag Secure, HttpOnly, SameSite (Lax/Strict) pada semua cookie",
        "Gunakan cookie CSRF token yang terpisah dari sesi",
    ],
}


def remediation_for_finding(f: Dict) -> List[str]:
    """Cari langkah remediasi untuk satu temuan berdasarkan title & detail."""
    title = (f.get("title", "") or "")
    detail = (f.get("detail", "") or "") + title
    low = detail.lower()

    # match kategori berdasarkan kata kunci
    mapping = [
        ("SQL injection", ("sql", "squel", "syntax error", "query")),
        ("XSS", ("xss", "cross-site scripting", "javascript:")),
        ("SSRF", ("ssrf", "server-side request")),
        ("Race Condition", ("race condition", "double-apply", "toctou")),
        ("Access Control", ("idor", "access control", "authorization", "bocor ke user")),
        ("Broken Authentication", ("login", "rate limit", "authentication")),
        ("Sensitive Data", ("sensitive", "pii", "password_hash", "api_key")),
        ("Cache Poisoning", ("cache poisoning", "host header")),
        ("dependency-cve", ("dependency rentan", "library")),
        ("JWT", ("jwt", "token")),
        ("Information Disclosure", ("disclosure", "banner", "version", "info")),
        ("favicon", ("favicon",)),
        ("Cookie Security", ("cookie",)),
        ("Security Misconfiguration", ("header", "security.txt", "missing")),
    ]
    for category, keywords in mapping:
        if any(k in low for k in keywords):
            return REMEDIATION_STEPS.get(category, [])
    return [
        "Tinjau temuan ini secara manual dan tentukan langkah mitigasi yang sesuai",
        "Dokumentasikan keputusan dan status perbaikan di tracker issue tim",
    ]


def build_remediation_plan(findings: List[Dict]) -> Dict:
    """Bangun rencana remediasi lengkap dari daftar temuan."""
    by_sev: Dict[str, List[Dict]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
    for f in findings:
        s = (f.get("severity", "INFO") or "INFO").upper()
        by_sev.setdefault(s, []).append(f)

    ordered = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        for f in by_sev.get(sev, []):
            ordered.append({"severity": sev, "title": f.get("title", ""), "endpoint": f.get("endpoint", ""),
                            "steps": remediation_for_finding(f)})

    rs = risk_score(findings)
    return {
        "grade": rs["grade"],
        "recommendation": rs["recommendation"],
        "items": ordered,
        "summary": {s: len(by_sev.get(s, [])) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")},
    }


def remediation_markdown(plan: Dict, target: str) -> str:
    """Render rencana remediasi ke markdown."""
    lines = ["## Rencana Remediasi", ""]
    lines.append(f"Target: `{target}` | Risk Score: **{plan['grade']}**")
    lines.append("")
    lines.append(f"_{plan['recommendation']}_")
    lines.append("")
    if not plan["items"]:
        lines.append("Tidak ada temuan yang perlu diperbaiki.")
        return "\n".join(lines) + "\n"
    for item in plan["items"]:
        lines.append(f"### [{item['severity']}] {item['title']}")
        lines.append("")
        lines.append(f"Endpoint: `{item['endpoint']}`")
        lines.append("")
        lines.append("Langkah perbaikan:")
        lines.append("")
        for step in item["steps"]:
            lines.append(f"- {step}")
        lines.append("")
    return "\n".join(lines) + "\n"