"""Professional reporting (v0.19.0): template report + finding template.

Level PwnDoc/Dradis tanpa dependency baru:
- `REPORT_TEMPLATES`  : kerangka laporan per audiens (standard / owasp / pci /
                        hipaa / ctf).
- `FINDING_TEMPLATES` : boilerplate deskripsi + remediasi + referensi per jenis
                        temuan (SQLi, XSS, CSRF, dll).
- `apply_finding_templates` : melengkapi temuan yang field deskripsinya kosong.
- `ReportGenerator`    : menyusun markdown sesuai template + opsi (executive
                        only, section tertentu, dst).
"""

from datetime import datetime
from typing import Dict, List, Optional

# --- Finding templates -------------------------------------------------------

FINDING_TEMPLATES: Dict[str, Dict] = {
    "sql_injection": {
        "title": "SQL Injection",
        "description": ("Input pengguna disisipkan langsung ke query SQL tanpa "
                        "parameterisasi. Penyerang dapat membaca, mengubah, atau "
                        "menghapus data, termasuk bypass autentikasi."),
        "remediation": ("Gunakan parameterized query / prepared statement, "
                        "validasi input server-side, dan batasi hak akses akun database."),
        "references": ["OWASP: SQL Injection", "CWE-89", "MITRE T1190"],
    },
    "xss": {
        "title": "Cross-Site Scripting (XSS)",
        "description": ("Input direfleksikan/diproses tanpa encoding sehingga "
                        "penyerang dapat menyuntikkan JavaScript yang berjalan "
                        "di browser korban (pencurian cookie, keylog, deface)."),
        "remediation": ("Encode output sesuai konteks (HTML/attr/JS), terapkan "
                        "Content-Security-Policy, dan validasi input di sisi server."),
        "references": ["OWASP: XSS", "CWE-79", "MITRE T1189"],
    },
    "csrf": {
        "title": "Cross-Site Request Forgery (CSRF)",
        "description": ("Request state-changing tidak memerlukan token anti-CSRF "
                        "atau pengesahan origin, sehingga situs lain bisa memaksa "
                        "browser korban mengirim request berbahaya."),
        "remediation": ("Gunakan token CSRF per-sesi, cek header Origin/Referer, "
                        "dan set cookie SameSite."),
        "references": ["OWASP: CSRF", "CWE-352"],
    },
    "ssrf": {
        "title": "Server-Side Request Forgery (SSRF)",
        "description": ("Aplikasi melakukan request ke URL yang dikendalikan "
                        "pengguna tanpa validasi, memungkinkan akses ke metadata "
                        "cloud, layanan internal, atau file lokal (file://)."),
        "remediation": ("Allowlist host/port/ip, blokir IP privat & metadata "
                        "cloud, dan gunakan resolver terpisah untuk DNS rebinding."),
        "references": ["OWASP: SSRF", "CWE-918", "MITRE T1190"],
    },
    "lfi": {
        "title": "Local File Inclusion (LFI)",
        "description": ("Parameter file/template dapat menunjuk ke path lokal "
                        "(mis. /etc/passwd), memungkinkan pembacaan file sensitif "
                        "dan potensi escalation ke RCE."),
        "remediation": ("Allowlist path yang diizinkan, larang separators "
                        "(../, ..\\, null byte), dan jangan gabungkan input ke path filesystem."),
        "references": ["OWASP: File Inclusion", "CWE-98", "CWE-22", "MITRE T1005"],
    },
    "open_redirect": {
        "title": "Open Redirect",
        "description": ("Parameter redirect menerima URL eksternal tanpa validasi, "
                        "digunakan untuk phishing dengan memanfaatkan domain terpercaya."),
        "remediation": ("Allowlist host tujuan, atau selalu arahkan ke path relatif "
                        "yang sudah divalidasi."),
        "references": ["OWASP: Open Redirect", "CWE-601"],
    },
    "idor": {
        "title": "Insecure Direct Object Reference (IDOR)",
        "description": ("Resource diakses lewat ID langsung (mis. /users/1) tanpa "
                        "pengecekan otorisasi, memungkinkan akses data milik user lain."),
        "remediation": ("Terapkan access control berbasis pemilik (ownership check) "
                        "dan gunakan identifier yang tidak bisa ditebak (UUID)."),
        "references": ["OWASP: Broken Access Control", "CWE-639", "MITRE T1068"],
    },
    "weak_credentials": {
        "title": "Weak / Default Credentials",
        "description": ("Login menerima kredensial lemah atau default, sehingga "
                        "akun dapat ditebak dengan brute force ringan."),
        "remediation": ("Terapkan kebijakan password kuat, MFA, rate limiting, "
                        "dan blokir akun default."),
        "references": ["OWASP: Identification and Authentication Failures", "MITRE T1110"],
    },
    "info_disclosure": {
        "title": "Information Disclosure",
        "description": ("Respons/banner/error mengungkap informasi internal "
                        "(versi, stack, path, token) yang membantu penyerang "
                        "menyusun serangan lanjutan."),
        "remediation": ("Sembunyikan banner & error detail di produksi, minimalkan "
                        "kebocoran header, dan kendalikan akses file konfigurasi."),
        "references": ["CWE-200", "OWASP: Security Misconfiguration"],
    },
    "auth_bypass": {
        "title": "Authentication / Authorization Bypass",
        "description": ("Mekanisme autentikasi atau kontrol akses dapat dilewati "
                        "(verbtampering, path normalization, parameter tampering), "
                        "memberikan akses tanpa kredensial yang sah."),
        "remediation": ("Terapkan kontrol akses di sisi server secara konsisten, "
                        "normalisasi path, dan jangan percaya parameter klien."),
        "references": ["OWASP: Broken Access Control", "MITRE T1550"],
    },
    "rce": {
        "title": "Remote Code Execution",
        "description": ("Aplikasi mengeksekusi perintah/kode berdasarkan input "
                        "pengguna (command injection, template injection, "
                        "deserialization), memberi kendali penuh atas server."),
        "remediation": ("Jangan eksekusi perintah berbasis input; gunakan API yang "
                        "aman, allowlist, dan sandbox untuk kode/template."),
        "references": ["OWASP: Command Injection", "CWE-78", "CWE-94", "MITRE T1059"],
    },
    "security_misconfig": {
        "title": "Security Misconfiguration",
        "description": ("Konfigurasi tidak aman: default credentials, debug mode, "
                        "CORS longgar, header keamanan hilang, direktori terbuka."),
        "remediation": ("Terapkan hardening baseline, otomatisasi konfigurasi, "
                        "dan review rutin terhadap header & CORS."),
        "references": ["OWASP: Security Misconfiguration", "CWE-16"],
    },
    "session_issue": {
        "title": "Session / Cookie Issue",
        "description": ("Cookie sesi tanpa atribut Secure/HttpOnly/SameSite atau "
                        "dengan nilai mudah ditebak memungkinkan session hijacking."),
        "remediation": ("Set Secure, HttpOnly, SameSite; regenerate session id "
                        "setelah login; masa berlaku dibatasi."),
        "references": ["OWASP: Session Management", "CWE-614", "MITRE T1539"],
    },
}

# kata kunci di title -> id template (deteksi otomatis)
_TITLE_MATCH = [
    (("sql", "injection", "union"), "sql_injection"),
    (("xss", "cross-site", "cross site"), "xss"),
    (("csrf", "cross-site request"), "csrf"),
    (("ssrf", "server-side request"), "ssrf"),
    (("lfi", "local file", "file inclusion", "path traversal"), "lfi"),
    (("open redirect", "redirect"), "open_redirect"),
    (("idor", "object reference"), "idor"),
    (("weak", "default cred", "brute force", "weak login"), "weak_credentials"),
    (("information disclosure", "info disclosure", "sensitive", "exposed", "leak"), "info_disclosure"),
    (("bypass", "auth"), "auth_bypass"),
    (("rce", "remote code", "command injection", "deserialization"), "rce"),
    (("misconfig", "missing header", "cors", "directory listing"), "security_misconfig"),
    (("cookie", "session"), "session_issue"),
]


def _norm(text: str) -> str:
    return " ".join(str(text or "").lower().split())


def detect_finding_template(finding: Dict) -> Optional[str]:
    """Deteksi id template dari title/detail temuan (heuristik ringan)."""
    title = _norm(finding.get("title", ""))
    detail = _norm(finding.get("detail", ""))
    for needles, tid in _TITLE_MATCH:
        if any(n in title for n in needles) or any(n in detail for n in needles):
            return tid
    return None


def apply_finding_templates(findings: List[Dict]) -> List[Dict]:
    """Lengkapi description/remediation/references temuan yang kosong."""
    out = []
    for f in findings:
        f = dict(f)
        tid = f.get("template_id") or detect_finding_template(f)
        if tid and tid in FINDING_TEMPLATES:
            t = FINDING_TEMPLATES[tid]
            if not f.get("description"):
                f["description"] = t["description"]
            if not f.get("remediation"):
                f["remediation"] = t["remediation"]
            if not f.get("references"):
                f["references"] = list(t["references"])
            f["template_id"] = tid
        out.append(f)
    return out


# --- Report templates --------------------------------------------------------

REPORT_TEMPLATES: Dict[str, Dict] = {
    "standard": {
        "label": "Standard",
        "sections": ["cover", "executive", "scope", "methodology", "summary",
                     "attack_paths", "findings", "remediation", "appendix"],
    },
    "owasp": {
        "label": "OWASP Top 10 (2021)",
        "sections": ["cover", "executive", "scope", "methodology", "owasp",
                     "summary", "attack_paths", "findings", "remediation",
                     "appendix"],
    },
    "pci": {
        "label": "PCI DSS",
        "sections": ["cover", "executive", "scope", "methodology", "pci",
                     "summary", "findings", "remediation", "appendix"],
    },
    "hipaa": {
        "label": "HIPAA",
        "sections": ["cover", "executive", "scope", "methodology", "hipaa",
                     "summary", "findings", "remediation", "appendix"],
    },
    "ctf": {
        "label": "CTF / Challenge",
        "sections": ["cover", "executive", "walkthrough", "flags", "screenshots",
                     "appendix"],
    },
}

# Pemetaan temuan ke kontrol PCI/OWASP/HIPAA untuk tabel kepatuhan
_COMPLIANCE_MAP = {
    "PCI DSS": {
        "req": {"1": "Firewall & network segmentation", "3": "Protect stored data",
                "4": "Encrypt transmission", "6": "Secure coding & patching",
                "7": "Restrict access by need-to-know", "8": "Authentication",
                "10": "Logging & monitoring", "11": "Regular testing"},
        "finding": {"sql_injection": "6.5.1", "xss": "6.5.7", "rce": "6.5.1",
                    "weak_credentials": "8.1.4", "info_disclosure": "6.5.6",
                    "session_issue": "4.1", "security_misconfig": "6.4.2"},
    },
    "HIPAA": {
        "req": {"164.308": "Access control & audit", "164.312": "Technical safeguards",
                "164.314": "Business associate", "164.316": "Policies"},
        "finding": {"sql_injection": "164.312", "xss": "164.312", "rce": "164.312",
                    "weak_credentials": "164.312", "info_disclosure": "164.312",
                    "session_issue": "164.312", "security_misconfig": "164.308"},
    },
}

_OWASP_2021 = [
    ("A01", "Broken Access Control"),
    ("A02", "Cryptographic Failures"),
    ("A03", "Injection"),
    ("A04", "Insecure Design"),
    ("A05", "Security Misconfiguration"),
    ("A06", "Vulnerable and Outdated Components"),
    ("A07", "Identification and Authentication Failures"),
    ("A08", "Software and Data Integrity Failures"),
    ("A09", "Security Logging and Monitoring Failures"),
    ("A10", "Server-Side Request Forgery"),
]

_OWASP_BY_TEMPLATE = {
    "sql_injection": ("A03", "Injection"),
    "xss": ("A03", "Injection"),
    "rce": ("A03", "Injection"),
    "csrf": ("A01", "Broken Access Control"),
    "idor": ("A01", "Broken Access Control"),
    "auth_bypass": ("A01", "Broken Access Control"),
    "weak_credentials": ("A07", "Identification and Authentication Failures"),
    "ssrf": ("A10", "Server-Side Request Forgery"),
    "security_misconfig": ("A05", "Security Misconfiguration"),
    "info_disclosure": ("A05", "Security Misconfiguration"),
    "session_issue": ("A02", "Cryptographic Failures"),
    "lfi": ("A03", "Injection"),
    "open_redirect": ("A01", "Broken Access Control"),
}


def template_ids(findings: List[Dict]) -> List[str]:
    """Daftar template_id unik dari findings (untuk tabel kepatuhan)."""
    ids = {str(f.get("template_id")) for f in findings if f.get("template_id")}
    return sorted(tid for tid in ids if tid)


def compliance_table(framework: str, findings: List[Dict]) -> List[List[str]]:
    """Tabel pemetaan temuan -> kontrol framework (PCI/HIPAA)."""
    meta = _COMPLIANCE_MAP.get(framework)
    if not meta:
        return []
    rows = [["Kontrol", "Deskripsi", "Temuan Relevan"]]
    by_control = {}
    for f in findings:
        tid = f.get("template_id")
        if not tid:
            continue
        ctrl = (meta["finding"] or {}).get(tid)
        if ctrl:
            by_control.setdefault(ctrl, []).append(f.get("title", ""))
    for ctrl, desc in meta["req"].items():
        titles = by_control.get(ctrl, [])
        rows.append([ctrl, desc, "; ".join(titles[:3]) or "-"])
    return rows


# --- Report generator --------------------------------------------------------

class ReportGenerator:
    """Susun laporan markdown sesuai template + opsi."""

    def __init__(self, template: str = "standard", options: Optional[Dict] = None,
                 author: str = "Keris"):
        self.template = template if template in REPORT_TEMPLATES else "standard"
        self.options = options or {}
        self.author = author
        self.target = ""
        self.recon: Dict = {}
        self.discovery: Dict = {}
        self.findings: List[Dict] = []
        self._lines: List[str] = []

    def generate(self, target: str, recon: Dict, discovery: Dict,
                 findings: List[Dict]) -> str:
        self.target = target
        self.recon = recon or {}
        self.discovery = discovery or {}
        self.findings = apply_finding_templates(findings or [])
        self._lines = []
        sections = REPORT_TEMPLATES[self.template]["sections"]
        if self.options.get("executive_only"):
            sections = ["executive"]
        for sec in sections:
            getattr(self, f"_sec_{sec}")()
        return "\n".join(self._lines)

    # --- section renderers ---
    def _p(self, text: str = "") -> None:
        self._lines.append(text)

    def _h(self, text: str) -> None:
        self._lines.append(text)
        self._p()

    def _sec_cover(self) -> None:
        now = datetime.now().strftime("%d %B %Y, %H:%M")
        self._h(f"# Laporan Pengujian Keamanan — {self.target}")
        self._p(f"**Tanggal:** {now}")
        self._p(f"**Template:** {REPORT_TEMPLATES[self.template]['label']}")
        self._p(f"**Disusun oleh:** {self.author}")
        self._p(f"**Jenis:** Black-box {self.options.get('mode', 'otomatis')}")
        self._p("---")

    def _sec_executive(self) -> None:
        from keris.modules.riskscore import risk_score

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            s = f.get("severity", "INFO").upper()
            counts[s] = counts.get(s, 0) + 1
        total = sum(counts.values())
        rs = risk_score(self.findings)
        self._h("## Ringkasan Eksekutif")
        self._p(f"Pengujian terhadap `{self.target}` menemukan **{total}** temuan.")
        self._p(f"**Risk Score:** `{rs['grade']}` ({rs['score']}/100)")
        self._p(f"_{rs['recommendation']}_")
        self._p()
        self._p("| Severity | Jumlah |")
        self._p("|---|---|")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self._p(f"| {sev} | {counts.get(sev, 0)} |")
        self._p()
        exec_note = self.options.get("executive_summary")
        if exec_note:
            self._p(exec_note)
            self._p()

    def _sec_scope(self) -> None:
        self._h("## 1. Lingkup Pengujian")
        self._p("| Item | Nilai |")
        self._p("|---|---|")
        self._p(f"| URL | `{self.target}` |")
        self._p(f"| Host | `{self.recon.get('host', '')}` |")
        self._p(f"| IP | `{', '.join(self.recon.get('ips', []))}` |")
        self._p(f"| Server | `{self.recon.get('server_header', 'n/a')}` |")
        self._p()
        self._p("**Catatan:** Pengujian dilakukan dalam kerangka black-box; "
                "tidak ada kredensial awal yang diberikan.")
        self._p()

    def _sec_methodology(self) -> None:
        self._h("## 2. Metodologi")
        self._p("Tahapan pengujian:")
        self._p("1. **Reconnaissance** — fingerprinting server, stack, header.")
        self._p("2. **Discovery** — enumerasi endpoint, asset JS, secret.")
        self._p("3. **Vulnerability scanning** — deteksi SQLi/XSS/SSRF/IDOR/dll.")
        self._p("4. **Correlation** — penyusunan attack chains & attack paths.")
        self._p("5. **Reporting** — laporan, prioritas, dan rencana remediasi.")
        self._p()

    def _sec_summary(self) -> None:
        self._h("## 3. Ringkasan Temuan")
        self._p("| Severity | Lokasi | Deskripsi |")
        self._p("|---|---|---|")
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for f in sorted(self.findings, key=lambda x: order.get(x.get("severity", "INFO").upper(), 9)):
            self._p(f"| **{f.get('severity', 'INFO')}** | `{f.get('endpoint', '')}` | {f.get('title', '')} |")
        self._p()

    def _sec_owasp(self) -> None:
        self._h("## 3. Pemetaan OWASP Top 10 (2021)")
        self._p("| Kode | Kategori | Jumlah Temuan |")
        self._p("|---|---|---|")
        count_by = {}
        for f in self.findings:
            tid = f.get("template_id")
            code = (_OWASP_BY_TEMPLATE.get(tid) if tid else None)
            if not code:
                code = ("A99", "Lainnya")
            count_by[code[0]] = count_by.get(code[0], 0) + 1
        for code, name in _OWASP_2021:
            n = count_by.get(code, 0)
            if n:
                self._p(f"| {code} | {name} | {n} |")
        self._p()

    def _sec_pci(self) -> None:
        self._h("## 3. Kepatuhan PCI DSS")
        self._p("Pemetaan temuan terhadap kebutuhan PCI DSS:")
        self._p()
        for row in compliance_table("PCI DSS", self.findings):
            self._p("| " + " | ".join(str(c) for c in row) + " |")
            if len(row) == 3 and row[0] == "Kontrol":
                self._p("|---|---|---|")
        self._p()

    def _sec_hipaa(self) -> None:
        self._h("## 3. Kepatuhan HIPAA")
        self._p("Pemetaan temuan terhadap standar HIPAA:")
        self._p()
        for row in compliance_table("HIPAA", self.findings):
            self._p("| " + " | ".join(str(c) for c in row) + " |")
            if len(row) == 3 and row[0] == "Kontrol":
                self._p("|---|---|---|")
        self._p()

    def _sec_attack_paths(self) -> None:
        attack_paths = self.options.get("attack_paths") or []
        mitre_chains = self.options.get("mitre_chains") or []
        if mitre_chains:
            from keris.modules.mitre import mitre_markdown
            self._lines.extend(mitre_markdown(mitre_chains))
            self._p()
        elif attack_paths:
            from keris.modules.correlation import paths_markdown
            self._lines.extend(paths_markdown(attack_paths))
            self._p()

    def _sec_findings(self) -> None:
        self._h("## 4. Detail Temuan")
        if not self.findings:
            self._p("Tidak ada temuan kerentanan yang terdeteksi pada pengujian ini.")
            self._p()
            return
        from keris.cvss import classify

        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for i, f in enumerate(sorted(self.findings, key=lambda x: order.get(x.get("severity", "INFO").upper(), 9)), 1):
            self._p(f"### {i}. [{f.get('severity', 'INFO')}] {f.get('title', '')}")
            self._p()
            self._p(f"**Lokasi:** `{f.get('endpoint', '')}`")
            self._p()
            cvss = classify(f.get("title", ""), f.get("severity", ""))
            self._p(f"**CVSS v3.1:** {cvss['score']} (`{cvss['vector']}`) · "
                    f"**OWASP:** {cvss['owasp_code']} {cvss['owasp_name']}")
            self._p()
            desc = f.get("description") or f.get("detail") or ""
            if desc:
                self._p(desc)
                self._p()
            if f.get("evidence"):
                self._p("**Bukti:**")
                self._p()
                self._p("```")
                self._p(str(f["evidence"])[:1000])
                self._p("```")
                self._p()
            if f.get("remediation"):
                self._p(f"**Remediasi:** {f['remediation']}")
                self._p()
            refs = f.get("references") or []
            if refs:
                self._p("**Referensi:** " + ", ".join(str(r) for r in refs))
                self._p()

    def _sec_remediation(self) -> None:
        from keris.modules.remediation import build_remediation_plan, remediation_markdown

        plan = build_remediation_plan(self.findings)
        if plan["items"]:
            self._lines.extend(remediation_markdown(plan, self.target).splitlines())
            self._p()

    def _sec_walkthrough(self) -> None:
        self._h("## Walkthrough")
        self._p("Langkah-langkah yang berhasil dieksekusi selama pengujian:")
        self._p()
        for i, f in enumerate(sorted(self.findings, key=lambda x: x.get("severity", "INFO")), 1):
            self._p(f"{i}. **{f.get('title', '')}** — `{f.get('endpoint', '')}`")
            if f.get("evidence"):
                self._p(f"   Bukti: `{str(f['evidence'])[:200]}`")
        self._p()

    def _sec_flags(self) -> None:
        flags = self.options.get("flags") or []
        self._h("## Flags")
        if flags:
            for i, fl in enumerate(flags, 1):
                self._p(f"{i}. `{fl}`")
        else:
            self._p("Tidak ada flag yang terkumpul.")
        self._p()

    def _sec_screenshots(self) -> None:
        shots = self.options.get("screenshots") or []
        self._h("## Screenshots")
        for s in shots:
            self._p(f"![{s}]({s})")
        self._p()

    def _sec_appendix(self) -> None:
        self._h("## Lampiran")
        self._p("- Alat: Keris (otomatis).")
        self._p("- Metode verifikasi: request ulang + analisis konteks.")
        self._p("- Laporan dihasilkan otomatis; verifikasi manual disarankan "
                "untuk temuan berstatus terindikasi/potensial.")
        self._p()


def render_markdown_report(target: str, recon: Dict, discovery: Dict,
                           findings: List[Dict], template: str = "standard",
                           options: Optional[Dict] = None) -> str:
    """Render laporan markdown dengan template tertentu."""
    return ReportGenerator(template=template, options=options).generate(
        target, recon, discovery, findings)


def render_report_from_scan(scan_data: Dict, template: str = "standard",
                            options: Optional[Dict] = None) -> str:
    """Render report langsung dari dict hasil scan JSON."""
    options = dict(options or {})
    options.setdefault("attack_paths", scan_data.get("attack_paths") or [])
    mitre = scan_data.get("mitre") or {}
    options.setdefault("mitre_chains", mitre.get("chains") or [])
    if scan_data.get("executive_summary"):
        options["executive_summary"] = scan_data["executive_summary"]
    return render_markdown_report(
        scan_data.get("target", ""),
        scan_data.get("recon", {}),
        scan_data.get("discovery", {}),
        scan_data.get("findings", []),
        template=template, options=options)