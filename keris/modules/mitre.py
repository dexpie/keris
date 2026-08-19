"""MITRE ATT&CK integration untuk attack chains (v0.18.0).

Memetakan temuan ke MITRE ATT&CK technique/tactic, menandai tiap step attack
path dengan technique ID, dan menyusun "tactic progression" (Reconnaissance
sampai Impact) seperti cara analis manusia membaca serangan.

Zero-dependency: mapping technique di-hardcode (subset utama yang relevan
untuk web pentest); tidak butuh package `mitre-attack`.
"""

from typing import Dict, List, Optional

# Tactic progression sesuai MITRE ATT&CK (urutan fase serangan)
TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

TACTIC_RANK = {t: i for i, t in enumerate(TACTICS)}

# Tag temuan (dari correlation._TAGS) -> MITRE technique
TECHNIQUE_BY_TAG = {
    "sqli": "T1190",
    "ssrf": "T1190",
    "host-header": "T1190",
    "cache-poison": "T1189",
    "xss": "T1189",
    "xss-any": "T1189",
    "cors": "T1189",
    "open-redirect": "T1204",
    "rce": "T1059",
    "upload": "T1505.003",
    "deserialization": "T1210",
    "weak-login": "T1110",
    "brute": "T1110",
    "auth-bypass": "T1550",
    "secret": "T1552.001",
    "git-leak": "T1552.001",
    "credential-dumping": "T1003",
    "reset-poisoning": "T1556",
    "cookie": "T1539",
    "sensitive": "T1005",
    "sqlite-leak": "T1005",
    "file-read": "T1005",
    "lfi": "T1005",
    "backup": "T1005",
    "listing": "T1083",
    "directory-listing": "T1083",
    "idor": "T1068",
    "admin-panel": "T1078",
    "takeover": "T1584.001",
    "port-scan": "T1046",
    "subdomain": "T1595.001",
    "osint": "T1593",
}

# Fallback berdasarkan jenis temuan (finding["type"]) bila tag tidak cocok
TECHNIQUE_BY_TYPE = {
    "sql-injection": "T1190",
    "sqli": "T1190",
    "xss": "T1189",
    "ssrf": "T1190",
    "command-injection": "T1059",
    "cmdi": "T1059",
    "rce": "T1059",
    "lfi": "T1005",
    "file-read": "T1005",
    "idor": "T1068",
    "auth-bypass": "T1550",
    "brute-force": "T1110",
    "weak-credentials": "T1110",
    "directory-listing": "T1083",
    "sensitive-data": "T1005",
    "open-redirect": "T1204",
    "subdomain-takeover": "T1584.001",
    "host-header": "T1190",
    "cache-poisoning": "T1189",
    "cors": "T1189",
    "cookie": "T1539",
    "websocket": "T1190",
    "upload": "T1505.003",
    "deserialization": "T1210",
    "information-disclosure": "T1005",
}

# Detail teknik: id -> nama + tactic + deskripsi singkat
TECHNIQUE_DETAILS: Dict[str, Dict] = {
    "T1190": {"id": "T1190", "name": "Exploit Public-Facing Application",
              "tactic": "Initial Access",
              "description": "Eksploitasi aplikasi yang terpapar internet untuk mendapatkan akses awal."},
    "T1189": {"id": "T1189", "name": "Drive-by Compromise",
              "tactic": "Initial Access",
              "description": "Kerentanan di sisi klien (XSS/cache poisoning) yang mengeksploitasi interaksi user."},
    "T1204": {"id": "T1204", "name": "User Execution",
              "tactic": "Initial Access",
              "description": "Mengandalkan user untuk mengeksekusi payload (open redirect, phishing link)."},
    "T1078": {"id": "T1078", "name": "Valid Accounts",
              "tactic": "Persistence",
              "description": "Menggunakan akun valid (hasil brute force/ekspos panel) untuk akses."},
    "T1059": {"id": "T1059", "name": "Command and Scripting Interpreter",
              "tactic": "Execution",
              "description": "Eksekusi perintah/script di mesin target (RCE, command injection)."},
    "T1505.003": {"id": "T1505.003", "name": "Web Shell",
                   "tactic": "Persistence",
                   "description": "Upload web shell untuk mempertahankan akses."},
    "T1210": {"id": "T1210", "name": "Exploitation of Remote Services",
              "tactic": "Lateral Movement",
              "description": "Eksploitasi layanan jarak jauh (deserialization) untuk berpindah antar host."},
    "T1110": {"id": "T1110", "name": "Brute Force",
              "tactic": "Credential Access",
              "description": "Menebak/membruteforce kredensial login."},
    "T1550": {"id": "T1550", "name": "Use Alternate Authentication Material",
              "tactic": "Defense Evasion",
              "description": "Bypass autentikasi memakai material alternatif (token/sesi curian)."},
    "T1552.001": {"id": "T1552.001", "name": "Credentials In Files",
                   "tactic": "Credential Access",
                   "description": "Mencuri kredensial dari file (.env, .git, config) yang terekspos."},
    "T1003": {"id": "T1003", "name": "OS Credential Dumping",
              "tactic": "Credential Access",
              "description": "Ekstraksi kredensial dari sistem (database dump, memory)."},
    "T1556": {"id": "T1556", "name": "Modify Authentication Process",
              "tactic": "Credential Access",
              "description": "Memanipulasi proses autentikasi (password-reset poisoning)."},
    "T1539": {"id": "T1539", "name": "Steal Web Session Cookie",
              "tactic": "Credential Access",
              "description": "Mencuri cookie sesi untuk membajak sesi user."},
    "T1005": {"id": "T1005", "name": "Data from Local System",
              "tactic": "Collection",
              "description": "Mengumpulkan data sensitif (LFI, backup, database leak)."},
    "T1083": {"id": "T1083", "name": "File and Directory Discovery",
              "tactic": "Discovery",
              "description": "Menemukan file/direktori internal lewat directory listing."},
    "T1046": {"id": "T1046", "name": "Network Service Discovery",
              "tactic": "Discovery",
              "description": "Pemindaian layanan di jaringan internal."},
    "T1068": {"id": "T1068", "name": "Exploitation for Privilege Escalation",
              "tactic": "Privilege Escalation",
              "description": "Eksploitasi kelemahan kontrol akses (IDOR) untuk akses lebih tinggi."},
    "T1584.001": {"id": "T1584.001", "name": "Compromise Infrastructure",
                   "tactic": "Resource Development",
                   "description": "Mengambil alih infrastruktur target (subdomain takeover)."},
    "T1595.001": {"id": "T1595.001", "name": "Active Scanning",
                   "tactic": "Reconnaissance",
                   "description": "Pemindaian aktif untuk mengumpulkan informasi target."},
    "T1593": {"id": "T1593", "name": "Search Open Websites/Domains",
              "tactic": "Reconnaissance",
              "description": "Pencarian OSINT melalui sumber publik."},
    "T1486": {"id": "T1486", "name": "Data Encrypted for Impact",
              "tactic": "Impact",
              "description": "Enkripsi data target (ransomware) sebagai dampak akhir."},
    "T1565": {"id": "T1565", "name": "Data Manipulation",
              "tactic": "Impact",
              "description": "Manipulasi/penghancuran data sebagai dampak akhir."},
}

_SEV_MITRE = {
    "CRITICAL": "T1486",
    "HIGH": "T1565",
    "MEDIUM": "T1005",
    "LOW": "T1595.001",
}


class MitreAttackMapper:
    """Map temuan / tag ke MITRE ATT&CK technique."""

    def map_tags(self, tags) -> Optional[str]:
        for tag in (tags or []):
            if tag in TECHNIQUE_BY_TAG:
                return TECHNIQUE_BY_TAG[tag]
        return None

    def map_finding(self, finding: Dict) -> Optional[Dict]:
        tags = finding.get("tags") or []
        tid = self.map_tags(tags)
        if not tid:
            ftype = str(finding.get("type", "")).lower()
            tid = TECHNIQUE_BY_TYPE.get(ftype)
        if not tid:
            # fallback severity-based: temuan penting tanpa teknik spesifik
            tid = _SEV_MITRE.get(str(finding.get("severity", "")).upper())
        return self.detail(tid)

    def detail(self, tid: Optional[str]) -> Optional[Dict]:
        if not tid:
            return None
        d = TECHNIQUE_DETAILS.get(tid)
        if not d:
            return {"id": tid, "name": tid, "tactic": "Unknown",
                    "description": ""}
        return d


def annotate_paths(paths: List[Dict]) -> List[Dict]:
    """Anotasi tiap step attack path dengan MITRE technique + tactic.

    Memperkaya path (mutasi in-place pada copy) dan menambahkan:
    - step["mitre"]        : {technique_id, name, tactic}
    - path["mitre_chain"]  : daftar teknik unik berurutan
    - path["tactic_progression"] : daftar tactic unik berurutan
    - path["mitre_summary"]: "T1190 -> T1003 -> T1078"
    """
    mapper = MitreAttackMapper()
    out = []
    for p in paths:
        p = dict(p)
        steps = []
        for s in p.get("steps", []):
            s = dict(s)
            mitre = mapper.detail(mapper.map_tags(s.get("tags")))
            if not mitre:
                mitre = mapper.detail(
                    _SEV_MITRE.get(str(s.get("severity", "")).upper()))
            s["mitre"] = mitre
            steps.append(s)
        p["steps"] = steps
        techniques = []
        for s in steps:
            tid = (s.get("mitre") or {}).get("id")
            if tid and tid not in techniques:
                techniques.append(tid)
        p["mitre_chain"] = techniques
        p["mitre_summary"] = " -> ".join(techniques)
        tactics = []
        for s in steps:
            tac = (s.get("mitre") or {}).get("tactic")
            if tac and tac != "Unknown" and tac not in tactics:
                tactics.append(tac)
        p["tactic_progression"] = tactics
        out.append(p)
    return out


def build_mitre_chains(paths: List[Dict], limit: int = 5) -> List[Dict]:
    """Susun chain tingkat tinggi: path + tactic progression + dampak akhir."""
    chains = []
    for p in paths[:limit]:
        tactics = p.get("tactic_progression", [])
        steps = p.get("steps", [])
        last_tech = (steps[-1].get("mitre") or {}).get("id") if steps else "?"
        chains.append({
            "title": " -> ".join(tactics) if tactics else "Chain",
            "tactics": tactics,
            "techniques": p.get("mitre_chain", []),
            "technique_summary": p.get("mitre_summary", ""),
            "final_technique": last_tech,
            "severity": p.get("severity", "LOW"),
            "score": p.get("score", 0),
            "impact": p.get("impact", ""),
            "steps": p.get("steps", []),
        })
    return chains


def mitre_markdown(chains: List[Dict], limit: int = 5) -> List[str]:
    """Buat blok markdown "Attack Paths (MITRE ATT&CK)"."""
    if not chains:
        return []
    lines = ["## Attack Paths (MITRE ATT&CK)", ""]
    for i, c in enumerate(chains[:limit], 1):
        lines.append(f"### {c['severity']} PATH #{i}: {c['title']}")
        lines.append("")
        lines.append(f"**Criticality Score:** {c['score']:.1f}/100")
        lines.append("")
        lines.append("**MITRE Tactic Progression:**")
        lines.append("")
        for j, s in enumerate(c.get("steps", []), 1):
            mitre = s.get("mitre") or {}
            tid = mitre.get("id", "?")
            name = mitre.get("name", "")
            tactic = mitre.get("tactic", "")
            lines.append(
                f"{j}. **[{tid}] {name}** ({tactic})")
            lines.append(f"   - {s.get('title', '')} @ `{s.get('endpoint', '')}`")
        lines.append("")
        lines.append(f"-> **Impact: {c.get('impact', '')}**")
        if c.get("technique_summary"):
            lines.append(f"**MITRE Techniques:** {c['technique_summary']}")
        lines.append("")
    return lines


def render_mitre_dot(paths: List[Dict], target: str = "") -> str:
    """Render attack paths dengan label MITRE technique ke Graphviz .dot."""
    lines = ['digraph "attack_paths_mitre" {', "  rankdir=LR;",
             '  node [shape=box, style=rounded, fontname="Helvetica"];']
    if target:
        lines.append(f'  label="{target}";')
    node_styles = {
        "CRITICAL": 'fillcolor="#f8d7da", color="#dc3545", style="filled"',
        "HIGH": 'fillcolor="#ffeeba", color="#e0a800", style="filled"',
        "MEDIUM": 'fillcolor="#d1ecf1", color="#0c5460", style="filled"',
        "LOW": 'fillcolor="#d6d8db", color="#383d41", style="filled"',
    }
    seen = set()
    for p in paths[:10]:
        for i, s in enumerate(p.get("steps", [])):
            nid = s.get("id", "")
            if nid in seen:
                continue
            seen.add(nid)
            style = node_styles.get(s.get("severity", ""), node_styles["LOW"])
            mitre = s.get("mitre") or {}
            label = f"{nid}: {s.get('title', '')[:40]}"
            if mitre.get("id"):
                label += f"\\n[{mitre['id']}] {mitre.get('name', '')[:40]}"
            lines.append(f'  "{nid}" [label="{label}", {style}];')
            if i > 0:
                prev = p["steps"][i - 1].get("id", "")
                lines.append(f'  "{prev}" -> "{nid}";')
    lines.append("}")
    return "\n".join(lines)