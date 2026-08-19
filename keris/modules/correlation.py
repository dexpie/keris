"""Correlation engine: chains low/medium findings into critical attack chains.

v0.15.0 upgrade:
- `build_chains` (lama) — rule-based chains yang ringkas.
- `build_paths` (baru) — Attack Path Generator: membangun graph hubungan antar
  finding, menelusuri semua path serangan hingga `path_depth`, dan menilai
  tiap path dengan Criticality Score (severity + panjang + ease-of-exploit).
- `render_dot` — output Graphviz `.dot` untuk visualisasi path.
- `criticality_score` — Prioritization Engine.
"""

import os
import re
from typing import Dict, List, Optional, Tuple

# severity weight untuk scoring
SEV_WEIGHT = {"CRITICAL": 100, "HIGH": 60, "MEDIUM": 30, "LOW": 10, "INFO": 0}


def sev_weight(sev: str) -> int:
    return SEV_WEIGHT.get(str(sev or "").upper(), 0)


CHAIN_RULES = [
    {
        "name": "Cache poisoning + reflected XSS",
        "needs": ["cache-poison", "xss"],
        "severity": "CRITICAL",
        "why": "Reflected XSS yang bisa disuntik lewat header cacheable menjadi stored XSS untuk semua user yang memuat cache.",
    },
    {
        "name": "Host header injection + password reset",
        "needs": ["host-header", "reset-poisoning"],
        "severity": "HIGH",
        "why": "Host header yang direfleksikan di link reset password memungkinkan akun dikompromikan oleh attacker (password-reset poisoning).",
    },
    {
        "name": "Auth bypass + sensitive endpoint",
        "needs": ["auth-bypass", "sensitive"],
        "severity": "CRITICAL",
        "why": "Bypass autentikasi plus data sensitif yang terbuka memberikan akses penuh ke informasi internal tanpa kredensial.",
    },
    {
        "name": "Weak credentials + admin panel",
        "needs": ["weak-login", "admin-panel"],
        "severity": "CRITICAL",
        "why": "Login lemah pada panel admin memungkinkan takeover langsung.",
    },
    {
        "name": "Directory listing + backup file",
        "needs": ["listing", "backup"],
        "severity": "HIGH",
        "why": "Directory listing yang membocorkan file backup membuat source code atau konfigurasi bisa diekstrak.",
    },
    {
        "name": "CORS wildcard + auth cookie",
        "needs": ["cors", "cookie"],
        "severity": "HIGH",
        "why": "CORS yang mengizinkan origin bebas plus cookie session tanpa proteksi membuat data user bisa dibaca dari situs lain.",
    },
]

_TAGS = {
    "cache-poison": ("cache", "poison"),
    "xss": ("xss", "cross-site", "cross site", "dom"),
    "host-header": ("host header", "host-header", "hostheader"),
    "reset-poisoning": ("reset", "password-reset", "forgot"),
    "auth-bypass": ("auth bypass", "authentication bypass", "bypass"),
    "sensitive": ("sensitive", "pii", "credential", "api key", "token", "secret"),
    "weak-login": ("weak", "brute", "login"),
    "admin-panel": ("admin", "panel"),
    "listing": ("directory listing", "listing"),
    "backup": ("backup", ".bak", ".zip"),
    "cors": ("cors", "cross-origin resource"),
    "cookie": ("cookie", "session"),
    # tag tambahan untuk path generation
    "git-leak": ("git", ".git", "source tree"),
    "secret": ("aws", "key", "secret", "token", "credential"),
    "rce": ("rce", "remote code", "command injection", "shell", "exec"),
    "ssrf": ("ssrf", "server-side request"),
    "sqli": ("sqli", "sql injection", "union"),
    "xss-any": ("xss", "cross-site"),
    "open-redirect": ("open redirect", "redirect"),
    "takeover": ("takeover", "subdomain takeover"),
    "directory-listing": ("directory listing", "listing"),
    "sqlite-leak": ("sql", "database", "dump"),
    "idor": ("idor", "insecure direct object"),
    "file-read": ("file read", "lfi", "path traversal", "etc/passwd"),
    "upload": ("upload", "file upload"),
    "deserialization": ("deserial", "pickle", "yaml"),
}

# tag yang "membuka jalan" (prerequisite / input ke tahap berikutnya)
_PREREQ_TAGS = {
    "git-leak": "source code bocor",
    "secret": "kredensial/secret bocor",
    "sqlite-leak": "database bocor",
    "listing": "file listing terbuka",
    "directory-listing": "file listing terbuka",
    "backup": "file backup terekspos",
    "weak-login": "login lemah",
    "xss": "sink XSS",
    "ssrf": "SSRF",
    "open-redirect": "open redirect",
    "file-read": "file read / LFI",
    "upload": "upload tidak aman",
    "idor": "IDOR",
    "sqli": "SQL injection",
    "cors": "CORS longgar",
}

# tag "dampak" yang menjadi tujuan akhir (impact node)
_IMPACT_TAGS = {
    "rce": "Remote Code Execution",
    "takeover": "Subdomain/account takeover",
    "auth-bypass": "Auth bypass",
    "admin-panel": "Akses panel admin",
    "secret": "Kebocoran kredensial",
    "sqlite-leak": "Exfiltrasi database",
    "sensitive": "Kebocoran data sensitif",
}


_NEEDLE_RE_CACHE = {}


def _needle_re(needle: str):
    """Kompilasi regex pencocokan needle.

    Needle pendek (<=4, murni alfabet) memakai word boundary agar tidak
    salah-match substring seperti "rce" di dalam "source". Needle lain
    (mis. ".git", ".bak", frasa) tetap substring match.
    """
    rx = _NEEDLE_RE_CACHE.get(needle)
    if rx is not None:
        return rx
    if len(needle) <= 4 and needle.isalpha():
        rx = re.compile(rf"\b{re.escape(needle)}\b", re.IGNORECASE)
    else:
        rx = re.compile(re.escape(needle), re.IGNORECASE)
    _NEEDLE_RE_CACHE[needle] = rx
    return rx


def _tag_finding(f: Dict) -> List[str]:
    text = " ".join([
        str(f.get("title", "")),
        str(f.get("detail", "")),
        str(f.get("endpoint", "")),
        str(f.get("evidence", "")),
    ]).lower()
    tags = []
    for tag, needles in _TAGS.items():
        if any(_needle_re(n).search(text) for n in needles):
            tags.append(tag)
    return tags


def build_chains(findings: List[Dict]) -> List[Dict]:
    """Returns a list of chain findings (dicts) derived from existing findings."""
    if not findings:
        return []
    tagged = [(f, set(_tag_finding(f))) for f in findings]
    chains = []
    for rule in CHAIN_RULES:
        needs = set(rule["needs"])
        hits = []
        covered = set()
        for f, tags in tagged:
            have = needs.intersection(tags)
            if have:
                hits.append(f)
                covered |= have
        if covered == needs and hits:
            chains.append({
                "severity": rule["severity"],
                "title": rule["name"],
                "endpoint": " / ".join(str(f.get("endpoint", "")) for f in hits),
                "detail": rule["why"],
                "evidence": "Chain terbentuk dari: " + "; ".join(
                    "[{s}] {t} @ {e}".format(
                        s=f.get("severity", "?"), t=f.get("title", "?"), e=f.get("endpoint", "?"))
                    for f in hits),
                "chain": rule["name"],
                "source": "correlation",
            })
    return chains


# ---------------------------------------------------------------------------
# Attack Path Generator (v0.15.0)
# ---------------------------------------------------------------------------

def _finding_id(f: Dict, idx: int) -> str:
    return f.get("id") or f.get("fingerprint") or f"F{idx}"


def _same_endpoint(a: Dict, b: Dict) -> bool:
    ea = str(a.get("endpoint", ""))
    eb = str(b.get("endpoint", ""))
    if not ea or not eb:
        return False
    return ea == eb or ea in eb or eb in ea


def _ease(sev: str) -> float:
    """Ease of exploitation dari severity (0..1)."""
    return {"CRITICAL": 0.9, "HIGH": 0.7, "MEDIUM": 0.5, "LOW": 0.3}.get(
        str(sev or "").upper(), 0.1)


def build_paths(findings: List[Dict], path_depth: int = 3) -> List[Dict]:
    """Bangun graph hubungan finding dan telusuri attack paths.

    Edge A -> B dibuat bila A punya tag prerequisite yang relevan dan B punya
    tag dampak, atau keduanya di endpoint yang sama dengan severity meningkat.
    Mengembalikan daftar path terurut by criticality score.
    """
    if not findings:
        return []
    nodes = []
    for idx, f in enumerate(findings):
        tags = set(_tag_finding(f))
        nodes.append({
            "id": _finding_id(f, idx),
            "finding": f,
            "tags": tags,
            "sev": str(f.get("severity", "INFO")).upper(),
            "endpoint": str(f.get("endpoint", "")),
        })

    # adjacency: prereq_node -> impact_node
    adj: Dict[str, List[str]] = {n["id"]: [] for n in nodes}
    node_map = {n["id"]: n for n in nodes}

    for a in nodes:
        for b in nodes:
            if a["id"] == b["id"]:
                continue
            prereq = _PREREQ_TAGS.keys() & a["tags"]
            impact = _IMPACT_TAGS.keys() & b["tags"]
            # a "membuka jalan" ke b: a punya prerequisite & b punya impact
            # dan severity b >= severity a (escalation) ATAU endpoint sama
            escalated = sev_weight(b["sev"]) >= sev_weight(a["sev"])
            same_ep = _same_endpoint(a["finding"], b["finding"])
            if prereq and impact and (escalated or same_ep):
                if b["id"] not in adj[a["id"]]:
                    adj[a["id"]].append(b["id"])

    # node tanpa predecessor = titik awal path
    has_pred = {b for targets in adj.values() for b in targets}
    starts = [n["id"] for n in nodes if n["id"] not in has_pred]
    if not starts:
        # graph cyclic penuh (semua node punya predecessor): mulai dari semua
        starts = [n["id"] for n in nodes]

    # enumerasi path dengan DFS berbatas kedalaman
    paths: List[List[str]] = []
    visited_edges = set()

    def _dfs(cur: str, trail: List[str]):
        if len(trail) > path_depth:
            return
        # node impact = titik berbahaya; path valid berhenti di sana
        nxt = adj[cur]
        is_impact = bool(node_map[cur]["tags"] & _IMPACT_TAGS.keys())
        if is_impact or not nxt:
            if len(trail) >= 2:
                paths.append(list(trail))
        for nb in nxt:
            edge = (cur, nb)
            if edge in visited_edges:
                continue
            visited_edges.add(edge)
            _dfs(nb, trail + [nb])

    for s in starts:
        _dfs(s, [s])

    # build hasil path dengan score
    out = []
    for p in paths:
        steps = []
        for nid in p:
            n = node_map[nid]
            steps.append({
                "id": nid,
                "severity": n["sev"],
                "title": str(n["finding"].get("title", "")),
                "endpoint": n["endpoint"],
                "evidence": str(n["finding"].get("evidence", ""))[:200],
                "tags": sorted(n["tags"]),
            })
        score = criticality_score(steps)
        impact = _path_impact(steps)
        out.append({
            "steps": steps,
            "score": score,
            "impact": impact,
            "severity": _score_severity(score),
            "source": "correlation-path",
        })

    out.sort(key=lambda x: x["score"], reverse=True)
    return out


def _path_impact(steps: List[Dict]) -> str:
    for s in reversed(steps):
        for tag, label in _IMPACT_TAGS.items():
            if tag in s.get("tags", []):
                return label
    return "Dampak akhir tidak teridentifikasi"


def _score_severity(score: float) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def criticality_score(steps: List[Dict]) -> float:
    """Prioritization Engine: skor 0..100 untuk satu attack path.

    Komponen:
    - severity tiap step (weighted, bobot step akhir lebih besar).
    - panjang path (semakin pendek = lebih langsung berbahaya).
    - ease of exploitation (dari severity).
    """
    if not steps:
        return 0.0
    n = len(steps)
    sev_sum = 0.0
    for i, s in enumerate(steps):
        w = 1.0 + 0.5 * (i / max(n - 1, 1))  # step akhir lebih berbobot
        sev_sum += sev_weight(s.get("severity", "")) * w
    sev_component = sev_sum / max(n * 100, 1)
    # path pendek lebih berbahaya: 1 step menuju impact = effort minimal
    length_component = 1.0 - min((n - 1) / max(path_depth_global(), 1), 0.6)
    ease_component = max(_ease(s.get("severity", "")) for s in steps)
    return round((sev_component * 60) + (length_component * 25) + (ease_component * 15), 1)


_path_depth_default = 3


def path_depth_global() -> int:
    return _path_depth_default


def set_path_depth(depth: int) -> None:
    global _path_depth_default
    _path_depth_default = max(2, min(int(depth or 3), 10))


# ---------------------------------------------------------------------------
# Visual output (Graphviz DOT)
# ---------------------------------------------------------------------------

def render_dot(paths: List[Dict], target: str = "") -> str:
    """Render attack paths menjadi dokumen Graphviz .dot."""
    lines = ['digraph "attack_paths" {', "  rankdir=LR;",
             '  node [shape=box, style=rounded, fontname="Helvetica"];']
    if target:
        lines.append(f'  label="{target}";')
    node_styles = {
        "CRITICAL": 'fillcolor="#f8d7da", color="#dc3545", style="filled"',
        "HIGH": 'fillcolor="#ffeeba", color="#e0a800", style="filled"',
        "MEDIUM": 'fillcolor="#d1ecf1", color="#0c5460", style="filled"',
        "LOW": 'fillcolor="#d6d8db", color="#383d41", style="filled"',
    }
    seen_nodes = set()
    for p in paths[:10]:
        for i, s in enumerate(p["steps"]):
            nid = s["id"]
            if nid in seen_nodes:
                continue
            seen_nodes.add(nid)
            style = node_styles.get(s["severity"], node_styles["LOW"])
            label = s["title"].replace('"', "'")[:60]
            lines.append(
                f'  "{nid}" [label="{nid}: {label}", {style}];')
            if i > 0:
                prev = p["steps"][i - 1]["id"]
                lines.append(f'  "{prev}" -> "{nid}";')
    lines.append("}")
    return "\n".join(lines)


def save_dot(paths: List[Dict], out_path: str, target: str = "") -> Optional[str]:
    """Simpan DOT ke file; kembalikan path, atau None bila gagal."""
    try:
        parent = os.path.dirname(out_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(render_dot(paths, target))
        return out_path
    except OSError:
        return None


def dot_to_image(dot_path: str, out_path: str) -> bool:
    """Konversi DOT ke PNG/SVG via binary `dot` (Graphviz)."""
    ext = os.path.splitext(out_path)[1].lstrip(".") or "png"
    cmd = ["dot", "-T" + ext, dot_path, "-o", out_path]
    try:
        import subprocess

        r = subprocess.run(cmd, capture_output=True, timeout=30)
        return r.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Markdown section
# ---------------------------------------------------------------------------

def paths_markdown(paths: List[Dict], limit: int = 5) -> List[str]:
    """Buat blok markdown "Attack Paths" berisi step-by-step tiap path."""
    if not paths:
        return []
    lines = ["## Attack Paths", ""]
    for i, p in enumerate(paths[:limit], 1):
        sev = p["severity"]
        lines.append(f"### Path {i}: {sev} - {p['impact']}")
        lines.append("")
        lines.append(f"**Criticality Score:** {p['score']:.1f}/100")
        lines.append("")
        for j, s in enumerate(p["steps"], 1):
            ev = (s.get("evidence") or "").strip()
            ev = ev[:160] if ev else ""
            lines.append(f"{j}. `[{s['severity']}]` {s['title']} @ `{s['endpoint']}`")
            if ev:
                lines.append(f"   - Bukti: {ev}")
        lines.append("")
        lines.append(f"-> **Impact: {p['impact']}**")
        lines.append("")
    return lines