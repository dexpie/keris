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
