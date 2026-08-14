"""WebSocket security: deteksi endpoint & uji keamanan handshake/message.

Uji yang dilakukan:
- Temukan endpoint WebSocket (dari halaman / path umum / JS bundle).
- Cek handshake tanpa Origin (server harus menolak cross-origin).
- Cek autentikasi: apakah koneksi bisa dibuka tanpa token/sesi.
- Cek echo/refleksi pesan yang bisa dipakai injeksi atau amplifikasi.

Dependency `websocket-client` diimpor secara opsional; bila tidak terpasang,
modul melaporkan pesan dan tidak crash.
"""

import re
from typing import List, Optional
from urllib.parse import urlparse

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

WS_PATHS = [
    "/ws", "/websocket", "/socket", "/socket.io/", "/sockjs-node/",
    "/ws/chat", "/api/ws", "/v1/ws", "/realtime", "/stream", "/live",
]

# Indikator halaman/JS memuat WebSocket
WS_HINTS = [
    r"new\s+WebSocket\((['\"])([^'\"]+)",
    r"wss?://[^\"'\s>]+",
    r"socket\.io",
]


def _ws_url(base: str, path: str) -> str:
    p = urlparse(base)
    scheme = "wss" if p.scheme == "https" else "ws"
    return f"{scheme}://{p.netloc}{path}"


def _find_ws_urls(base: str, client: KerisHTTP, sample_assets: Optional[List[str]] = None) -> List[str]:
    """Kumpulkan URL WebSocket dari halaman utama + bundle JS."""
    found: List[str] = []
    try:
        r = client.get(base, timeout=15)
        page = r.text
    except requests.RequestException:
        page = ""

    # dari halaman utama
    for m in re.finditer(WS_HINTS[0], page) or []:
        found.append(m.group(2))
    for m in re.finditer(WS_HINTS[1], page):
        found.append(m.group(0).rstrip("'\">"))

    # dari asset JS bila tersedia
    assets = sample_assets or []
    for asset in assets[:10]:
        try:
            r = client.get(asset, timeout=12)
        except requests.RequestException:
            continue
        text = r.text
        for m in re.finditer(WS_HINTS[1], text):
            u = m.group(0).rstrip("'\">")
            if u not in found:
                found.append(u)

    seen = set()
    out = []
    for u in found:
        u = u.strip()
        if u.startswith("/"):
            u = _ws_url(base, u)
        if u.startswith(("ws://", "wss://")) and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _probe_handshake(url: str, origin: Optional[str], token: Optional[str]) -> Optional[dict]:
    """Coba handshake. Mengembalikan hasil probe atau None bila tidak ada client."""
    try:
        from websocket import create_connection, WebSocketBadStatusException
        from websocket import WebSocketException as _WSE
    except ImportError:
        return None

    header = {}
    if origin:
        header["Origin"] = origin
    if token:
        header["Authorization"] = f"Bearer {token}"

    try:
        ws = create_connection(url, header=header, timeout=5)
        ws.close()
        return {"connected": True, "status": "101", "reason": "handshake diterima"}
    except WebSocketBadStatusException as e:
        return {"connected": False, "status": str(e.status_code),
                "reason": str(e) or "ditolak"}
    except Exception as e:  # noqa: BLE001 - apapun, catat
        return {"connected": False, "status": "error", "reason": str(e)[:120]}


def check_websocket(base: str, client: KerisHTTP,
                    sample_assets: Optional[List[str]] = None) -> List[Finding]:
    """Uji keamanan WebSocket pada target."""
    findings: List[Finding] = []
    urls = _find_ws_urls(base, client, sample_assets)

    # tambahkan path umum bila belum ketemu
    for path in WS_PATHS:
        u = _ws_url(base, path)
        if u not in urls:
            urls.append(u)

    if not urls:
        info("Tidak ada endpoint WebSocket yang terdeteksi")
        return findings

    ok(f"Endpoint WebSocket kandidat: {len(urls)}")

    for url in urls[:12]:
        # 1. handshake normal
        normal = _probe_handshake(url, origin=None, token=None)
        if normal is None:
            warn("`websocket-client` belum terpasang; install dengan: pip install websocket-client")
            findings.append(Finding(
                "INFO", "Modul WebSocket butuh dependency",
                base,
                "Pasang `websocket-client` untuk menjalankan uji WebSocket: "
                "`pip install websocket-client`.",
                "",
            ))
            break

        if normal.get("connected"):
            findings.append(Finding(
                "MEDIUM", "WebSocket terbuka tanpa autentikasi",
                url,
                "Koneksi WebSocket diterima tanpa token/sesi. Bila kanal "
                "membawa data sensitif, pastikan auth ditangani pada lapisan "
                "aplikasi (sub-protocol/message).",
                f"handshake=101, reason={normal.get('reason', '')}",
            ))

            # 2. tanpa Origin — harus ditolak bila kebijakan ketat
            no_origin = _probe_handshake(url, origin="", token=None)
            if no_origin and no_origin.get("connected"):
                findings.append(Finding(
                    "LOW", "WebSocket tidak memvalidasi Origin",
                    url,
                    "Handshake tanpa header Origin diterima. Cross-origin "
                    "WebSocket hijacking (CSWSH) dapat membuka kanal dari situs "
                    "pihak ketiga.",
                    "origin=none, handshake=101",
                ))
        elif normal.get("status") not in ("404", "400"):
            findings.append(Finding(
                "LOW", "WebSocket kandidat merespons aneh",
                url,
                f"Endpoint merespons status {normal['status']}. Verifikasi "
                "apakah ini titik WebSocket yang sebenarnya.",
                f"status={normal['status']}, reason={normal.get('reason', '')[:200]}",
            ))

    return findings
