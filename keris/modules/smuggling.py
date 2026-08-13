"""HTTP request smuggling detection (CL.TE / TE.CL) via raw socket.

Non-destruktif: kirim request khusus dan amati perilaku koneksi/response.
Klasik:
- CL.TE: backend membaca Content-Length; frontend membaca Transfer-Encoding.
- TE.CL: kebalikannya.

Deteksi berbasis perilaku koneksi (tidak perlu request kedua berbahaya).
"""

import socket
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

DEFAULT_TIMEOUT = 8.0


def _connect(host: str, port: int, tls: bool) -> Optional[socket.socket]:
    try:
        s = socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT)
        if tls:
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.settimeout(DEFAULT_TIMEOUT)
        return s
    except OSError:
        return None


def _recv_all(s: socket.socket, duration: float = 2.0) -> bytes:
    data = b""
    end = time.monotonic() + duration
    s.setblocking(False)
    while time.monotonic() < end:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        except (BlockingIOError, socket.timeout):
            time.sleep(0.05)
        except OSError:
            break
    s.setblocking(True)
    return data


def _test_cl_te(host: str, port: int, tls: bool) -> bool:
    """CL.TE: kirim request dengan CL besar + TE chunked. Jika backend pakai CL,
    ia menunggu body (koneksi menggantung / timeout). Frontend pakai TE -> kirim.
    Deteksi: respons pertama muncul cepat (TE dipakai frontend), lalu koneksi
    tetap terbuka karena body CL belum lengkap.
    """
    s = _connect(host, port, tls)
    if not s:
        return False
    # header: Content-Length: 6 (jumlah total body) + Transfer-Encoding: chunked
    # body chunked: "0\r\n\r\n" (terminasi) diikuti 4 byte untuk melengkapi CL
    payload = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Content-Length: 6\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n"
        b"0\r\n"
        b"\r\n"
        b"SMUGGLE"
    )
    try:
        s.sendall(payload)
        # CL.TE: backend membaca CL=6, jadi ia menunggu 6 byte tambahan.
        # Respons tidak datang dalam waktu singkat (timeout) -> kandidat.
        time.sleep(1.0)
        s.sendall(b"X")  # kirim 1 byte lagi
        data = _recv_all(s, 2.5)
        if not data:
            # koneksi menggantung menunggu body -> kemungkinan CL dipakai backend
            # setelah 6 byte: "SMUGGL" sudah cukup -> kirim sisanya
            s.sendall(b"E")
            data2 = _recv_all(s, 1.5)
            s.close()
            # Jika backend memproses request kedua yang diselundupkan, kita akan
            # melihat respons kedua (mis. 400/200) meski body pertama selesai.
            # Heuristik: dua respons berbeda atau status non-empty.
            return bool(data2) and len(data) == 0
        s.close()
        return False
    except OSError:
        try:
            s.close()
        except OSError:
            pass
        return False


def _test_te_cl(host: str, port: int, tls: bool) -> bool:
    """TE.CL: kirim TE chunked dengan CL yang TIDAK termasuk isi chunked penuh."""
    s = _connect(host, port, tls)
    if not s:
        return False
    # CL = 4 (hanya "0\r\n\r\n" sepanjang 4 byte sebenarnya; di sini buat
    # ketidakcocokan: CL=4 sedangkan chunked body berisi "0\r\n\r\nSMUGGLE")
    payload = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Content-Length: 4\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n"
        b"5\r\nSMUGG\r\n"
        b"0\r\n\r\n"
    )
    try:
        s.sendall(payload)
        data = _recv_all(s, 2.5)
        s.close()
        # TE.CL: backend (CL=4) membaca hanya "0\r\n\r" lalu menganggap selesai,
        # sisa "SMUGGLE" menjadi request kedua yang diolah frontend. Indikasi:
        # ada dua respons atau respons kedua (status non-200) muncul.
        if not data:
            return False
        count = data.count(b"HTTP/1.1")
        return count >= 2
    except OSError:
        try:
            s.close()
        except OSError:
            pass
        return False


def check_smuggling(base: str, client: KerisHTTP) -> List[Finding]:
    """Uji request smuggling CL.TE/TE.CL pada target."""
    findings = []
    p = urlparse(base)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    tls = p.scheme == "https"
    info(f"Request smuggling test: {host}:{port}")

    if _test_cl_te(host, port, tls):
        findings.append(Finding(
            "HIGH", "Potensi HTTP request smuggling (CL.TE)",
            base, "Perilaku koneksi konsisten dengan parsing Content-Length di "
                  "backend dan Transfer-Encoding di frontend. Verifikasi dengan "
                  "tools khusus (Burp/CL.TE scanner).",
            "smuggling=CL.TE",
        ))
    if _test_te_cl(host, port, tls):
        findings.append(Finding(
            "HIGH", "Potensi HTTP request smuggling (TE.CL)",
            base, "Respons ganda terdeteksi — konsisten dengan parsing "
                  "Transfer-Encoding di backend dan Content-Length di frontend.",
            "smuggling=TE.CL",
        ))
    if not findings:
        debug("Tidak ada indikasi request smuggling")
    return findings