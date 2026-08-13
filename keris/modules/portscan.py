"""Port scanner sederhana berbasis TCP connect."""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from keris.core.logger import info, ok, warn

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 993, 995,
    1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432, 5900, 5984, 6379, 6443,
    8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 11211, 15672, 27017,
]


def _scan_port(host: str, port: int, timeout: float) -> Optional[int]:
    """Coba TCP connect. Kembalikan port jika terbuka, None jika tidak."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except OSError:
        return None


def scan_ports(host: str, ports: Optional[List[int]] = None,
               workers: int = 20, timeout: float = 2.0) -> List[int]:
    """Scan port umum pada host. Mengembalikan daftar port terbuka."""
    if ports is None:
        ports = COMMON_PORTS
    info(f"Scanning {len(ports)} port pada {host} ...")
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_scan_port, host, p, timeout) for p in ports]
        for fut in as_completed(futures):
            port = fut.result()
            if port is not None:
                open_ports.append(port)
    open_ports.sort()
    if open_ports:
        ok(f"Port terbuka: {', '.join(str(p) for p in open_ports)}")
    else:
        warn("Tidak ada port umum yang terbuka")
    return open_ports
