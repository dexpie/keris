"""Tes v0.16.0: Auto-Pivoting Framework (pivot_auto.py)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class FakeClient:
    """KerisHTTP stub yang mengembalikan respons sesuai URL."""

    def __init__(self, responses=None):
        self.responses = responses or {}

    def get(self, url, timeout=8):
        class R:
            def __init__(self, code, content, text):
                self.status_code = code
                self.content = content
                self.text = text
        for needle, (code, body) in self.responses.items():
            if needle in url:
                return R(code, body.encode(), body)
        return R(404, b"", "not found")


class FakeRce:
    """PivotExecutor RCE yang mensimulasikan output perintah."""

    mode = "rce"

    def __init__(self, outputs):
        self.outputs = outputs  # {cmd_substring: output}
        self.calls = []

    def run(self, cmd):
        self.calls.append(cmd)
        for needle, out in self.outputs.items():
            if needle in cmd:
                return 200, out
        return 200, ""

    def fetch(self, url, timeout=8):
        return 0, b""


class TestParseInterfaces:
    def test_parse_private_ips(self):
        from keris.modules.pivot_auto import parse_interfaces

        out = """
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.5  netmask 255.0.0.0
        inet 192.168.1.20  netmask 255.255.255.0
lo: inet 127.0.0.1
        """
        ips = parse_interfaces(out)
        assert "10.0.0.5" in ips
        assert "192.168.1.20" in ips
        assert "127.0.0.1" not in ips

    def test_parse_ip_a(self):
        from keris.modules.pivot_auto import parse_interfaces

        out = "inet 172.16.31.7/24 brd 172.16.31.255 scope global eth0"
        ips = parse_interfaces(out)
        assert "172.16.31.7" in ips

    def test_no_interfaces(self):
        from keris.modules.pivot_auto import parse_interfaces

        assert parse_interfaces("no such interface") == []


class TestCidrs:
    def test_cidrs_from_ips(self):
        from keris.modules.pivot_auto import _cidrs_from_ips

        cidrs = _cidrs_from_ips(["10.0.0.5", "192.168.1.20"])
        assert "10.0.0.0/8" in cidrs
        assert "192.168.0.0/16" in cidrs
        assert "10.0.0.0/24" in cidrs

    def test_non_private_filtered(self):
        from keris.modules.pivot_auto import _cidrs_from_ips

        assert "8.8.8.0/24" not in _cidrs_from_ips(["8.8.8.8"])


class TestDetectInterfaces:
    def test_detect_interfaces(self, tmp_path):
        from keris.modules.pivot_auto import detect_interfaces

        ex = FakeRce({
            "ifconfig": "eth0 inet 10.0.0.5",
            "ip a": "eth0 inet 10.0.0.5",
        })
        log = str(tmp_path / "pivot.log")
        assert detect_interfaces(ex, logfile=log) == ["10.0.0.5"]
        assert os.path.exists(log)

    def test_no_detect(self):
        from keris.modules.pivot_auto import detect_interfaces

        ex = FakeRce({"ifconfig": "not found"})
        assert detect_interfaces(ex) == []


class TestScanInternal:
    def test_scan_finds_service(self, tmp_path):
        from keris.modules.pivot_auto import scan_internal

        ex = FakeRce({
            "/dev/tcp/10.0.0.1/3306": "OPEN",
            "/dev/tcp/10.0.0.1/6379": "CLOSED",
        })
        found = scan_internal(ex, ["10.0.0.0/24"],
                              ports=[3306, 6379], max_hosts=1,
                              max_port_tests=10,
                              logfile=str(tmp_path / "p.log"))
        assert any(s["port"] == 3306 and s["service"] == "mysql" for s in found)

    def test_scan_limits_hosts(self):
        from keris.modules.pivot_auto import scan_internal

        ex = FakeRce({})
        found = scan_internal(ex, ["10.0.0.0/24"], max_hosts=1,
                              max_port_tests=2)
        assert len(found) == 0  # tidak ada service terbuka


class TestDefaultCreds:
    def test_redis_rce(self):
        from keris.modules.pivot_auto import try_default_creds

        ex = FakeRce({"redis-cli": "REDIS_OK"})
        hits = try_default_creds(ex, "10.0.0.5", 6379, "redis")
        assert hits and hits[0]["ok"]
        assert hits[0]["service"] == "redis"

    def test_mysql_root_root(self):
        from keris.modules.pivot_auto import try_default_creds

        ex = FakeRce({"mysql -h 10.0.0.5 -P 3306 -u root -proot": "MYSQL_OK"})
        hits = try_default_creds(ex, "10.0.0.5", 3306, "mysql")
        assert hits and hits[0]["ok"]
        assert hits[0]["username"] == "root"

    def test_mongo_no_auth(self):
        from keris.modules.pivot_auto import try_default_creds

        ex = FakeRce({"mongo": "MONGO_OK"})
        hits = try_default_creds(ex, "10.0.0.5", 27017, "mongodb")
        assert hits and hits[0]["ok"]

    def test_no_creds_no_hits(self):
        from keris.modules.pivot_auto import try_default_creds

        ex = FakeRce({"mysql": "MYSQL_FAIL"})
        hits = try_default_creds(ex, "10.0.0.5", 3306, "mysql")
        assert hits == []


class TestOrchestrator:
    def test_requires_authorized(self, tmp_path):
        from keris.modules.pivot_auto import run_pivot_auto

        res = run_pivot_auto("http://x/", None, authorized=False)
        assert res["error"] == "unauthorized"
        assert res["findings"] == []

    def test_requires_executor(self):
        from keris.modules.pivot_auto import run_pivot_auto

        res = run_pivot_auto("http://x/", None, authorized=True)
        assert res["error"] == "no-executor"

    def test_full_flow(self, tmp_path):
        from keris.modules.pivot_auto import run_pivot_auto

        ex = FakeRce({
            "ifconfig": "eth0 inet 10.0.0.1",
            "/dev/tcp/10.0.0.1/6379": "OPEN",
            "redis-cli -h 10.0.0.1 -p 6379 INFO": "REDIS_OK",
        })
        from keris.modules.pivot_auto import RcePivotExecutor
        client = FakeClient()

        class EX(RcePivotExecutor):
            mode = "rce"

            def __init__(self):
                pass

            def run(self, cmd):
                return ex.run(cmd)

            def fetch(self, url, timeout=8):
                return 0, b""

        res = run_pivot_auto("http://x/", client,
                             rce_candidates=[("http://x/?id=1", "id")],
                             internal_scan_depth=1,
                             pivot_method="socks5",
                             executor=EX(),
                             authorized=True,
                             logfile=str(tmp_path / "p.log"))
        assert res.get("services"), res
        assert any(s["service"] == "redis" for s in res["services"])
        assert res["findings"]
        assert os.path.exists(res["log"])

    def test_socks5_needs_yes(self):
        from keris.modules.pivot_auto import setup_socks5

        assert setup_socks5("http://x/?u=1", "u", None,
                            authorized=True, yes=False) is None


class TestPivotMethods:
    def test_ssh_command(self):
        from keris.modules.pivot_auto import ssh_tunnel_command

        cmd = ssh_tunnel_command("10.0.0.5", 3306, "127.0.0.1", 13306)
        assert "ssh" in cmd and "-R 13306" in cmd

    def test_chisel_command(self):
        from keris.modules.pivot_auto import chisel_tunnel_command

        cmd = chisel_tunnel_command("10.0.0.1", 8080)
        assert "chisel" in cmd and "R:1080:socks" in cmd

    def test_set_method_ssh(self):
        from keris.modules.pivot_auto import set_pivot_method

        ex = FakeRce({})
        r = set_pivot_method(ex, "ssh", "10.0.0.5", 3306, "127.0.0.1", 13306)
        assert r["method"] == "ssh"
        assert ex.calls