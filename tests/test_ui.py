"""Tes untuk Web UI lokal (`keris serve`).

Menjalankan UI server di port ephemeral, mengirim satu scan ke target
lokal (demo handler mini), lalu memverifikasi status, temuan, dan laporan.
"""

import json
import os
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from keris.ui import UIServer, _worker, DEFAULT_HOST, DEFAULT_PORT  # noqa: E402


class _MiniHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"<html><body><h1>Demo</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def ui_server():
    jobs = {}
    lock = threading.Lock()
    server = UIServer(("127.0.0.1", 0), jobs, lock)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield server.server_address[1], jobs, lock
    server.shutdown()
    server.server_close()


def _http(port, path, method="GET", body=None):
    url = f"http://127.0.0.1:{port}{path}"
    req = urllib.request.Request(url, method=method)
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
        req.data = data
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_health(ui_server):
    port, _, _ = ui_server
    status, body = _http(port, "/api/health")
    assert status == 200
    data = json.loads(body)
    assert data["ok"] is True


def test_index_page(ui_server):
    port, _, _ = ui_server
    status, body = _http(port, "/")
    assert status == 200
    assert b"KERIS" in body
    assert b"MULAI SCAN" in body


def test_scan_job_lifecycle(ui_server):
    port, jobs, lock = ui_server

    # target demo lokal ephemeral
    demo = HTTPServer(("127.0.0.1", 0), _MiniHandler)
    dt = threading.Thread(target=demo.serve_forever, daemon=True)
    dt.start()
    demo_port = demo.server_address[1]

    try:
        # minimal scan: nonaktifkan modul berat agar cepat
        opts = {"preset": "fast", "authorized": False,
                "passive": False, "platform_checks": False,
                "cache_poisoning": False, "host_header": False,
                "websocket": False, "js_analysis": False,
                "sensitive_data": False, "hidden_endpoints": False,
                "hidden_params": False, "fuzz": False,
                "waf": False, "tls_cert": False, "buckets": False}
        status, body = _http(port, "/api/scan", "POST",
                             {"target": f"http://127.0.0.1:{demo_port}", "options": opts})
        assert status == 200
        job_id = json.loads(body)["id"]

        # tunggu sampai selesai
        deadline = time.time() + 60
        job = None
        while time.time() < deadline:
            _, body = _http(port, f"/api/jobs/{job_id}")
            job = json.loads(body)
            if job["status"] in ("done", "error", "stopped"):
                break
            time.sleep(1)
        assert job is not None
        assert job["status"] in ("done", "error")
        if job["status"] == "error":
            pytest.fail(f"scan gagal: {job.get('error')}")
        assert job["progress"] == 100.0
        assert "findings" in job
        assert isinstance(job["findings"], list)
        assert len(job["log"]) > 0

        # laporan tersedia
        for fmt in ("md", "html", "json"):
            _, body = _http(port, f"/api/jobs/{job_id}/report?fmt={fmt}")
            assert len(body) > 0
    finally:
        demo.shutdown()
        demo.server_close()


def test_duplicate_scan_rejected(ui_server):
    port, jobs, lock = ui_server
    job = None
    # simulasikan scan sedang berjalan
    import types

    from keris.ui import ScanJob

    job = ScanJob("http://127.0.0.1:1", {"preset": "fast"})
    job.status = "running"
    with lock:
        jobs["fake"] = job
    try:
        status, body = _http(port, "/api/scan", "POST",
                             {"target": "http://127.0.0.1:1", "options": {}})
        assert status == 409
        assert "berjalan" in json.loads(body)["error"]
    finally:
        with lock:
            jobs.pop("fake", None)


def test_scan_missing_target(ui_server):
    port, _, _ = ui_server
    status, body = _http(port, "/api/scan", "POST", {"target": "", "options": {}})
    assert status == 400


def test_stop_job(ui_server):
    port, jobs, lock = ui_server
    status, body = _http(port, "/api/scan", "POST",
                         {"target": "http://127.0.0.1:1", "options": {"preset": "fast"}})
    job_id = json.loads(body)["id"]
    _, body = _http(port, f"/api/jobs/{job_id}/stop", "POST")
    assert json.loads(body)["status"] in ("stopped", "running")


def test_check_rate_limit_no_crash_on_conn_error():
    """check_rate_limit tidak boleh crash saat semua request gagal koneksi."""
    from keris.core.http import KerisHTTP
    from keris.modules.scanner import check_rate_limit

    c = KerisHTTP(timeout=2)
    try:
        f = check_rate_limit(c, "http://127.0.0.1:1/nonexistent")
        assert f is None
    finally:
        c.close()


def test_dos_requires_confirmation(ui_server):
    port, _, _ = ui_server
    status, body = _http(port, "/api/dos", "POST",
                         {"target": "http://127.0.0.1:1", "confirmed": False,
                          "options": {"type": "flood", "requests": 5}})
    assert status == 400
    assert "izin" in json.loads(body)["error"]


def test_dos_job_runs(ui_server):
    port, jobs, lock = ui_server
    demo = HTTPServer(("127.0.0.1", 0), _MiniHandler)
    dt = threading.Thread(target=demo.serve_forever, daemon=True)
    dt.start()
    demo_port = demo.server_address[1]
    try:
        status, body = _http(port, "/api/dos", "POST",
                             {"target": f"http://127.0.0.1:{demo_port}", "confirmed": True,
                              "options": {"type": "flood", "requests": 8,
                                          "concurrency": 3, "duration": 1}})
        assert status == 200
        job_id = json.loads(body)["id"]
        deadline = time.time() + 90
        job = None
        while time.time() < deadline:
            _, body = _http(port, f"/api/jobs/{job_id}")
            job = json.loads(body)
            if job["status"] in ("done", "error", "stopped"):
                break
            time.sleep(1)
        assert job is not None
        assert job["status"] in ("done", "error")
        assert job["kind"] == "dos"
        assert isinstance(job["findings"], list)
        # laporan regenerated dari findings harus tersedia
        for fmt in ("md", "html", "pdf"):
            _, body = _http(port, f"/api/jobs/{job_id}/report?fmt={fmt}")
            assert len(body) > 0
    finally:
        demo.shutdown()
        demo.server_close()