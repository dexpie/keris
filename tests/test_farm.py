"""Tes v0.16.0: Distributed Scanning Cluster (farm)."""

import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _free_port():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestAuth:
    def test_token_roundtrip(self):
        from keris.farm.auth import create_token, verify_token

        t = create_token({"sub": "w1", "role": "worker"}, "secret", ttl=60)
        payload = verify_token(t, "secret")
        assert payload["sub"] == "w1"
        assert payload["role"] == "worker"

    def test_wrong_secret(self):
        from keris.farm.auth import create_token, verify_token

        t = create_token({"sub": "w1", "role": "worker"}, "secret")
        assert verify_token(t, "other") is None

    def test_expired(self):
        from keris.farm.auth import create_token, verify_token

        t = create_token({"sub": "w1", "role": "worker"}, "secret", ttl=-10)
        assert verify_token(t, "secret") is None

    def test_tampered(self):
        from keris.farm.auth import create_token, verify_token

        t = create_token({"sub": "w1", "role": "worker"}, "secret")
        bad = t[:-2] + ("A" if t[-1] != "A" else "B")
        assert verify_token(bad, "secret") is None

    def test_require_auth_role(self):
        from keris.farm.auth import create_token, require_auth

        t = create_token({"sub": "w1", "role": "worker"}, "secret")
        assert require_auth(t, "secret", role="worker") is not None
        assert require_auth(t, "secret", role="admin") is None

    def test_read_secret_env(self, monkeypatch):
        from keris.farm.auth import read_secret

        monkeypatch.setenv("KERIS_FARM_SECRET", "env-secret")
        assert read_secret() == "env-secret"

    def test_read_secret_file(self, tmp_path):
        from keris.farm.auth import read_secret

        p = str(tmp_path / "secret.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write("file-secret")
        assert read_secret(p) == "file-secret"


class TestStore:
    def test_add_claim_complete(self, tmp_path):
        from keris.farm.master import FarmStore

        st = FarmStore(str(tmp_path / "farm.db"))
        st.add_job("j1", "http://x/", "{}")
        st.upsert_worker("w1", "worker", 1)
        job = st.claim_job("w1")
        assert job and job["id"] == "j1"
        st.complete_job("j1", "w1", json.dumps({"findings": [{"severity": "HIGH"}]}))
        stats = st.stats()
        assert stats["done"] == 1
        assert stats["workers"] == 1

    def test_no_job_returns_none(self, tmp_path):
        from keris.farm.master import FarmStore

        st = FarmStore(str(tmp_path / "farm.db"))
        st.upsert_worker("w1", "worker", 1)
        assert st.claim_job("w1") is None

    def test_fail_job(self, tmp_path):
        from keris.farm.master import FarmStore

        st = FarmStore(str(tmp_path / "farm.db"))
        st.add_job("j1", "http://x/", "{}")
        st.upsert_worker("w1", "worker", 1)
        st.claim_job("w1")
        st.fail_job("j1", "w1", "error")
        assert st.stats()["failed"] == 1

    def test_reassign_stale(self, tmp_path):
        from keris.farm.master import FarmStore

        st = FarmStore(str(tmp_path / "farm.db"))
        st.add_job("j1", "http://x/", "{}")
        st.upsert_worker("w1", "worker", 1)
        st.claim_job("w1")
        # ubah assigned_at jadi lama supaya dianggap stale
        st._conn.execute("UPDATE jobs SET assigned_at=? WHERE id='j1'",
                         (time.time() - 120,))
        st._conn.commit()
        st.upsert_worker("w2", "worker2", 1)
        job = st.claim_job("w2")
        assert job and job["id"] == "j1"


class TestMasterAPI:
    def _start_master(self, tmp_path):
        from keris.farm.master import MasterServer

        port = _free_port()
        srv = MasterServer(host="127.0.0.1", port=port,
                           db_path=str(tmp_path / "farm.db"),
                           report_dir=str(tmp_path / "reports"),
                           secret="test-secret")
        srv.start()
        return srv, port

    def test_register_and_claim(self, tmp_path):
        import requests

        srv, port = self._start_master(tmp_path)
        try:
            url = f"http://127.0.0.1:{port}"
            r = requests.post(f"{url}/api/register",
                              json={"name": "w1", "capacity": 2}, timeout=5)
            assert r.status_code == 200
            data = r.json()
            assert "token" in data and "worker_id" in data
            headers = {"Authorization": f"Bearer {data['token']}"}
            # submit job
            r = requests.post(f"{url}/api/jobs", headers=headers,
                              json={"targets": ["http://a/", "http://b/"]},
                              timeout=5)
            assert r.status_code == 200
            assert len(r.json()["job_ids"]) == 2
            # claim
            r = requests.post(f"{url}/api/claim", headers=headers, json={},
                              timeout=5)
            job = r.json()["job"]
            assert job and job["target"] == "http://a/"
            # complete
            r = requests.post(f"{url}/api/jobs/{job['id']}/result",
                              headers=headers,
                              json={"result": {"findings": [{"severity": "HIGH",
                                                             "title": "x"}]}},
                              timeout=5)
            assert r.status_code == 200
            # status
            st = requests.get(f"{url}/api/status", timeout=5).json()
            assert st["done"] == 1 and st["pending"] == 1
            # report
            rep = requests.get(f"{url}/api/report", timeout=5)
            assert rep.status_code == 200 and "Farm Unified Report" in rep.text
        finally:
            srv.stop()

    def test_unauthorized_rejected(self, tmp_path):
        import requests

        srv, port = self._start_master(tmp_path)
        try:
            url = f"http://127.0.0.1:{port}"
            r = requests.post(f"{url}/api/jobs",
                              json={"targets": ["http://a/"]}, timeout=5)
            assert r.status_code == 401
        finally:
            srv.stop()

    def test_claim_without_token_rejected(self, tmp_path):
        import requests

        srv, port = self._start_master(tmp_path)
        try:
            url = f"http://127.0.0.1:{port}"
            r = requests.post(f"{url}/api/claim", json={}, timeout=5)
            assert r.status_code == 401
        finally:
            srv.stop()


class TestWorker:
    def test_worker_flow(self, tmp_path):
        from keris.farm.master import MasterServer
        from keris.farm.worker import WorkerLoop

        port = _free_port()
        srv = MasterServer(host="127.0.0.1", port=port,
                           db_path=str(tmp_path / "farm.db"),
                           report_dir=str(tmp_path / "reports"),
                           secret="test-secret")
        srv.start()
        try:
            url = f"http://127.0.0.1:{port}"
            import requests

            r = requests.post(f"{url}/api/register",
                              json={"name": "w1", "capacity": 1}, timeout=5)
            token = r.json()["token"]
            headers = {"Authorization": f"Bearer {token}"}
            requests.post(f"{url}/api/jobs", headers=headers,
                          json={"targets": ["http://test/"]}, timeout=5)

            def fake_scan(target, config):
                return {"ok": True, "findings": [
                    {"severity": "HIGH", "title": "sql",
                     "endpoint": target}], "risk_score": {"score": 42}}

            w = WorkerLoop(url, name="w1", capacity=1, poll_interval=0.1,
                           runner=fake_scan)
            w.token = token
            w.worker_id = r.json()["worker_id"]
            done = w.run_forever(iterations=1)
            assert done == 1
            jobs = requests.get(f"{url}/api/jobs", headers=headers,
                                timeout=5).json()["jobs"]
            assert jobs[0]["status"] == "done"
        finally:
            srv.stop()

    def test_worker_fail_reports(self, tmp_path):
        from keris.farm.master import MasterServer
        from keris.farm.worker import WorkerLoop

        port = _free_port()
        srv = MasterServer(host="127.0.0.1", port=port,
                           db_path=str(tmp_path / "farm.db"),
                           report_dir=str(tmp_path / "reports"),
                           secret="test-secret")
        srv.start()
        try:
            url = f"http://127.0.0.1:{port}"
            import requests

            r = requests.post(f"{url}/api/register",
                              json={"name": "w1", "capacity": 1}, timeout=5)
            token = r.json()["token"]
            headers = {"Authorization": f"Bearer {token}"}
            requests.post(f"{url}/api/jobs", headers=headers,
                          json={"targets": ["http://test/"]}, timeout=5)

            def failing_scan(target, config):
                return {"ok": False, "error": "boom"}

            w = WorkerLoop(url, name="w1", capacity=1, poll_interval=0.1,
                           runner=failing_scan)
            w.token = token
            w.worker_id = r.json()["worker_id"]
            w.run_forever(iterations=1)
            jobs = requests.get(f"{url}/api/jobs", headers=headers,
                                timeout=5).json()["jobs"]
            assert jobs[0]["status"] == "failed"
        finally:
            srv.stop()


class TestClient:
    def test_read_targets(self, tmp_path):
        from keris.farm.client import read_targets

        p = str(tmp_path / "t.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write("# comment\nhttp://a/\nhttp://b/\n\n")
        assert read_targets(p) == ["http://a/", "http://b/"]

    def test_read_targets_missing(self):
        from keris.farm.client import read_targets

        try:
            read_targets("none.txt")
            assert False
        except FileNotFoundError:
            pass

    def test_read_config(self, tmp_path):
        from keris.farm.client import read_config

        p = str(tmp_path / "c.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"quiet": True}, f)
        assert read_config(p) == {"quiet": True}

    def test_status_via_client(self, tmp_path):
        from keris.farm.client import FarmClient
        from keris.farm.master import MasterServer

        port = _free_port()
        srv = MasterServer(host="127.0.0.1", port=port,
                           db_path=str(tmp_path / "farm.db"),
                           report_dir=str(tmp_path / "reports"),
                           secret="test-secret")
        srv.start()
        try:
            st = FarmClient(f"http://127.0.0.1:{port}").status()
            assert "jobs" in st and "workers" in st
        finally:
            srv.stop()