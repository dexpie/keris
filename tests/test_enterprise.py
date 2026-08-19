"""Tes v0.17.0: Enterprise Suite (keris-enterprise)."""

import json
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import requests


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestAuth:
    def test_hash_verify(self):
        from keris_enterprise.auth import hash_password, verify_password

        h = hash_password("rahasia")
        assert h.startswith("pbkdf2$")
        assert verify_password("rahasia", h)
        assert not verify_password("salah", h)
        assert not verify_password("rahasia", "garbage")

    def test_role_levels(self):
        from keris_enterprise.auth import Role

        assert Role.LEVEL[Role.VIEWER] == 1
        assert Role.LEVEL[Role.PENTESTER] == 2
        assert Role.LEVEL[Role.ADMIN] == 3

    def test_user_crud(self, tmp_path):
        from keris_enterprise.auth import Role, UserStore
        from keris_enterprise.db import EnterpriseDB

        db = EnterpriseDB(str(tmp_path / "ent.db"))
        store = UserStore(db, secret="unit-test-secret")
        u = store.create_user("budi", "pass1", role="pentester", email="b@x.id")
        assert u["role"] == "pentester"
        assert store.authenticate("budi", "pass1")["username"] == "budi"
        assert store.authenticate("budi", "nope") is None
        store.update_role("budi", Role.ADMIN)
        assert store.list_users()[0]["role"] == Role.ADMIN
        store.delete_user("budi")
        assert store.list_users() == []
        db.close()

    def test_token_flow(self, tmp_path):
        from keris_enterprise.auth import Role, UserStore
        from keris_enterprise.db import EnterpriseDB

        db = EnterpriseDB(str(tmp_path / "ent.db"))
        store = UserStore(db, secret="unit-test-secret")
        store.create_user("view", "pass1", role=Role.VIEWER)
        store.create_user("admin", "pass2", role=Role.ADMIN)
        tok_v = store.issue_token({"username": "view", "role": Role.VIEWER})
        tok_a = store.issue_token({"username": "admin", "role": Role.ADMIN})
        assert store.require(tok_a, min_level=Role.LEVEL[Role.PENTESTER]) is not None
        assert store.require(tok_v, min_level=Role.LEVEL[Role.PENTESTER]) is None
        assert store.verify_token(tok_v + "x") is None
        db.close()


class TestProjects:
    def test_project_crud_and_results(self, tmp_path):
        from keris_enterprise.db import EnterpriseDB
        from keris_enterprise.projects import ProjectStore

        db = EnterpriseDB(str(tmp_path / "ent.db"))
        store = ProjectStore(db)
        p = store.create_project("Proyek A", "Klien X",
                                 ["https://a.example", "https://b.example"],
                                 schedule="daily")
        assert p["targets"] == ["https://a.example", "https://b.example"]
        assert p["schedule"] == "daily"
        store.save_result(p["id"], "https://a.example",
                          {"findings": [{"title": "XSS", "severity": "HIGH"}]})
        results = store.project_results(p["id"])
        assert len(results) == 1
        assert results[0]["result"]["findings"][0]["title"] == "XSS"
        store.update_project(p["id"], schedule="*/5m")
        assert store.get_project(p["id"])["schedule"] == "*/5m"
        store.delete_project(p["id"])
        assert store.get_project(p["id"]) is None
        db.close()

    def test_remediation_tracking(self, tmp_path):
        from keris_enterprise.db import EnterpriseDB
        from keris_enterprise.projects import ProjectStore

        db = EnterpriseDB(str(tmp_path / "ent.db"))
        store = ProjectStore(db)
        p = store.create_project("Proyek B", schedule="weekly")
        store.upsert_remediation(p["id"], "fp-1", "SQLi di login", "open")
        store.upsert_remediation(p["id"], "fp-1", "SQLi di login", "fixed")
        store.upsert_remediation(p["id"], "fp-2", "XSS profil", "open")
        rems = store.list_remediations(p["id"])
        assert len(rems) == 2
        assert sum(1 for r in rems if r["status"] == "fixed") == 1
        fixed = store.list_remediations(p["id"], status="fixed")
        assert len(fixed) == 1 and fixed[0]["finding_key"] == "fp-1"
        db.close()


class TestScheduler:
    def test_parse_schedule(self):
        from keris_enterprise.scheduler import parse_schedule

        assert parse_schedule("hourly") == 3600.0
        assert parse_schedule("daily") == 86400.0
        assert parse_schedule("weekly") == 604800.0
        assert parse_schedule("*/30m") == 1800.0
        assert parse_schedule("0 2 * * *") is None
        assert parse_schedule("") is None

    def test_tick_runs_due_projects(self, tmp_path):
        from keris_enterprise.db import EnterpriseDB
        from keris_enterprise.projects import ProjectStore
        from keris_enterprise.scheduler import Scheduler

        db = EnterpriseDB(str(tmp_path / "ent.db"))
        store = ProjectStore(db)
        store.create_project("Proyek C", targets=["https://c.example"],
                             schedule="*/1m")
        ran = []

        def runner(proj, target):
            ran.append(target)
            return {"findings": [{"title": "T", "severity": "LOW"}]}

        sched = Scheduler(store, runner=runner)
        results = sched.tick()
        assert len(results) == 1
        assert results[0]["findings"] == 1
        # Kedua tick berikutnya tidak boleh rerun karena interval belum lewat
        assert sched.tick() == []
        assert ran == ["https://c.example"]
        db.close()

    def test_tick_skips_no_schedule(self, tmp_path):
        from keris_enterprise.db import EnterpriseDB
        from keris_enterprise.projects import ProjectStore
        from keris_enterprise.scheduler import Scheduler

        db = EnterpriseDB(str(tmp_path / "ent.db"))
        store = ProjectStore(db)
        store.create_project("Tanpa Jadwal", targets=["https://x.example"])
        sched = Scheduler(store, runner=lambda proj, target: {"findings": []})
        assert sched.tick() == []
        db.close()


class TestAlerts:
    def test_escalation_level(self):
        from keris_enterprise.alerts import AlertManager

        mgr = AlertManager({"escalate_after_repeats": 2})
        f_crit = [{"severity": "CRITICAL", "title": "RCE"}]
        f_low = [{"severity": "LOW", "title": "Info"}]
        assert mgr.escalation_level("p1", f_low) == 1
        mgr.register_repeat("p1")
        mgr.register_repeat("p1")
        assert mgr.escalation_level("p1", f_crit) == 2
        mgr.register_repeat("p1")
        mgr.register_repeat("p1")
        assert mgr.escalation_level("p1", f_crit) == 3

    def test_slack_webhook(self, monkeypatch):
        from keris_enterprise import alerts as A

        calls = {}

        def fake_post(url, **kwargs):
            calls["url"] = url
            calls["payload"] = kwargs.get("json")
            return type("R", (), {"status_code": 200})()

        monkeypatch.setattr(A.requests, "post", fake_post)
        mgr = A.AlertManager({"slack": {"webhook": "https://hooks.slack/x"}})
        ok_list = mgr.send("p1", "Proyek", "https://a.example",
                           [{"severity": "HIGH", "title": "SQLi",
                             "endpoint": "/login"}])
        assert ok_list == [True]
        assert calls["url"] == "https://hooks.slack/x"
        assert "SQLi" in calls["payload"]["text"]

    def test_email_smtp_fail_safe(self):
        from keris_enterprise.alerts import AlertManager

        mgr = AlertManager({"email": {"smtp_host": "127.0.0.1", "smtp_port": 1,
                                      "username": "", "password": "",
                                      "to": ["a@x.id"], "use_tls": False}})
        res = mgr.send("p1", "Proyek", "https://a.example", [])
        assert res and res[0] is False


class TestIntegrations:
    def test_forward_logs(self, monkeypatch):
        from keris_enterprise import integrations as I

        calls = {}

        def fake_post(url, **kwargs):
            calls["url"] = url
            calls["headers"] = kwargs.get("headers")
            calls["payload"] = kwargs.get("json")
            return type("R", (), {"status_code": 200})()

        monkeypatch.setattr(I.requests, "post", fake_post)
        assert I.forward_logs("https://splunk/services/collector", "tok",
                              "idx", "keris", [{"title": "T"}]) is True
        assert "Splunk tok" in calls["headers"]["Authorization"]
        assert calls["payload"]["index"] == "idx"

    def test_github_ticket(self, monkeypatch):
        from keris_enterprise import integrations as I

        calls = {}

        def fake_post(url, **kwargs):
            calls["url"] = url
            calls["headers"] = kwargs.get("headers")
            calls["payload"] = kwargs.get("json")
            return type("R", (), {"status_code": 201})()

        monkeypatch.setattr(I.requests, "post", fake_post)
        ok = I.github_ticket("org/repo", "tok", "Judul", "Isi")
        assert ok is True
        assert calls["url"] == "https://api.github.com/repos/org/repo/issues"
        assert calls["payload"]["title"] == "Judul"


class TestApi:
    def _make_server(self, tmp_path):
        from contextlib import contextmanager

        from keris_enterprise import EnterpriseServer

        @contextmanager
        def manager():
            srv = EnterpriseServer(host="127.0.0.1", port=0,
                                   db_path=str(tmp_path / "ent.db"),
                                   secret="unit-test-secret",
                                   scan_runner=lambda proj, target: {
                                       "findings": [
                                           {"title": "XSS",
                                            "severity": "HIGH",
                                            "endpoint": "/search",
                                            "fingerprint": "fp-xss"}]})
            srv.users.create_user("admin", "admin123", role="admin")
            srv.users.create_user("view", "view123", role="viewer")
            srv.start()
            try:
                yield srv
            finally:
                srv.stop()

        return manager

    def test_login_and_authz(self, tmp_path):
        with self._make_server(tmp_path)() as srv:
            url = f"http://127.0.0.1:{srv.port}"
            r = requests.post(url + "/api/login",
                              json={"username": "admin", "password": "admin123"})
            assert r.status_code == 200
            token = r.json()["token"]
            r2 = requests.get(url + "/api/projects",
                              headers={"Authorization": f"Bearer {token}"})
            assert r2.status_code == 200
            r3 = requests.get(url + "/api/projects")
            assert r3.status_code == 401

    def test_rbac_viewer_cannot_create_user(self, tmp_path):
        with self._make_server(tmp_path)() as srv:
            url = f"http://127.0.0.1:{srv.port}"
            tok = requests.post(url + "/api/login",
                                json={"username": "view",
                                      "password": "view123"}).json()["token"]
            r = requests.post(url + "/api/users",
                              headers={"Authorization": f"Bearer {tok}"},
                              json={"username": "evil", "password": "x",
                                    "role": "admin"})
            assert r.status_code == 403

    def test_project_and_scan_flow(self, tmp_path):
        with self._make_server(tmp_path)() as srv:
            url = f"http://127.0.0.1:{srv.port}"
            token = requests.post(url + "/api/login",
                                  json={"username": "admin",
                                        "password": "admin123"}).json()["token"]
            h = {"Authorization": f"Bearer {token}"}
            p = requests.post(url + "/api/projects",
                              headers=h,
                              json={"name": "Proyek API", "client": "Klien",
                                    "targets": ["https://api.example"],
                                    "schedule": "daily"}).json()
            pid = p["id"]
            res = requests.post(url + f"/api/projects/{pid}/scan",
                                headers=h, json={"target": "https://api.example"})
            assert res.status_code == 200
            body = res.json()
            assert body["findings"] == 1
            results = requests.get(url + f"/api/projects/{pid}/results",
                                   headers=h).json()["results"]
            assert len(results) == 1
            rems = requests.get(url + f"/api/projects/{pid}/remediations",
                                headers=h).json()["remediations"]
            assert any(r["finding_key"] == "fp-xss" for r in rems)
            dash = requests.get(url + "/api/dashboard", headers=h).json()
            assert dash["projects"] == 1
            assert dash["total_findings"] == 1

    def test_scheduler_http_control(self, tmp_path):
        with self._make_server(tmp_path)() as srv:
            url = f"http://127.0.0.1:{srv.port}"
            token = requests.post(url + "/api/login",
                                  json={"username": "admin",
                                        "password": "admin123"}).json()["token"]
            h = {"Authorization": f"Bearer {token}"}
            r = requests.post(url + "/api/scheduler/start", headers=h)
            assert r.status_code == 200 and r.json()["ok"] is True
            r = requests.post(url + "/api/scheduler/stop", headers=h)
            assert r.status_code == 200 and r.json()["ok"] is True


class TestWebUi:
    def test_dashboard_html(self):
        from keris_enterprise import webui

        data = {"projects": 2, "recent_results": 5, "total_findings": 9,
                "remediations_open": 3, "remediations_total": 4,
                "trend": [{"target": "x", "score": 60, "grade": "C"}]}
        html = webui.render_dashboard(data)
        assert "<title>keris-enterprise Dashboard</title>" in html
        assert "9" in html

    def test_attack_paths_section(self):
        from keris_enterprise import webui

        results = [{"target": "x.example", "result": {"attack_paths": [
            {"severity": "HIGH", "impact": "RCE", "score": 8.5,
             "steps": [{"severity": "HIGH", "title": "SQLi",
                        "endpoint": "/login"}]}]}}]
        section = webui.attack_paths_section(results)
        assert "Attack Path" in section
        assert "SQLi" in section
        assert "Tidak ada attack path." in webui.attack_paths_section([])