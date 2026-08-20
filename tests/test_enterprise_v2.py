"""Tests v0.27.0: Enterprise microservices — orgs/tenants, RBAC matrix,
scan CRUD API, worker/scheduler queue, docker-compose."""

import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
import requests

from keris_enterprise.db import EnterpriseDB


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------------------
# RBAC matrix
# ---------------------------------------------------------------------------

class TestRbacMatrix:
    def test_has_permission_roles(self):
        from keris_enterprise.orgs import (ALL_PERMISSIONS, P_MANAGE_USERS,
                                           P_SCAN, P_VIEW_RESULTS, has_permission)
        from keris_enterprise.auth import Role

        assert has_permission(Role.ADMIN, P_MANAGE_USERS)
        assert has_permission(Role.PENTESTER, P_SCAN)
        assert not has_permission(Role.PENTESTER, P_MANAGE_USERS)
        assert has_permission(Role.VIEWER, P_VIEW_RESULTS)
        assert not has_permission(Role.VIEWER, P_SCAN)
        assert not has_permission("nonexistent", P_SCAN)
        assert P_SCAN in ALL_PERMISSIONS

    def test_rbac_matrix_shape(self):
        from keris_enterprise.orgs import rbac_matrix
        from keris_enterprise.auth import Role

        m = rbac_matrix()
        assert set(m) == set(Role.ALL)
        assert m[Role.ADMIN]["manage_users"] is True
        assert m[Role.VIEWER]["scan"] is False


# ---------------------------------------------------------------------------
# OrgStore / multi-tenant
# ---------------------------------------------------------------------------

class TestOrgs:
    def test_org_crud_and_members(self, tmp_path):
        from keris_enterprise.orgs import OrgStore

        db = EnterpriseDB(str(tmp_path / "orgs.db"))
        store = OrgStore(db)
        o = store.create_org("PT Maju")
        assert o["id"].startswith("o-")
        assert store.get_org(o["id"])["name"] == "PT Maju"
        assert store.add_member(o["id"], "budi", "pentester")
        assert store.add_member(o["id"], "budi", "bogus") is False
        assert store.member_role(o["id"], "budi") == "pentester"
        members = store.list_members(o["id"])
        assert len(members) == 1
        store.remove_member(o["id"], "budi")
        assert store.list_members(o["id"]) == []
        store.delete_org(o["id"])
        assert store.get_org(o["id"]) is None
        db.close()

    def test_scoped_query(self):
        from keris_enterprise.orgs import scoped

        sql, params = scoped("o-1", "SELECT * FROM projects", ())
        assert "WHERE org_id=?" in sql
        assert params == ("o-1",)
        sql2, params2 = scoped("", "SELECT * FROM projects", ())
        assert "WHERE" not in sql2
        assert params2 == ()

    def test_org_isolates_projects(self, tmp_path):
        from keris_enterprise.orgs import OrgStore
        from keris_enterprise.projects import ProjectStore

        db = EnterpriseDB(str(tmp_path / "iso.db"))
        OrgStore(db)  # migrasi kolom org_id
        projects = ProjectStore(db)
        projects.create_project("A", org_id="o-1")
        projects.create_project("B", org_id="o-2")
        assert len(projects.list_projects(org_id="o-1")) == 1
        assert len(projects.list_projects()) == 2
        db.close()


# ---------------------------------------------------------------------------
# ScanWorker / queue
# ---------------------------------------------------------------------------

class TestWorker:
    def test_enqueue_and_queue_length(self, tmp_path):
        from keris_enterprise.orgs import OrgStore
        from keris_enterprise.projects import ProjectStore
        from keris_enterprise.worker import ScanWorker

        db = EnterpriseDB(str(tmp_path / "w.db"))
        OrgStore(db)
        projects = ProjectStore(db)
        p = projects.create_project("P", targets=["https://x.example"])
        w = ScanWorker(projects, runner=lambda proj, target: {"findings": []})
        meta = w.enqueue(p["id"], "https://x.example")
        assert meta["status"] == "queued"
        assert w.queue_length() == 1
        db.close()

    def test_worker_processes_queue(self, tmp_path):
        from keris_enterprise.orgs import OrgStore
        from keris_enterprise.projects import ProjectStore
        from keris_enterprise.worker import ScanWorker

        db = EnterpriseDB(str(tmp_path / "w2.db"))
        OrgStore(db)
        projects = ProjectStore(db)
        p = projects.create_project("P", targets=["https://x.example"])
        seen = []

        def runner(proj, target):
            seen.append(target)
            return {"findings": [{"title": "XSS", "severity": "HIGH"}]}

        w = ScanWorker(projects, runner=runner)
        w.enqueue(p["id"], "https://x.example")
        w.start()
        deadline = time.time() + 5
        while time.time() < deadline and w.queue_length():
            time.sleep(0.1)
        w.stop()
        results = projects.project_results(p["id"])
        assert seen == ["https://x.example"]
        assert results[0]["status"] == "done"
        assert w.stats["processed"] == 1
        db.close()


# ---------------------------------------------------------------------------
# API: orgs, rbac, CRUD results, worker
# ---------------------------------------------------------------------------

def _make_server(tmp_path, scan_runner=None):
    from contextlib import contextmanager

    from keris_enterprise import EnterpriseServer

    @contextmanager
    def manager():
        srv = EnterpriseServer(host="127.0.0.1", port=0,
                               db_path=str(tmp_path / "ent.db"),
                               secret="unit-test-secret",
                               scan_runner=scan_runner or (
                                   lambda proj, target: {
                                       "findings": [
                                           {"title": "XSS", "severity": "HIGH",
                                            "endpoint": "/search",
                                            "fingerprint": "fp-xss"}]}))
        srv.users.create_user("admin", "admin123", role="admin")
        srv.start()
        try:
            yield srv
        finally:
            srv.stop()

    return manager


class TestApiV2:
    def test_rbac_endpoint(self, tmp_path):
        with _make_server(tmp_path)() as srv:
            url = f"http://127.0.0.1:{srv.port}"
            tok = requests.post(url + "/api/login",
                                json={"username": "admin",
                                      "password": "admin123"}).json()["token"]
            h = {"Authorization": f"Bearer {tok}"}
            r = requests.get(url + "/api/rbac", headers=h)
            assert r.status_code == 200
            assert r.json()["matrix"]["admin"]["manage_users"] is True
            # tanpa token -> 401
            assert requests.get(url + "/api/rbac").status_code == 401

    def test_orgs_crud_endpoint(self, tmp_path):
        with _make_server(tmp_path)() as srv:
            url = f"http://127.0.0.1:{srv.port}"
            tok = requests.post(url + "/api/login",
                                json={"username": "admin",
                                      "password": "admin123"}).json()["token"]
            h = {"Authorization": f"Bearer {tok}"}
            r = requests.post(url + "/api/orgs", headers=h,
                              json={"name": "PT Bahari"})
            assert r.status_code == 201
            oid = r.json()["id"]
            r2 = requests.get(url + "/api/orgs", headers=h)
            assert any(o["id"] == oid for o in r2.json()["orgs"])
            r3 = requests.post(url + f"/api/orgs/{oid}/members", headers=h,
                               json={"username": "siti", "role": "pentester"})
            assert r3.json()["ok"] is True
            r4 = requests.get(url + f"/api/orgs/{oid}/members", headers=h)
            assert any(m["username"] == "siti" for m in r4.json()["members"])

    def test_project_org_id_endpoint(self, tmp_path):
        with _make_server(tmp_path)() as srv:
            url = f"http://127.0.0.1:{srv.port}"
            tok = requests.post(url + "/api/login",
                                json={"username": "admin",
                                      "password": "admin123"}).json()["token"]
            h = {"Authorization": f"Bearer {tok}"}
            p = requests.post(url + "/api/projects", headers=h,
                              json={"name": "P-Org", "org_id": "o-1",
                                    "targets": ["https://p.example"]}).json()
            assert p["org_id"] == "o-1"

    def test_result_crud(self, tmp_path):
        with _make_server(tmp_path)() as srv:
            url = f"http://127.0.0.1:{srv.port}"
            tok = requests.post(url + "/api/login",
                                json={"username": "admin",
                                      "password": "admin123"}).json()["token"]
            h = {"Authorization": f"Bearer {tok}"}
            p = requests.post(url + "/api/projects", headers=h,
                              json={"name": "P-CRUD",
                                    "targets": ["https://c.example"]}).json()
            pid = p["id"]
            res = requests.post(url + f"/api/projects/{pid}/scan",
                                headers=h,
                                json={"target": "https://c.example"}).json()
            rid = res["id"]
            r = requests.delete(url + f"/api/results/{rid}", headers=h)
            assert r.json()["ok"] is True
            remaining = requests.get(url + f"/api/projects/{pid}/results",
                                     headers=h).json()["results"]
            assert remaining == []

    def test_patch_project(self, tmp_path):
        with _make_server(tmp_path)() as srv:
            url = f"http://127.0.0.1:{srv.port}"
            tok = requests.post(url + "/api/login",
                                json={"username": "admin",
                                      "password": "admin123"}).json()["token"]
            h = {"Authorization": f"Bearer {tok}"}
            p = requests.post(url + "/api/projects", headers=h,
                              json={"name": "P", "targets": ["https://p.x"]}).json()
            r = requests.patch(url + f"/api/projects/{p['id']}", headers=h,
                               json={"schedule": "hourly"})
            assert r.json()["ok"] is True
            got = requests.get(url + "/api/projects", headers=h).json()["projects"]
            proj = next(x for x in got if x["id"] == p["id"])
            assert proj["schedule"] == "hourly"

    def test_scan_queue_and_worker_status(self, tmp_path):
        with _make_server(tmp_path)() as srv:
            url = f"http://127.0.0.1:{srv.port}"
            tok = requests.post(url + "/api/login",
                                json={"username": "admin",
                                      "password": "admin123"}).json()["token"]
            h = {"Authorization": f"Bearer {tok}"}
            p = requests.post(url + "/api/projects", headers=h,
                              json={"name": "P-Q",
                                    "targets": ["https://q.example"]}).json()
            pid = p["id"]
            # scan diantrekan (async)
            r = requests.post(url + f"/api/projects/{pid}/scan/queue",
                              headers=h,
                              json={"target": "https://q.example"})
            assert r.json()["queued"] is True
            st = requests.get(url + "/api/worker/status", headers=h)
            assert st.json()["queue"] == 1
            # jalankan worker, tunggu antrean kosong
            requests.post(url + "/api/worker/start", headers=h)
            deadline = time.time() + 10
            final = None
            while time.time() < deadline:
                final = requests.get(url + "/api/worker/status", headers=h).json()
                if final["queue"] == 0 and final["stats"].get("processed", 0) >= 1:
                    break
                time.sleep(0.1)
            requests.post(url + "/api/worker/stop", headers=h)
            assert final is not None
            assert final["queue"] == 0
            assert final["stats"]["processed"] >= 1
            results = requests.get(url + f"/api/projects/{pid}/results",
                                   headers=h).json()["results"]
            assert results and results[0]["status"] == "done"


# ---------------------------------------------------------------------------
# docker-compose & entrypoint CLI
# ---------------------------------------------------------------------------

class TestDeployment:
    def test_docker_compose_has_services(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "docker-compose.yml"), encoding="utf-8") as f:
            content = f.read()
        for svc in ("enterprise-api", "enterprise-worker",
                    "enterprise-scheduler", "keris"):
            assert f"  {svc}:" in content
        assert "keris_data" in content

    def test_enterprise_main_has_worker_cmd(self):
        from keris_enterprise import __main__ as m

        assert m._worker and m._scheduler

    def test_status_includes_queue(self, tmp_path, capsys):
        from keris_enterprise import __main__ as m

        class A:
            db = str(tmp_path / "s.db")
            json = True

        m._status(A())
        out = capsys.readouterr().out
        assert '"queue"' in out