"""REST API keris-enterprise: auth, orgs, RBAC, projects, scans, scheduler,
worker, alerts.

Server HTTP (stdlib) dengan endpoint:
- POST /api/login                  -> token
- GET  /api/users, POST /api/users, PATCH /api/users/<u>/role
- GET  /api/rbac                   -> matriks izin per role
- GET/POST /api/orgs, GET/PATCH/DELETE /api/orgs/<id>
- POST /api/orgs/<id>/members
- GET/POST /api/projects, GET/PATCH/DELETE /api/projects/<id>
- POST /api/projects/<id>/scan     -> jalankan scan sekali (sync)
- POST /api/projects/<id>/scan/queue -> antrekan scan (async, worker)
- GET  /api/projects/<id>/results, GET/DELETE /api/results/<rid>
- GET  /api/projects/<id>/remediations, POST .../remediations
- GET  /api/dashboard              -> ringkasan untuk web UI
- POST /api/scheduler/start|stop
- POST /api/worker/start|stop, GET /api/worker/status
"""

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional

from keris.core.logger import info, ok, warn
from keris_enterprise.alerts import AlertManager
from keris_enterprise.auth import Role, UserStore
from keris_enterprise.db import EnterpriseDB
from keris_enterprise.orgs import OrgStore, rbac_matrix
from keris_enterprise.projects import ProjectStore
from keris_enterprise.scheduler import Scheduler
from keris_enterprise.worker import ScanWorker


class EnterpriseServer:
    """Orkestrator REST API + scheduler + worker + alert."""

    def __init__(self, host: str = "0.0.0.0", port: int = 9000,
                 db_path: str = "", secret: str = "",
                 authorized: bool = False, runner=None, scan_runner=None,
                 worker_concurrency: int = 1):
        self.host = host
        self.port = port
        self.db = EnterpriseDB(db_path)
        self.users = UserStore(self.db, secret=secret)
        self.projects = ProjectStore(self.db)
        self.orgs = OrgStore(self.db)
        self.alerts = AlertManager()
        self.scheduler = Scheduler(self.projects, runner=runner,
                                   authorized=authorized)
        self.worker = ScanWorker(self.projects, runner=runner,
                                 authorized=authorized,
                                 concurrency=worker_concurrency)
        self._scan_runner = scan_runner  # testing hook untuk scan manual
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._shutdown = threading.Event()

    # --- helpers ---
    def _auth_user(self, token: str, min_level: int = 1) -> Optional[Dict]:
        return self.users.require(token, min_level)

    def _effective_org(self, user: Dict) -> str:
        """org user: token tidak membawa org_id, jadi cek membership org admin.
        Untuk user tanpa keanggotaan org spesifik, kembali ke global ("")."""
        try:
            uid = user.get("sub", "")
            rows = self.db.query(
                "SELECT org_id FROM org_users WHERE username=?", (uid,))
            return rows[0]["org_id"] if rows else ""
        except Exception:
            return ""

    def run_scan(self, project_id: str, target: str) -> Dict:
        proj = self.projects.get_project(project_id)
        if not proj:
            return {"error": "project tidak ditemukan"}
        if self._scan_runner is not None:
            result = self._scan_runner(proj, target)
        else:
            result = self.scheduler._subprocess_scan(target)
        saved = self.projects.save_result(project_id, target, result)
        findings = result.get("findings", []) if isinstance(result, dict) else []
        # sync remediasi otomatis dari temuan
        for f in findings:
            key = f.get("fingerprint") or f.get("title", "")
            if key:
                self.projects.upsert_remediation(project_id, key,
                                                 f.get("title", ""),
                                                 status="open")
        return {"project_id": project_id, "target": target,
                "findings": len(findings), "result": result, "id": saved["id"]}

    def dashboard(self) -> Dict:
        projects = self.projects.list_projects()
        results = self.projects.recent_results(limit=50)
        total_findings = sum(len(r["result"].get("findings", [])) for r in results)
        rem = []
        for p in projects:
            rem.extend(self.projects.list_remediations(p["id"]))
        open_rem = sum(1 for r in rem if r["status"] == "open")
        # risk trend: skor risk per hasil
        trend = []
        for r in reversed(results):
            rs = r["result"].get("risk_score", {})
            trend.append({"target": r["target"], "score": rs.get("score", 0),
                          "grade": rs.get("grade", "-"),
                          "time": r["created_at"]})
        return {
            "projects": len(projects),
            "recent_results": len(results),
            "total_findings": total_findings,
            "remediations_open": open_rem,
            "remediations_total": len(rem),
            "trend": trend,
        }

    def _handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def _send(self, data, code: int = 200, ctype: str = "application/json"):
                body = data if isinstance(data, bytes) else json.dumps(data).encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self) -> Dict:
                ln = int(self.headers.get("Content-Length") or 0)
                if not ln:
                    return {}
                try:
                    return json.loads(self.rfile.read(ln))
                except json.JSONDecodeError:
                    return {}

            def _token(self) -> str:
                auth = self.headers.get("Authorization", "")
                if auth.lower().startswith("bearer "):
                    return auth[7:].strip()
                return ""

            def do_POST(self):
                path = self.path.split("?")[0]
                body = self._body()
                if path == "/api/login":
                    u = server.users.authenticate(str(body.get("username", "")),
                                                  str(body.get("password", "")))
                    if not u:
                        self._send({"error": "invalid credentials"}, 401)
                        return
                    self._send({"token": server.users.issue_token(u),
                                "user": u})
                    return
                if path == "/api/users":
                    payload = server.users.verify_token(self._token())
                    if not payload:
                        self._send({"error": "unauthorized"}, 401)
                        return
                    if payload.get("role") != Role.ADMIN:
                        self._send({"error": "forbidden"}, 403)
                        return
                    u = server.users.create_user(
                        str(body.get("username", "")),
                        str(body.get("password", "")),
                        str(body.get("role", Role.VIEWER)),
                        str(body.get("email", "")))
                    self._send(u, 201)
                    return
                if path == "/api/orgs":
                    payload = server.users.verify_token(self._token())
                    if not payload or payload.get("role") != Role.ADMIN:
                        self._send({"error": "forbidden"}, 403)
                        return
                    o = server.orgs.create_org(str(body.get("name", "")))
                    self._send(o, 201)
                    return
                if path.startswith("/api/orgs/") and path.endswith("/members"):
                    oid = path[len("/api/orgs/"):-len("/members")]
                    payload = server.users.verify_token(self._token())
                    if not payload or payload.get("role") != Role.ADMIN:
                        self._send({"error": "forbidden"}, 403)
                        return
                    ok_ = server.orgs.add_member(
                        oid, str(body.get("username", "")),
                        str(body.get("role", Role.VIEWER)))
                    self._send({"ok": ok_})
                    return
                user = server._auth_user(self._token(),
                                         min_level=Role.LEVEL[Role.PENTESTER])
                if not user:
                    self._send({"error": "unauthorized"}, 401)
                    return
                if path == "/api/projects":
                    p = server.projects.create_project(
                        str(body.get("name", "")),
                        str(body.get("client", "")),
                        body.get("targets") or [],
                        str(body.get("schedule", "")),
                        org_id=str(body.get("org_id", "")))
                    self._send(p, 201)
                    return
                if path.startswith("/api/projects/") and path.endswith("/scan/queue"):
                    pid = path[len("/api/projects/"):-len("/scan/queue")]
                    target = str(body.get("target", ""))
                    if not target:
                        proj = server.projects.get_project(pid)
                        targets = proj.get("targets", []) if proj else []
                        target = targets[0] if targets else ""
                    if not target:
                        self._send({"error": "target kosong"}, 400)
                        return
                    meta = server.worker.enqueue(pid, target)
                    self._send({"queued": True, "result": meta})
                    return
                if path.startswith("/api/projects/") and path.endswith("/scan"):
                    pid = path[len("/api/projects/"):-len("/scan")]
                    target = str(body.get("target", ""))
                    if not target:
                        proj = server.projects.get_project(pid)
                        targets = proj.get("targets", []) if proj else []
                        target = targets[0] if targets else ""
                    if not target:
                        self._send({"error": "target kosong"}, 400)
                        return
                    res = server.run_scan(pid, target)
                    self._send(res)
                    return
                if path.startswith("/api/projects/") and path.endswith("/remediations"):
                    pid = path[len("/api/projects/"):-len("/remediations")]
                    r = server.projects.upsert_remediation(
                        pid, str(body.get("finding_key", "")),
                        str(body.get("title", "")),
                        str(body.get("status", "open")))
                    self._send(r, 201)
                    return
                if path == "/api/scheduler/start":
                    server.scheduler.start()
                    self._send({"ok": True})
                    return
                if path == "/api/scheduler/stop":
                    server.scheduler.stop()
                    self._send({"ok": True})
                    return
                if path == "/api/worker/start":
                    server.worker.start()
                    self._send({"ok": True})
                    return
                if path == "/api/worker/stop":
                    server.worker.stop()
                    self._send({"ok": True})
                    return
                self._send({"error": "not found"}, 404)

            def do_GET(self):
                path = self.path.split("?")[0]
                if path == "/api/dashboard":
                    self._send(server.dashboard())
                    return
                if path == "/api/health":
                    self._send({"ok": True})
                    return
                if path == "/api/rbac":
                    payload = server.users.verify_token(self._token())
                    if not payload:
                        self._send({"error": "unauthorized"}, 401)
                        return
                    self._send({"matrix": rbac_matrix()})
                    return
                user = server._auth_user(self._token())
                if not user:
                    self._send({"error": "unauthorized"}, 401)
                    return
                if path == "/api/users":
                    if user["role"] != Role.ADMIN:
                        self._send({"error": "forbidden"}, 403)
                        return
                    self._send({"users": server.users.list_users()})
                    return
                if path == "/api/orgs":
                    if user["role"] != Role.ADMIN:
                        self._send({"error": "forbidden"}, 403)
                        return
                    orgs = server.orgs.list_orgs()
                    for o in orgs:
                        o["members"] = server.orgs.list_members(o["id"])
                    self._send({"orgs": orgs})
                    return
                if path.startswith("/api/orgs/") and path.endswith("/members"):
                    oid = path[len("/api/orgs/"):-len("/members")]
                    if user["role"] != Role.ADMIN:
                        self._send({"error": "forbidden"}, 403)
                        return
                    self._send({"members": server.orgs.list_members(oid)})
                    return
                if path == "/api/projects":
                    org_id = server._effective_org(user)
                    self._send({"projects":
                                server.projects.list_projects(org_id=org_id)})
                    return
                if path == "/api/worker/status":
                    self._send({"queue": server.worker.queue_length(),
                                "stats": server.worker.stats})
                    return
                if path.startswith("/api/projects/") and path.endswith("/results"):
                    pid = path[len("/api/projects/"):-len("/results")]
                    self._send({"results": server.projects.project_results(pid)})
                    return
                if path.startswith("/api/projects/") and path.endswith("/remediations"):
                    pid = path[len("/api/projects/"):-len("/remediations")]
                    self._send({"remediations":
                                server.projects.list_remediations(pid)})
                    return
                self._send({"error": "not found"}, 404)

            def do_DELETE(self):
                path = self.path.split("?")[0]
                user = server._auth_user(self._token(),
                                         min_level=Role.LEVEL[Role.PENTESTER])
                if not user:
                    self._send({"error": "unauthorized"}, 401)
                    return
                if path.startswith("/api/results/"):
                    rid = path[len("/api/results/"):]
                    server.projects.delete_result(rid)
                    self._send({"ok": True})
                    return
                if path.startswith("/api/projects/"):
                    pid = path[len("/api/projects/"):]
                    server.projects.delete_project(pid)
                    self._send({"ok": True})
                    return
                self._send({"error": "not found"}, 404)

            def do_PATCH(self):
                path = self.path.split("?")[0]
                body = self._body()
                user = server._auth_user(self._token(),
                                         min_level=Role.LEVEL[Role.PENTESTER])
                if not user:
                    self._send({"error": "unauthorized"}, 401)
                    return
                if path.startswith("/api/projects/"):
                    pid = path[len("/api/projects/"):]
                    ok_ = server.projects.update_project(
                        pid,
                        name=str(body.get("name", "")) if body.get("name") else None,
                        client=str(body.get("client", "")) if body.get("client") else None,
                        targets=body.get("targets"),
                        schedule=str(body.get("schedule", "")) if body.get("schedule") else None)
                    self._send({"ok": ok_})
                    return
                self._send({"error": "not found"}, 404)

        return Handler

    def start(self) -> "EnterpriseServer":
        self._server = ThreadingHTTPServer((self.host, self.port), self._handler())
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        ok(f"keris-enterprise aktif: http://{self.host}:{self.port}")
        return self

    def run_forever(self) -> None:
        self.start()
        info("keris-enterprise berjalan (Ctrl+C untuk berhenti).")
        try:
            while not self._shutdown.is_set():
                self._shutdown.wait(0.5)
        except KeyboardInterrupt:
            pass
        self.stop()

    def stop(self) -> None:
        self.scheduler.stop()
        self.worker.stop()
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        self.db.close()
        ok("keris-enterprise dihentikan")