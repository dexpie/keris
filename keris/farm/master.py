"""Master node untuk distributed scan farm.

Menjalankan HTTP REST API (stdlib `http.server`) yang:
- menerima registrasi worker
- menerima submit job (daftar target)
- memberikan job ke worker (load balancing berbasis capacity + last-seen)
- menerima hasil job dan mengagregasi ke report markdown
- menyediakan endpoint status / shutdown (JWT admin)

Metadata disimpan di SQLite; report file lokal disimpan di direktori
report dir (model seperti object store).
"""

import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

from keris.core.logger import info, ok, warn
from keris.farm.auth import create_token, read_secret, require_auth

SCHEMA = """
CREATE TABLE IF NOT EXISTS workers (
    id TEXT PRIMARY KEY,
    name TEXT,
    capacity INTEGER DEFAULT 1,
    status TEXT DEFAULT 'idle',
    last_seen REAL
);
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    target TEXT,
    config TEXT,
    status TEXT DEFAULT 'pending',
    worker_id TEXT,
    result TEXT,
    created_at REAL,
    assigned_at REAL,
    done_at REAL
);
"""


class FarmStore:
    """SQLite storage untuk metadata farm."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()

    def _rows(self, sql: str, params: tuple = ()) -> List[Dict]:
        cur = self._conn.execute(sql, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    # workers
    def upsert_worker(self, wid: str, name: str, capacity: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO workers(id,name,capacity,status,last_seen) "
                "VALUES(?,?,?,?,?)",
                (wid, name, capacity, "idle", time.time()))
            self._conn.commit()

    def touch_worker(self, wid: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE workers SET last_seen=? WHERE id=?",
                               (time.time(), wid))
            self._conn.commit()

    def set_worker_status(self, wid: str, status: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE workers SET status=? WHERE id=?",
                               (status, wid))
            self._conn.commit()

    def get_workers(self) -> List[Dict]:
        return self._rows("SELECT * FROM workers")

    # jobs
    def add_job(self, jid: str, target: str, config: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO jobs(id,target,config,status,created_at) VALUES(?,?,?,?,?)",
                (jid, target, config, "pending", time.time()))
            self._conn.commit()

    def claim_job(self, wid: str) -> Optional[Dict]:
        """Ambil job pending; load balancing + reassign worker mati."""
        with self._lock:
            # reassign job yang ditinggal worker mati (>60s sejak assign)
            stale = self._rows(
                "SELECT * FROM jobs WHERE status='assigned' AND assigned_at<?",
                (time.time() - 60,))
            for j in stale:
                self._conn.execute("UPDATE jobs SET status='pending', worker_id=NULL "
                                   "WHERE id=?", (j["id"],))
            job = self._rows(
                "SELECT * FROM jobs WHERE status='pending' ORDER BY created_at LIMIT 1")
            self._conn.commit()
        if not job:
            return None
        j = job[0]
        with self._lock:
            self._conn.execute(
                "UPDATE jobs SET status='assigned', worker_id=?, assigned_at=? "
                "WHERE id=?", (wid, time.time(), j["id"]))
            self._conn.commit()
            self._conn.execute("UPDATE workers SET status='busy', last_seen=? "
                               "WHERE id=?", (time.time(), wid))
            self._conn.commit()
        return {"id": j["id"], "target": j["target"], "config": j["config"]}

    def complete_job(self, jid: str, wid: str, result: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE jobs SET status='done', result=?, done_at=?, worker_id=? "
                "WHERE id=?", (result, time.time(), wid, jid))
            self._conn.execute("UPDATE workers SET status='idle', last_seen=? "
                               "WHERE id=?", (time.time(), wid))
            self._conn.commit()

    def fail_job(self, jid: str, wid: str, err: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE jobs SET status='failed', result=?, done_at=?, worker_id=? "
                "WHERE id=?", (json.dumps({"error": err}), time.time(), wid, jid))
            self._conn.execute("UPDATE workers SET status='idle', last_seen=? "
                               "WHERE id=?", (time.time(), wid))
            self._conn.commit()

    def get_jobs(self, status: Optional[str] = None) -> List[Dict]:
        if status:
            return self._rows("SELECT * FROM jobs WHERE status=?", (status,))
        return self._rows("SELECT * FROM jobs")

    def get_job(self, jid: str) -> Optional[Dict]:
        rows = self._rows("SELECT * FROM jobs WHERE id=?", (jid,))
        return rows[0] if rows else None

    def stats(self) -> Dict[str, Any]:
        rows = self._rows("SELECT status, COUNT(*) n FROM jobs GROUP BY status")
        by_status = {r["status"]: r["n"] for r in rows}
        workers = self.get_workers()
        return {
            "workers": len(workers),
            "workers_detail": workers,
            "jobs": sum(by_status.values()),
            "pending": by_status.get("pending", 0),
            "assigned": by_status.get("assigned", 0),
            "done": by_status.get("done", 0),
            "failed": by_status.get("failed", 0),
        }


class MasterServer:
    """HTTP REST API master farm."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8080,
                 db_path: str = "", report_dir: str = "", secret: str = ""):
        self.host = host
        self.port = port
        db_path = db_path or os.path.join(os.getcwd(), "farm.db")
        report_dir = report_dir or os.path.join(os.getcwd(), "farm_reports")
        self.store = FarmStore(db_path)
        self.report_dir = report_dir
        self.secret = secret or read_secret()
        os.makedirs(report_dir, exist_ok=True)
        self._shutdown = threading.Event()
        self._server = None
        self._thread = None

    def _handler(self):
        master = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def _json(self, data: Dict, code: int = 200):
                body = json.dumps(data).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read_body(self) -> Dict:
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
                body = self._read_body()
                if path == "/api/register":
                    name = str(body.get("name", "worker"))
                    capacity = int(body.get("capacity", 1) or 1)
                    wid = f"w-{int(time.time() * 1000)}"
                    master.store.upsert_worker(wid, name, capacity)
                    token = create_token({"sub": wid, "role": "worker",
                                          "capacity": capacity}, master.secret)
                    ok(f"Worker terdaftar: {name} ({wid})")
                    self._json({"worker_id": wid, "token": token})
                    return
                payload = require_auth(self._token(), master.secret, role="worker")
                if not payload:
                    self._json({"error": "unauthorized"}, 401)
                    return
                wid = payload.get("sub", "")
                if path == "/api/jobs":
                    targets = body.get("targets") or []
                    if not targets:
                        self._json({"error": "targets kosong"}, 400)
                        return
                    jids = []
                    for t in targets:
                        jid = f"j-{int(time.time() * 1000)}-{len(jids)}"
                        master.store.add_job(jid, str(t),
                                             json.dumps(body.get("config", {})))
                        jids.append(jid)
                    ok(f"{len(jids)} job diterima")
                    self._json({"job_ids": jids})
                    return
                if path == "/api/claim":
                    master.store.touch_worker(wid)
                    job = master.store.claim_job(wid)
                    if job:
                        info(f"Job {job['id']} diklaim worker {wid}: {job['target']}")
                        self._json({"job": job})
                    else:
                        master.store.set_worker_status(wid, "idle")
                        self._json({"job": None})
                    return
                if path.startswith("/api/jobs/") and path.endswith("/result"):
                    jid = path[len("/api/jobs/"):-len("/result")]
                    master.store.complete_job(jid, wid,
                                              json.dumps(body.get("result", {}),
                                                         default=str))
                    ok(f"Hasil job {jid} dari {wid}")
                    self._json({"ok": True})
                    return
                if path.startswith("/api/jobs/") and path.endswith("/fail"):
                    jid = path[len("/api/jobs/"):-len("/fail")]
                    master.store.fail_job(jid, wid, str(body.get("error", "unknown")))
                    self._json({"ok": True})
                    return
                if path == "/api/shutdown":
                    if payload.get("role") == "admin":
                        master._shutdown.set()
                        self._json({"ok": True})
                    else:
                        self._json({"error": "forbidden"}, 403)
                    return
                self._json({"error": "not found"}, 404)

            def do_GET(self):
                path = self.path.split("?")[0]
                if path == "/api/status":
                    self._json(master.store.stats())
                    return
                if path == "/api/jobs":
                    payload = require_auth(self._token(), master.secret,
                                           role="worker")
                    if not payload:
                        self._json({"error": "unauthorized"}, 401)
                        return
                    self._json({"jobs": master.store.get_jobs()})
                    return
                if path == "/api/report":
                    md = master.render_report()
                    body = md.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/markdown")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self._json({"error": "not found"}, 404)

        return Handler

    def render_report(self) -> str:
        """Unified report markdown dari semua job selesai."""
        jobs = self.store.get_jobs(status="done")
        lines = ["# Farm Unified Report", "",
                 f"Total job selesai: {len(jobs)}", ""]
        for j in jobs:
            lines.append(f"## Target: {j['target']}")
            lines.append("")
            try:
                res = json.loads(j["result"] or "{}")
            except json.JSONDecodeError:
                res = {}
            findings = res.get("findings", []) if isinstance(res, dict) else []
            lines.append(f"Temuan: {len(findings)}")
            if findings:
                lines.append("| Severity | Lokasi | Deskripsi |")
                lines.append("|---|---|---|")
                for f in findings[:50]:
                    lines.append(f"| {f.get('severity', 'INFO')} | "
                                 f"`{f.get('endpoint', '')}` | "
                                 f"{f.get('title', '')} |")
            lines.append("")
        return "\n".join(lines)

    def save_report(self) -> str:
        md = self.render_report()
        path = os.path.join(self.report_dir, "farm-report.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(md)
        return path

    def start(self) -> "MasterServer":
        self._server = ThreadingHTTPServer((self.host, self.port), self._handler())
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        ok(f"Farm master aktif: http://{self.host}:{self.port}")
        return self

    def run_forever(self) -> None:
        self.start()
        info("Master berjalan sampai di-stop (Ctrl+C / keris farm stop).")
        try:
            while not self._shutdown.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        self.stop()

    def stop(self) -> None:
        self._shutdown.set()
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        ok("Farm master dihentikan")