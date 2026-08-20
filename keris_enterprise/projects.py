"""Manajemen project/client untuk keris-enterprise.

Setiap project punya target list, jadwal scan, hasil scan terbaru, dan
status remediasi per temuan.
"""

import json
import os
import secrets
import time
from typing import Dict, List, Optional

from keris_enterprise.db import EnterpriseDB


class ProjectStore:
    def __init__(self, db: EnterpriseDB):
        self.db = db
        db.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT,
                client TEXT,
                targets TEXT,
                schedule TEXT,
                org_id TEXT,
                created_at REAL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                target TEXT,
                result TEXT,
                status TEXT,
                created_at REAL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS remediations (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                finding_key TEXT,
                title TEXT,
                status TEXT,
                updated_at REAL
            )
        """)

    # --- projects ---
    def create_project(self, name: str, client: str = "",
                       targets: Optional[List[str]] = None,
                       schedule: str = "", org_id: str = "") -> Optional[Dict]:
        pid = f"p-{secrets.token_hex(4)}"
        self.db.execute(
            "INSERT INTO projects(id,name,client,targets,schedule,created_at,org_id) "
            "VALUES(?,?,?,?,?,?,?)",
            (pid, name, client, json.dumps(targets or []), schedule, time.time(),
             org_id))
        return self.get_project(pid)

    def list_projects(self, org_id: str = "") -> List[Dict]:
        sql = "SELECT * FROM projects ORDER BY created_at DESC"
        params: tuple = ()
        if org_id:
            sql = "SELECT * FROM projects WHERE org_id=? ORDER BY created_at DESC"
            params = (org_id,)
        rows = self.db.query(sql, params)
        for r in rows:
            r["targets"] = json.loads(r.get("targets") or "[]")
        return rows

    def get_project(self, pid: str) -> Optional[Dict]:
        rows = self.db.query("SELECT * FROM projects WHERE id=?", (pid,))
        if not rows:
            return None
        p = rows[0]
        p["targets"] = json.loads(p.get("targets") or "[]")
        return p

    def update_project(self, pid: str, name: Optional[str] = None,
                       client: Optional[str] = None,
                       targets: Optional[List[str]] = None,
                       schedule: Optional[str] = None) -> bool:
        p = self.get_project(pid)
        if not p:
            return False
        self.db.execute(
            "UPDATE projects SET name=?, client=?, targets=?, schedule=? WHERE id=?",
            (name if name is not None else p["name"],
             client if client is not None else p["client"],
             json.dumps(targets) if targets is not None else json.dumps(p["targets"]),
             schedule if schedule is not None else p["schedule"],
             pid))
        return True

    def delete_project(self, pid: str) -> bool:
        self.db.execute("DELETE FROM projects WHERE id=?", (pid,))
        self.db.execute("DELETE FROM scan_results WHERE project_id=?", (pid,))
        self.db.execute("DELETE FROM remediations WHERE project_id=?", (pid,))
        return True

    # --- scan results ---
    def save_result(self, project_id: str, target: str, result: Dict,
                    status: str = "done") -> Dict:
        rid = f"s-{secrets.token_hex(4)}"
        self.db.execute(
            "INSERT INTO scan_results(id,project_id,target,result,status,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (rid, project_id, target, json.dumps(result, default=str),
             status, time.time()))
        return {"id": rid, "project_id": project_id, "target": target,
                "status": status}

    def get_result(self, rid: str) -> Optional[Dict]:
        rows = self.db.query("SELECT * FROM scan_results WHERE id=?", (rid,))
        if not rows:
            return None
        r = rows[0]
        try:
            r["result"] = json.loads(r.get("result") or "{}")
        except json.JSONDecodeError:
            r["result"] = {}
        return r

    def delete_result(self, rid: str) -> bool:
        self.db.execute("DELETE FROM scan_results WHERE id=?", (rid,))
        return True

    def update_result_status(self, rid: str, status: str) -> bool:
        self.db.execute("UPDATE scan_results SET status=? WHERE id=?",
                        (status, rid))
        return True

    def pending_results(self) -> List[Dict]:
        rows = self.db.query(
            "SELECT * FROM scan_results WHERE status IN ('queued','running') "
            "ORDER BY created_at")
        for r in rows:
            try:
                r["result"] = json.loads(r.get("result") or "{}")
            except json.JSONDecodeError:
                r["result"] = {}
        return rows

    def project_results(self, project_id: str) -> List[Dict]:
        rows = self.db.query(
            "SELECT * FROM scan_results WHERE project_id=? ORDER BY created_at DESC",
            (project_id,))
        for r in rows:
            try:
                r["result"] = json.loads(r.get("result") or "{}")
            except json.JSONDecodeError:
                r["result"] = {}
        return rows

    def recent_results(self, limit: int = 10) -> List[Dict]:
        rows = self.db.query(
            "SELECT * FROM scan_results ORDER BY created_at DESC LIMIT ?",
            (limit,))
        for r in rows:
            try:
                r["result"] = json.loads(r.get("result") or "{}")
            except json.JSONDecodeError:
                r["result"] = {}
        return rows

    # --- remediation tracking ---
    def upsert_remediation(self, project_id: str, finding_key: str,
                           title: str, status: str = "open") -> Dict:
        rows = self.db.query(
            "SELECT id FROM remediations WHERE project_id=? AND finding_key=?",
            (project_id, finding_key))
        if rows:
            self.db.execute(
                "UPDATE remediations SET title=?, status=?, updated_at=? "
                "WHERE project_id=? AND finding_key=?",
                (title, status, time.time(), project_id, finding_key))
        else:
            self.db.execute(
                "INSERT INTO remediations(id,project_id,finding_key,title,status,updated_at) "
                "VALUES(?,?,?,?,?,?)",
                (f"r-{secrets.token_hex(4)}", project_id, finding_key, title,
                 status, time.time()))
        return {"project_id": project_id, "finding_key": finding_key,
                "title": title, "status": status}

    def list_remediations(self, project_id: str,
                          status: str = "") -> List[Dict]:
        if status:
            return self.db.query(
                "SELECT * FROM remediations WHERE project_id=? AND status=? "
                "ORDER BY updated_at DESC", (project_id, status))
        return self.db.query(
            "SELECT * FROM remediations WHERE project_id=? ORDER BY updated_at DESC",
            (project_id,))

    def remediate(self, project_id: str, finding_key: str,
                  status: str = "fixed") -> bool:
        self.db.execute(
            "UPDATE remediations SET status=?, updated_at=? "
            "WHERE project_id=? AND finding_key=?",
            (status, time.time(), project_id, finding_key))
        return True