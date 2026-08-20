"""Multi-tenant organizations untuk keris-enterprise (v0.27.0).

Model: user dimiliki organisasi (`org_id`); project dimiliki organisasi.
Data lintas org di-isolasi lewat filter `org_id` pada setiap query.
Org dengan `org_id=""` adalah "global" (semua pengguna admin sistem bisa
melihat, digunakan untuk kompatibilitas v0.17-v0.26).

Kelas:
- `OrgStore`: CRUD organisasi + keanggotaan admin org.
- `scoped`: helper untuk filter query per-org.
- `PERMISSIONS` / `has_permission`: RBAC matrix per role.
"""

import secrets
import time
from typing import Dict, List, Optional

from keris_enterprise.auth import Role
from keris_enterprise.db import EnterpriseDB

# ---------------------------------------------------------------------------
# RBAC matrix: role -> kumpulan izin
# ---------------------------------------------------------------------------

# Izin yang dikenal
P_SCAN = "scan"
P_MANAGE_PROJECTS = "manage_projects"
P_MANAGE_USERS = "manage_users"
P_MANAGE_ORGS = "manage_orgs"
P_VIEW_RESULTS = "view_results"
P_RUN_SCHEDULER = "run_scheduler"
P_VIEW_REPORTS = "view_reports"
P_MANAGE_REMEDIATIONS = "manage_remediations"

ALL_PERMISSIONS = (
    P_SCAN, P_MANAGE_PROJECTS, P_MANAGE_USERS, P_MANAGE_ORGS,
    P_VIEW_RESULTS, P_RUN_SCHEDULER, P_VIEW_REPORTS, P_MANAGE_REMEDIATIONS,
)

PERMISSIONS: Dict[str, tuple] = {
    Role.ADMIN: (P_SCAN, P_MANAGE_PROJECTS, P_MANAGE_USERS, P_MANAGE_ORGS,
                 P_VIEW_RESULTS, P_RUN_SCHEDULER, P_VIEW_REPORTS,
                 P_MANAGE_REMEDIATIONS),
    Role.PENTESTER: (P_SCAN, P_MANAGE_PROJECTS, P_VIEW_RESULTS,
                     P_VIEW_REPORTS, P_MANAGE_REMEDIATIONS),
    Role.VIEWER: (P_VIEW_RESULTS, P_VIEW_REPORTS),
}


def has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, ())


def rbac_matrix() -> Dict[str, Dict[str, bool]]:
    """Matriks izin lengkap untuk tampilan/API."""
    return {r: {p: has_permission(r, p) for p in ALL_PERMISSIONS}
            for r in Role.ALL}


class OrgStore:
    def __init__(self, db: EnterpriseDB):
        self.db = db
        db.execute("""
            CREATE TABLE IF NOT EXISTS orgs (
                id TEXT PRIMARY KEY,
                name TEXT,
                created_at REAL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS org_users (
                org_id TEXT,
                username TEXT,
                role TEXT,
                PRIMARY KEY (org_id, username)
            )
        """)
        # migrasi kolom org_id bila belum ada (menjaga kompatibilitas DB lama)
        self._ensure_column("users", "org_id")
        self._ensure_column("projects", "org_id")

    def _ensure_column(self, table: str, column: str) -> None:
        try:
            rows = self.db.query(f"PRAGMA table_info({table})")
            if any(r["name"] == column for r in rows):
                return
            self.db.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT")
        except Exception:
            pass

    # --- orgs ---
    def create_org(self, name: str) -> Dict:
        oid = f"o-{secrets.token_hex(4)}"
        self.db.execute("INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)",
                        (oid, name, time.time()))
        return {"id": oid, "name": name}

    def list_orgs(self) -> List[Dict]:
        return self.db.query("SELECT * FROM orgs ORDER BY name")

    def get_org(self, oid: str) -> Optional[Dict]:
        rows = self.db.query("SELECT * FROM orgs WHERE id=?", (oid,))
        return rows[0] if rows else None

    def delete_org(self, oid: str) -> bool:
        self.db.execute("DELETE FROM orgs WHERE id=?", (oid,))
        self.db.execute("DELETE FROM org_users WHERE org_id=?", (oid,))
        return True

    # --- keanggotaan ---
    def add_member(self, org_id: str, username: str, role: str) -> bool:
        if role not in Role.ALL:
            return False
        self.db.execute(
            "INSERT OR REPLACE INTO org_users(org_id,username,role) VALUES(?,?,?)",
            (org_id, username, role))
        return True

    def list_members(self, org_id: str) -> List[Dict]:
        return self.db.query(
            "SELECT username, role FROM org_users WHERE org_id=?", (org_id,))

    def member_role(self, org_id: str, username: str) -> Optional[str]:
        rows = self.db.query(
            "SELECT role FROM org_users WHERE org_id=? AND username=?",
            (org_id, username))
        return rows[0]["role"] if rows else None

    def remove_member(self, org_id: str, username: str) -> bool:
        self.db.execute("DELETE FROM org_users WHERE org_id=? AND username=?",
                        (org_id, username))
        return True


# ---------------------------------------------------------------------------
# scope helper: tambahkan klausa org pada query
# ---------------------------------------------------------------------------

def scoped(org_id: str, sql: str, params: tuple = ()) -> tuple:
    """Tambahkan filter `org_id=?` ke query SQL bila org_id diberikan.

    Mengembalikan (sql, params). org_id kosong = global (tanpa filter).
    """
    if not org_id:
        return sql, params
    if "WHERE" in sql.upper():
        sql = sql.replace("WHERE", "WHERE org_id=? AND ", 1)
    else:
        sql = f"{sql} WHERE org_id=?"
    return sql, params + (org_id,)