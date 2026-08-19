"""Storage bersama keris-enterprise (SQLite dev / PostgreSQL-ready)."""

import os
import sqlite3
import threading
from typing import Any, List, Optional


class EnterpriseDB:
    """Wrapper SQLite dengan lock untuk akses thread-safe."""

    def __init__(self, db_path: str = ""):
        db_path = db_path or os.path.join(os.getcwd(), "keris-enterprise.db")
        self.db_path = db_path
        parent = os.path.dirname(os.path.abspath(db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()

    def execute(self, sql: str, params: tuple = ()) -> None:
        with self._lock:
            self._conn.execute(sql, params)
            self._conn.commit()

    def query(self, sql: str, params: tuple = ()) -> List[dict]:
        with self._lock:
            cur = self._conn.execute(sql, params)
            cols = [d[0] for d in cur.description] if cur.description else []
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass