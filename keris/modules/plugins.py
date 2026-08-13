"""Engine plugin Keris.

Dua jenis plugin didukung:

1. Plugin Python (`.py`) — file berisi fungsi:
       def run(client, base, ctx) -> list[Finding]:
           ...
   Wajib mengembalikan list objek Finding (dari keris.modules.scanner).

2. Plugin JSON (`.json`) — template deklaratif:
       {
         "name": "nama-check",
         "severity": "MEDIUM",
         "detail": "deskripsi",
         "requests": [
           {
             "method": "GET",
             "path": "/api/health",
             "match_status": [200],
             "not_match": ["status\":\"ok"]
           }
         ]
       }
   Rule: untuk setiap request, jika status cocok (match_status) DAN body
   mengandung semua di `match` (atau tidak mengandung `not_match`) ->
   menghasilkan finding.
"""

import importlib.util
import json
import os
from typing import List, Optional

from keris.core.http import KerisHTTP
from keris.core.logger import info, warn, error, debug, ok
from keris.modules.scanner import Finding


def load_plugin(plugin_path: str):
    """Muat plugin Python dan kembalikan objek modul."""
    if not os.path.exists(plugin_path):
        raise FileNotFoundError(f"Plugin tidak ditemukan: {plugin_path}")
    if plugin_path.endswith(".json"):
        return _load_json_plugin(plugin_path)
    spec = importlib.util.spec_from_file_location("keris_plugin", plugin_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "run"):
        raise ValueError(f"Plugin {plugin_path} tidak memiliki fungsi `run(client, base, ctx)`")
    return module


def _load_json_plugin(plugin_path: str) -> dict:
    with open(plugin_path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_json_plugin(spec: dict, client: KerisHTTP, base: str, ctx: dict) -> List[Finding]:
    """Jalankan plugin JSON deklaratif."""
    findings = []
    base_clean = base.rstrip("/")
    for req in spec.get("requests", []):
        method = req.get("method", "GET").upper()
        path = req.get("path", "/")
        url = path if path.startswith(("http://", "https://")) else base_clean + path
        try:
            r = client.request(method, url, allow_redirects=False, timeout=15)
        except Exception as e:
            debug(f"Plugin {spec.get('name', '?')}: request gagal {e}")
            continue
        status_ok = not req.get("match_status") or r.status_code in req.get("match_status", [])
        body = r.text[:8000]
        match_ok = all((m in body) for m in req.get("match", []))
        not_match_ok = not any((m in body) for m in req.get("not_match", []))
        if status_ok and match_ok and not_match_ok:
            findings.append(Finding(
                severity=req.get("severity", spec.get("severity", "INFO")).upper(),
                title=req.get("name", spec.get("name", "Plugin check")),
                endpoint=url,
                detail=req.get("detail", "Terpenuhi aturan plugin."),
                evidence=body[:300],
            ))
    return findings


def run_plugin(plugin, client: KerisHTTP, base: str, ctx: dict) -> List[Finding]:
    """Jalankan plugin (Python atau JSON)."""
    if isinstance(plugin, dict):
        return run_json_plugin(plugin, client, base, ctx)
    try:
        result = plugin.run(client, base, ctx)
        if result is None:
            result = []
        if not isinstance(result, list):
            raise ValueError(f"Plugin harus mengembalikan list, bukan {type(result)}")
        return [f if isinstance(f, Finding) else Finding(**f) for f in result]
    except Exception as e:
        warn(f"Plugin gagal: {e}")
        return []


def load_plugins(plugins_dir: Optional[str], extra_paths: Optional[List[str]] = None) -> List[dict]:
    """Muat semua plugin dari direktori + path eksplisit."""
    loaded = []
    paths = []
    if plugins_dir and os.path.isdir(plugins_dir):
        for fname in sorted(os.listdir(plugins_dir)):
            if fname.endswith(".py") or fname.endswith(".json"):
                paths.append(os.path.join(plugins_dir, fname))
    for p in extra_paths or []:
        if os.path.exists(p):
            paths.append(p)
    for path in paths:
        try:
            plugin = load_plugin(path)
            name = os.path.basename(path)
            loaded.append({"name": name, "path": path, "obj": plugin})
            debug(f"Plugin dimuat: {name}")
        except Exception as e:
            warn(f"Gagal memuat plugin {path}: {e}")
    return loaded


def run_plugins(plugins: List[dict], client: KerisHTTP, base: str, ctx: dict) -> List[Finding]:
    findings = []
    for p in plugins:
        found = run_plugin(p["obj"], client, base, ctx)
        for f in found:
            f.endpoint = f.endpoint
            findings.append(f)
        if found:
            ok(f"Plugin {p['name']}: {len(found)} temuan")
    return findings
