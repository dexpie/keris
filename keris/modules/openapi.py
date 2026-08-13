"""Import & pemrosesan dokumen OpenAPI/Swagger.

Mengambil spec dari endpoint umum (/openapi.json, /swagger.json, dll),
memparse path + method + parameter, lalu menyiapkan endpoint untuk fuzz.
"""

import json
from typing import Dict, List, Optional
from urllib.parse import urljoin

import requests
from yaml import safe_load

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn

# Endpoint umum untuk lokasi spec OpenAPI/Swagger
OPENAPI_PATHS = [
    "/openapi.json", "/swagger.json", "/api/openapi.json", "/api/swagger.json",
    "/swagger/v1/swagger.json", "/openapi.yaml", "/swagger.yaml", "/api-docs",
]

# Contoh nilai parameter agar request valid saat fuzz
SAMPLE_VALUES = {
    "string": "test",
    "integer": "1",
    "number": "1.5",
    "boolean": "true",
    "array": "a",
    "object": '{"a":1}',
}


def _load_yaml(text: str) -> Optional[dict]:
    try:
        return safe_load(text)
    except Exception:
        return None


def fetch_openapi(base: str, client: KerisHTTP, timeout: float = 15.0) -> Optional[dict]:
    """Cari spec OpenAPI di endpoint umum dan kembalikan dict spec-nya."""
    for path in OPENAPI_PATHS:
        url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        try:
            r = client.get(url, timeout=timeout)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        text = r.text
        spec = None
        if "json" in r.headers.get("Content-Type", "") or text.lstrip().startswith(("{", "[")):
            try:
                spec = json.loads(text)
            except Exception:
                spec = None
        if spec is None:
            spec = _load_yaml(text)
        if isinstance(spec, dict) and ("paths" in spec or "swagger" in spec or "openapi" in spec):
            ok(f"OpenAPI ditemukan: {path} (v{spec.get('openapi', spec.get('swagger', '?'))})")
            return spec
        debug(f"{path} bukan spec valid")
    warn("Spec OpenAPI/Swagger tidak ditemukan di endpoint umum")
    return None


def extract_operations(spec: dict, base: str) -> List[dict]:
    """Ubah spec menjadi daftar operasi (method + path + params) yang bisa di-fuzz."""
    operations = []
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            method = method.lower()
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            if not isinstance(op, dict):
                continue
            # resolusi parameter path + query
            params = []
            for p in op.get("parameters", []) or []:
                if not isinstance(p, dict):
                    continue
                name = p.get("name")
                loc = p.get("in")
                schema = p.get("schema", {}) if isinstance(p.get("schema"), dict) else {}
                ptype = schema.get("type", "string")
                params.append({
                    "name": name, "in": loc, "type": ptype,
                    "required": bool(p.get("required", False)),
                    "value": SAMPLE_VALUES.get(ptype, "test"),
                })
            # jalur path template: /users/{id} -> /users/1
            full_path = base.rstrip("/") + path
            for p in params:
                if p["in"] == "path":
                    full_path = full_path.replace("{" + p["name"] + "}", p["value"])
            operations.append({
                "method": method,
                "path": path,
                "url": full_path,
                "params": params,
                "summary": op.get("summary", ""),
            })
    return operations
