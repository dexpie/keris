"""GraphQL testing: deteksi endpoint, introspection, query berbahaya.

- deteksi endpoint umum (/graphql, /api/graphql, dll)
- uji introspection (bila aktif => info penting)
- uji batching / aliases untuk abuse
- uji query dengan depth besar (DoS) — non-destruktif, cukup 1 query kecil
"""

from typing import Dict, List, Optional

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/graph", "/graphiql", "/gql", "/query", "/api/query",
]

INTROSPECTION_QUERY = """query { __schema { types { name } } }"""


def detect_endpoint(base: str, client: KerisHTTP) -> Optional[str]:
    """Cari endpoint GraphQL yang menerima POST introspection."""
    for path in GRAPHQL_PATHS:
        url = base.rstrip("/") + path
        try:
            r = client.post(url, json={
                "query": INTROSPECTION_QUERY,
            }, timeout=15)
        except requests.RequestException:
            continue
        body = r.text[:500]
        if r.status_code == 200 and ("__schema" in body or '"types"' in body):
            ok(f"GraphQL endpoint: {url}")
            return url
        if "graphql" in body.lower() or r.status_code == 400:
            # mungkin endpoint tapi introspection dimatikan
            debug(f"Kandidat GraphQL (tanpa introspection): {url}")
    return None


def test_introspection(url: str, client: KerisHTTP) -> Optional[Dict]:
    """Jalankan introspection penuh. Mengembalikan info schema bila aktif."""
    try:
        r = client.post(url, json={"query": INTROSPECTION_QUERY}, timeout=20)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    data = r.json() if "application/json" in r.headers.get("content-type", "") or r.text.startswith("{") else {}
    try:
        types = data["data"]["__schema"]["types"]
    except (KeyError, TypeError):
        return None
    names = [t.get("name", "") for t in types if not t.get("name", "").startswith("__")]
    return {"types": sorted(names), "count": len(names)}


def test_depth_abuse(url: str, client: KerisHTTP, field: str = "__typename",
                     depth: int = 12) -> bool:
    """Query bertumpuk (aliases) untuk menguji pembatasan kedalaman query."""
    # alias berulang dalam satu operasi — test pembatasan depth
    q = "query { " + " ".join(f"a{i}: __typename" for i in range(30)) + " }"
    try:
        r = client.post(url, json={"query": q}, timeout=20)
        if r.status_code == 200 and '"data"' in r.text:
            return True
    except requests.RequestException:
        pass
    return False


def test_batching(url: str, client: KerisHTTP) -> bool:
    """Cek apakah endpoint menerima array query (batching)."""
    try:
        r = client.post(url, json=[
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ], timeout=20)
        return r.status_code == 200 and isinstance(r.json() if "json" in r.headers.get("content-type", "") or r.text.startswith("[") else None, list)
    except (requests.RequestException, ValueError):
        return False


def check_graphql(base: str, client: KerisHTTP) -> List[Finding]:
    """Uji penuh keamanan GraphQL pada target."""
    findings = []
    ep = detect_endpoint(base, client)
    if not ep:
        info("Endpoint GraphQL tidak terdeteksi")
        return findings

    schema = test_introspection(ep, client)
    if schema:
        findings.append(Finding(
            "MEDIUM", "GraphQL introspection aktif",
            ep,
            f"Introspection mengizinkan enumerasi schema ({schema['count']} tipe). "
            "Matikan di produksi.",
            "types=" + ",".join(schema["types"][:10]),
        ))
        debug(f"  types: {', '.join(schema['types'][:8])}")
    else:
        debug("Introspection dimatikan")

    if test_batching(ep, client):
        findings.append(Finding(
            "LOW", "GraphQL batching aktif",
            ep, "Endpoint menerima array query (batching) — potensial "
                "amplifikasi DoS/brute-force bila tanpa rate limit.",
            "batching=true",
        ))

    if test_depth_abuse(ep, client):
        findings.append(Finding(
            "LOW", "Query GraphQL dalam/dengan banyak alias diterima",
            ep, "Server menerima query dengan banyak field/alias. Bila tanpa "
                "limit kedalaman & kompleksitas, rentan DoS (graphql DoS).",
            "aliases=30",
        ))

    return findings