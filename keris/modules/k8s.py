"""Kubernetes cluster attack: enum & uji akses endpoint k8s.

Menargetkan API server Kubernetes (kubectl/unauthenticated) atau melalui
SSRF pivot:
- deteksi API server (kube-apiserver): /api, /api/v1, /version
- enum pods, namespaces, secrets, serviceaccounts, configmaps
- cek RBAC: apakah kita bisa list/get objek (tanpa menulis/menghapus)
- deteksi anonymous access (tanpa token)

Mendukung mode langsung (base = https://api-server) dan mode pivot SSRF
(vuln_url + vuln_param mengarah ke k8s API internal).

GUARD: memerlukan `authorized=True`; tanpa itu modul menolak beroperasi.
"""

import json
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

K8S_PATHS = [
    "/version", "/api", "/api/v1", "/api/v1/namespaces",
    "/api/v1/pods", "/api/v1/secrets", "/api/v1/serviceaccounts",
    "/api/v1/configmaps", "/apis/apps/v1/deployments",
    "/apis/rbac.authorization.k8s.io/v1/roles",
    "/apis/rbac.authorization.k8s.io/v1/clusterroles",
    "/apis/apps/v1/statefulsets",
]


def _is_json_list(body: str) -> bool:
    if not body or not body.strip().startswith(("{", "[")):
        return False
    try:
        d = json.loads(body)
        return "items" in d if isinstance(d, dict) else isinstance(d, list)
    except Exception:
        return False


def scan_k8s(base: str, client: KerisHTTP,
             vuln_url: str = "", vuln_param: str = "",
             authorized: bool = False) -> List[Finding]:
    """Scan k8s API. Bila vuln_url+param diisi -> lewat SSRF pivot."""
    if not authorized:
        warn("K8s scan memerlukan --authorized.")
        return []
    findings: List[Finding] = []
    base = base.rstrip("/")

    def _fetch(path: str) -> Optional[tuple]:
        if vuln_url and vuln_param:
            q = dict(parse_qsl(urlparse(vuln_url).query))
            q[vuln_param] = base + path
            p = urlparse(vuln_url)
            target = urlunparse(p._replace(query=urlencode(q)))
            try:
                r = client.get(target, timeout=15)
                return r.status_code, r.text or ""
            except Exception:
                return None
        try:
            r = client.get(base + path, timeout=15)
            return r.status_code, r.text or ""
        except Exception:
            return None

    info(f"K8s scan: {base} (pivot={'yes' if vuln_url else 'no'})")
    api_ok = False
    open_objects = []
    for path in K8S_PATHS:
        res = _fetch(path)
        if res is None:
            continue
        code, body = res
        if code == 200:
            if path in ("/version", "/api", "/api/v1"):
                api_ok = True
                info(f"  k8s API up: {path} ({code})")
            elif _is_json_list(body):
                try:
                    d = json.loads(body)
                    n = len(d.get("items", []))
                except Exception:
                    n = 0
                if n:
                    open_objects.append((path, n, code))
                    info(f"  terbuka: {path} -> {n} objek")
                else:
                    debug(f"  {path}: 200 tapi kosong")
            else:
                debug(f"  {path}: 200 (bukan list JSON)")
        elif code == 403:
            debug(f"  {path}: 403 (ditolak)")
        elif code == 401:
            debug(f"  {path}: 401 (butuh auth)")
        else:
            debug(f"  {path}: {code}")

    if open_objects:
        findings.append(Finding(
            "CRITICAL", "Kubernetes API akses tidak sah (RBAC lemah)",
            base,
            "Endpoint k8s dapat di-list tanpa izin: " +
            ", ".join(f"{p}({n})" for p, n, _ in open_objects[:8]) +
            ". Attacker dapat membaca secrets, pods, dan menjalankan "
            "pivot dalam cluster.",
            "; ".join(f"{p}={n}" for p, n, _ in open_objects),
            cwe="CWE-306",
            references="https://owasp.org/www-project-kubernetes-top-ten/",
        ))
        ok(f"K8s: {len(open_objects)} objek dapat diakses tanpa auth")
    elif api_ok:
        findings.append(Finding(
            "HIGH", "Kubernetes API terdeteksi (auth dibutuhkan)",
            base,
            "API server k8s merespons, tapi objek terproteksi. Uji dengan "
            "token bocor atau via SSRF pivot.",
            "endpoints=" + ",".join(K8S_PATHS[:4]),
            cwe="CWE-306",
        ))
    else:
        debug("Tidak ada endpoint k8s yang merespons")
    return findings
