"""Template / rule engine Keris (v0.13.0).

Memuat template YAML deklaratif (mirip Nuclei, ringan) dan menjalankannya
terhadap target. Tiap template berisi satu atau lebih request; tiap request
punya matchers (status / word / regex) dengan kondisi AND/OR. Temuan dihasilkan
hanya bila SELURUH matcher dalam satu request terpenuhi — ini yang membuat
deteksi akurat (false positive rendah).

Skema template v1:
    id: spring-actuator-exposed
    info:
      name: Spring Actuator ter-expose
      severity: HIGH
      description: ...
      tags: [misconfig, spring]
      cwe: CWE-200
      reference: https://...
    requests:
      - method: GET
        path: /actuator/health
        matchers-condition: and        # and | or (default: and)
        matchers:
          - type: status
            status: [200]
          - type: word
            words: ["UP", "status"]
            part: body                 # body | header | all
            condition: and             # and | or untuk words
          - type: regex
            regex: ["\\{\\s*\"status\""]
            part: body
        extractors:
          - type: regex
            name: version
            group: 1
            regex: ["status\":\\s*\"([A-Za-z]+)\""]
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import yaml

from keris.core.http import KerisHTTP
from keris.core.logger import debug, error, info, ok, warn
from keris.modules.scanner import Finding

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "templates")
DEFAULT_TEMPLATE_SEVERITY = "INFO"

# bobot tiap matcher untuk skor akurasi (0..1)
_MATCHER_WEIGHT = {"status": 0.15, "word": 0.3, "regex": 0.45}
# base confidence template tanpa info.spm (sumber tepercaya)
_DEFAULT_CONF = 0.6


class TemplateError(ValueError):
    """Template tidak valid."""


@dataclass
class Template:
    id: str
    name: str
    severity: str
    description: str
    tags: List[str]
    cwe: str
    reference: str
    confidence: float
    requests: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "tags": self.tags,
            "cwe": self.cwe,
            "reference": self.reference,
            "confidence": self.confidence,
            "requests": len(self.requests),
        }


def _as_list(v) -> List:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _validate_request(req: dict, template_id: str) -> None:
    if not isinstance(req, dict):
        raise TemplateError(f"{template_id}: request harus object")
    path = req.get("path")
    if not path or not isinstance(path, str):
        raise TemplateError(f"{template_id}: request butuh `path` string")
    matchers = req.get("matchers", [])
    if not isinstance(matchers, list) or not matchers:
        raise TemplateError(f"{template_id}: request butuh minimal 1 matcher")
    for m in matchers:
        if not isinstance(m, dict):
            raise TemplateError(f"{template_id}: matcher harus object")
        mtype = m.get("type", "word")
        if mtype not in ("status", "word", "regex"):
            raise TemplateError(f"{template_id}: matcher type tidak dikenal: {mtype}")
        if mtype == "status" and not m.get("status"):
            raise TemplateError(f"{template_id}: matcher status butuh `status`")
        if mtype == "word" and not m.get("words"):
            raise TemplateError(f"{template_id}: matcher word butuh `words`")
        if mtype == "regex" and not m.get("regex"):
            raise TemplateError(f"{template_id}: matcher regex butuh `regex`")


def parse_template(data: dict) -> Template:
    """Parsing & validasi satu template dict (dari YAML)."""
    tid = str(data.get("id", "")).strip()
    if not tid:
        raise TemplateError("template butuh `id`")
    info_block = data.get("info") or {}
    if not isinstance(info_block, dict):
        raise TemplateError(f"{tid}: `info` harus object")

    requests = _as_list(data.get("requests"))
    if not requests:
        raise TemplateError(f"{tid}: butuh minimal 1 request")
    for req in requests:
        _validate_request(req, tid)

    sev = str(info_block.get("severity", DEFAULT_TEMPLATE_SEVERITY)).upper()
    if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        sev = DEFAULT_TEMPLATE_SEVERITY

    conf = float(info_block.get("confidence", _DEFAULT_CONF) or _DEFAULT_CONF)
    conf = max(0.0, min(0.99, conf))

    return Template(
        id=tid,
        name=str(info_block.get("name", tid)),
        severity=sev,
        description=str(info_block.get("description", "")),
        tags=[str(t) for t in _as_list(info_block.get("tags"))],
        cwe=str(info_block.get("cwe", "") or ""),
        reference=str(info_block.get("reference", "") or ""),
        confidence=conf,
        requests=requests,
    )


def _match_body(m: dict, body: str, headers: Dict[str, str]) -> bool:
    part = str(m.get("part", "body")).lower()
    if part in ("header", "headers"):
        haystack = "\n".join(f"{k}: {v}" for k, v in headers.items())
    elif part == "all":
        haystack = body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
    else:
        haystack = body
    return _match_text(m, haystack)


def _match_text(m: dict, haystack: str) -> bool:
    mtype = m.get("type", "word")
    condition = str(m.get("condition", "and")).lower()
    negative = bool(m.get("negative", False))
    matched = False
    if mtype == "status":
        matched = int(haystack) in [int(s) for s in _as_list(m.get("status"))]
    elif mtype == "word":
        words = [str(w) for w in _as_list(m.get("words"))]
        if condition == "or":
            matched = any(w in haystack for w in words)
        else:
            matched = all(w in haystack for w in words)
    elif mtype == "regex":
        patterns = [str(r) for r in _as_list(m.get("regex"))]
        if condition == "or":
            matched = any(re.search(p, haystack, re.I | re.M | re.S) for p in patterns)
        else:
            matched = all(re.search(p, haystack, re.I | re.M | re.S) for p in patterns)
    return (not matched) if negative else matched


def _run_request(req: dict, client: KerisHTTP, base: str) -> Optional[dict]:
    """Eksekusi satu request template; kembalikan None bila matcher gagal."""
    method = str(req.get("method", "GET")).upper()
    path = req.get("path", "/")
    url = path if path.startswith(("http://", "https://")) else base.rstrip("/") + path
    headers = req.get("headers") or {}
    try:
        r = client.request(method, url, headers=headers,
                           data=req.get("body"), allow_redirects=False, timeout=20)
    except Exception as e:
        debug(f"Template request gagal {url}: {e}")
        return None

    body = r.text[:20000]
    headers_map = {k.lower(): v for k, v in r.headers.items()}
    cond = str(req.get("matchers-condition", "and")).lower()
    matchers = req.get("matchers", [])
    results = []
    for m in matchers:
        if m.get("type") == "status":
            results.append(int(r.status_code) in [int(s) for s in _as_list(m.get("status"))])
        else:
            results.append(_match_body(m, body, headers_map))
    if cond == "or":
        ok_all = any(results)
    else:
        ok_all = all(results)
    if not ok_all:
        return None

    return {"url": url, "status": r.status_code, "body": body, "headers": headers_map,
            "matched": matchers}


def _extract(req: dict, resp: dict) -> str:
    """Ekstrak bukti dari response via extractors."""
    parts = []
    for ex in req.get("extractors", []):
        ex_type = ex.get("type", "regex")
        if ex_type != "regex":
            continue
        part = str(ex.get("part", "body")).lower()
        haystack = resp["body"]
        if part in ("header", "headers"):
            haystack = "\n".join(f"{k}: {v}" for k, v in resp["headers"].items())
        elif part == "all":
            haystack = resp["body"] + "\n" + "\n".join(f"{k}: {v}" for k, v in resp["headers"].items())
        for pattern in _as_list(ex.get("regex")):
            m = re.search(str(pattern), haystack, re.I | re.M | re.S)
            if m:
                g = ex.get("group", 0)
                parts.append(m.group(int(g)) if m.groups() and g else m.group(0))
                break
    return " | ".join(parts)


def _template_confidence(req: dict) -> float:
    """Skor akurasi berdasarkan tipe matcher yang dipakai template."""
    base = 0.0
    for m in req.get("matchers", []):
        base += _MATCHER_WEIGHT.get(m.get("type", "word"), 0.3)
    n = len(req.get("matchers", []))
    # status+word+regex bersama = sangat akurat
    if base >= 0.9:
        return 0.95
    if base >= 0.6:
        return 0.85
    if base >= 0.45:
        return 0.75
    return 0.65 if n >= 2 else 0.5


def run_template(tpl: Template, client: KerisHTTP, base: str) -> List[Finding]:
    """Jalankan satu template terhadap target. Kembalikan list Finding."""
    findings = []
    for req in tpl.requests:
        resp = _run_request(req, client, base)
        if resp is None:
            continue
        extracted = _extract(req, resp)
        evidence = f"GET {resp['url']} -> {resp['status']}\n"
        if extracted:
            evidence += f"Extracted: {extracted}\n"
        evidence += (resp["body"] or "")[:400]
        conf = max(tpl.confidence, _template_confidence(req))
        fdict = Finding(
            severity=tpl.severity,
            title=tpl.name,
            endpoint=resp["url"],
            detail=tpl.description or f"Template {tpl.id} cocok.",
            evidence=evidence,
            cwe=tpl.cwe,
            references=tpl.reference,
            source=f"template-{tpl.id}",
        ).to_dict()
        fdict["confidence"] = conf
        findings.append(fdict)
    return findings


def load_templates(directory: str = "") -> List[Template]:
    """Muat semua template .yaml/.yml dari direktori."""
    directory = directory or TEMPLATE_DIR
    templates = []
    if not os.path.isdir(directory):
        warn(f"Direktori template tidak ada: {directory}")
        return templates
    for fname in sorted(os.listdir(directory)):
        if not (fname.endswith(".yaml") or fname.endswith(".yml")):
            continue
        path = os.path.join(directory, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                raise TemplateError(f"{fname}: root harus object")
            tpl = parse_template(data)
            templates.append(tpl)
            debug(f"Template dimuat: {tpl.id}")
        except Exception as e:
            warn(f"Gagal memuat template {path}: {e}")
    return templates


def run_templates(templates: List[Template], client: KerisHTTP, base: str) -> List[Finding]:
    """Jalankan semua template terhadap target."""
    findings = []
    for tpl in templates:
        try:
            found = run_template(tpl, client, base)
            for f in found:
                findings.append(f)
            if found:
                ok(f"Template {tpl.id}: {len(found)} temuan")
        except Exception as e:
            error(f"Template {tpl.id} gagal: {e}")
    return findings