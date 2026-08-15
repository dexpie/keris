"""Export temuan Keris ke format SARIF 2.1.0.

SARIF (Static Analysis Results Interchange Format) dipakai GitHub Code
Scanning, GitHub Actions, dan banyak alat keamanan. Setiap temuan menjadi
`result` dengan ruleId berdasarkan CWE/kategori, severity dipetakan ke
level (error/warning/note/none).
"""

import json
import re
from datetime import datetime
from typing import Dict, List

from keris import __version__
from keris.cvss import classify

SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}


def _rule_id(f: Dict) -> str:
    cwe = str(f.get("cwe", "") or "")
    if cwe:
        return cwe
    title = str(f.get("title", "") or "")
    slug = re.sub(r"[^A-Za-z0-9]+", "-", title.lower()).strip("-")
    return slug[:60] or "keris-finding"


def _rule_index(rules: List[Dict], rule_id: str) -> int:
    for i, r in enumerate(rules):
        if r["id"] == rule_id:
            return i
    rules.append({"id": rule_id, "name": rule_id,
                  "shortDescription": {"text": rule_id}})
    return len(rules) - 1


def build_sarif(findings: List[Dict], target: str, tool_version: str = "") -> Dict:
    """Bangun dokumen SARIF 2.1.0 dari daftar temuan."""
    rules: List[Dict] = []
    results = []

    for f in findings:
        rule_id = _rule_id(f)
        ridx = _rule_index(rules, rule_id)
        sev = str(f.get("severity", "INFO")).upper()
        level = SEVERITY_TO_LEVEL.get(sev, "warning")
        cvss = classify(f.get("title", ""), sev)

        artifact_uri = f.get("endpoint", target)
        region = None
        match = re.search(r"line[=:]?\s*(\d+)", str(f.get("evidence", "")), re.I)
        if match:
            region = {"startLine": int(match.group(1))}

        msg = f.get("detail", "") or f.get("title", "")
        r = {
            "ruleId": rule_id,
            "ruleIndex": ridx,
            "level": level,
            "message": {"text": str(msg)[:2000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri, "uriBaseId": "SRCROOT"},
                    **({"region": region} if region else {}),
                }
            }],
            "properties": {
                "severity": sev,
                "confidence": float(f.get("confidence", 0.5)),
                "confidenceLabel": f.get("confidence_label", ""),
                "cvssScore": cvss["score"],
                "owasp": f"{cvss['owasp_code']} {cvss['owasp_name']}",
                "source": f.get("source", ""),
                "id": f.get("id", ""),
            },
        }
        if f.get("evidence"):
            r["partialFingerprints"] = {"kerisId": f.get("id", "")}
        results.append(r)

    run = {
        "tool": {
            "driver": {
                "name": "Keris",
                "semanticVersion": tool_version or __version__,
                "informationUri": "https://github.com/dexpie/keris",
                "rules": rules,
            }
        },
        "automationDetails": {
            "id": "keris/scan",
            "guid": "89a3e5c1-keris-sarif-0001",
        },
        "invocations": [{
            "executionSuccessful": True,
            "endTimeUtc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        }],
        "results": results,
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def sarif_to_string(findings: List[Dict], target: str) -> str:
    return json.dumps(build_sarif(findings, target), indent=2)


def write_sarif(findings: List[Dict], target: str, path: str) -> str:
    """Tulis laporan SARIF ke file. Mengembalikan path."""
    import os

    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(sarif_to_string(findings, target))
    return path