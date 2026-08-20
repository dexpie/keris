"""ScannerAgent: pemindai kerentanan di setiap endpoint yang ditemukan."""

from typing import Any, Dict, List

from keris.agents.base import BaseAgent


class ScannerAgent(BaseAgent):
    """Fase scanning: uji endpoint untuk kerentanan web umum.

    Hook `scan_endpoint(endpoint) -> List[dict]` dipanggil per endpoint.
    Default tanpa network mengembalikan [] agar aman saat testing.
    """

    name = "scanner"
    role = "Memindai endpoint untuk kerentanan (SQLi, XSS, IDOR, header, ...)."

    def _default_scan_endpoint(self, endpoint: str) -> List[Dict[str, Any]]:
        return []

    def run(self) -> Dict[str, Any]:
        endpoints = self.memory.get("endpoints", [])
        self.log(f"Scan {len(endpoints)} endpoint")
        self.memory.status(self.name, "running")
        findings: List[Dict[str, Any]] = []
        for ep in endpoints:
            self.log(f"  scan {ep}")
            res = self.run_hook("scan_endpoint", ep) or []
            for f in res:
                if isinstance(f, dict):
                    findings.append(f)
        self.memory.extend("findings", findings)
        self.log(f"Scanner selesai: {len(findings)} temuan")
        self.memory.status(self.name, "done")
        return {"agent": self.name, "scanned": len(endpoints),
                "findings": findings}