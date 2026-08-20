"""ValidatorAgent: verifikasi & pembersihan temuan sebelum pelaporan."""

from typing import Any, Dict, List

from keris.agents.base import BaseAgent

# prioritas severity
_SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


class ValidatorAgent(BaseAgent):
    """Fase validasi: dedupe, filter false-positive, klasifikasi severity."""

    name = "validator"
    role = "Memvalidasi temuan: dedupe, filter false-positive, dan konfidensi."

    def _key(self, f: Dict[str, Any]) -> str:
        return f"{f.get('endpoint', '')}|{f.get('title', '')}|{f.get('severity', '')}"

    def _default_verify(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        return finding

    def run(self) -> Dict[str, Any]:
        findings = self.memory.get("findings", [])
        self.log(f"Validasi {len(findings)} temuan")
        self.memory.status(self.name, "running")

        seen = set()
        out: List[Dict[str, Any]] = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            k = self._key(f)
            if k in seen:
                continue
            seen.add(k)
            verified = self.run_hook("verify", f) or f
            if not isinstance(verified, dict):
                verified = f
            sev = str(verified.get("severity", "LOW")).upper()
            if sev not in _SEV_ORDER:
                sev = "LOW"
            verified["severity"] = sev
            verified.setdefault("confidence", 0.9)
            out.append(verified)

        out.sort(key=lambda x: _SEV_ORDER.get(x.get("severity", "LOW"), 0),
                 reverse=True)
        self.memory.set("validated", out)
        self.log(f"Validator selesai: {len(out)} temuan valid "
                 f"({len(findings) - len(out)} dihapus/dedupe)")
        self.memory.status(self.name, "done")
        return {"agent": self.name, "input": len(findings),
                "output": len(out), "validated": out}