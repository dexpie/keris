"""ReporterAgent: pembuat laporan akhir agent (markdown + JSON)."""

from typing import Any, Dict, List

from keris.agents.base import BaseAgent

_SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


class ReporterAgent(BaseAgent):
    """Fase akhir: tulis agent-report.md dan agent-findings.json.

    Hook `render(findings, recon, notes) -> str` untuk konten markdown.
    Default menghasilkan laporan markdown sederhana.
    """

    name = "reporter"
    role = "Menyusun laporan akhir agent."

    def _sev_label(self, sev: str) -> str:
        s = str(sev or "LOW").upper()
        return s if s in _SEV_ORDER else "LOW"

    def _default_render(self, findings: List[Dict[str, Any]],
                        recon: Dict[str, Any],
                        notes: List[Dict[str, Any]]) -> str:
        target = self.memory.get("target", "")
        goal = self.memory.get("goal", "full-pentest")
        lines = [f"# Agent Report - {target}", ""]
        lines.append(f"**Goal:** {goal}")
        lines.append(f"**Target:** `{target}`")
        lines.append(f"**Temuan:** {len(findings)}")
        lines.append("")
        lines.append("## Temuan")
        lines.append("")
        if not findings:
            lines.append("Tidak ada temuan signifikan.")
        for i, f in enumerate(findings, 1):
            sev = self._sev_label(str(f.get("severity") or "LOW"))
            lines.append(f"{i}. **[{sev}]** {f.get('title', '')}")
            if f.get("endpoint"):
                lines.append(f"   - Endpoint: `{f['endpoint']}`")
            if f.get("description"):
                lines.append(f"   - Deskripsi: {f['description']}")
        lines.append("")
        lines.append("## Catatan Agent")
        lines.append("")
        for n in notes:
            lines.append(f"- [{n.get('agent', '?')}] {n.get('msg', '')}")
        return "\n".join(lines)

    def run(self) -> Dict[str, Any]:
        findings = self.memory.get("validated", [])
        exploited = self.memory.get("exploited", [])
        recon = self.memory.get("recon", {})
        notes = self.memory.get("notes", [])
        self.memory.status(self.name, "running")
        self.log(f"Susun laporan: {len(findings)} temuan, "
                 f"{len(exploited)} dieksploitasi")

        md = self.run_hook("render", findings, recon, notes)
        report_path = self.hooks.get("report_path") or "agent-report.md"
        findings_path = self.hooks.get("findings_path") or "agent-findings.json"
        self._write(str(report_path), md)
        self._write_findings(str(findings_path), findings, exploited, recon)
        self.memory.status(self.name, "done")
        return {"agent": self.name, "report": report_path,
                "findings_file": findings_path}

    def _write(self, path: str, content: str) -> None:
        import os

        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def _write_findings(self, path: str, findings: List[Dict[str, Any]],
                        exploited: List[Dict[str, Any]],
                        recon: Dict[str, Any]) -> None:
        import json
        import os

        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        payload = {
            "target": self.memory.get("target", ""),
            "goal": self.memory.get("goal", "full-pentest"),
            "recon": recon,
            "findings": findings,
            "exploited": exploited,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)