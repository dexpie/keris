"""Tes v0.19.0: Professional reporting (template + finding template)."""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _findings():
    return [
        {"id": "f1", "title": "SQL Injection di /api/users",
         "detail": "UNION-based SQLi", "endpoint": "https://x.com/api/users",
         "severity": "HIGH", "type": "sql-injection", "evidence": "error in query"},
        {"id": "f2", "title": "Reflected XSS di /search",
         "detail": "refleksi payload", "endpoint": "https://x.com/search",
         "severity": "MEDIUM", "type": "xss", "evidence": "<script>"},
    ]


def _scan_data():
    return {"target": "https://x.com", "findings": _findings(),
            "recon": {"host": "x.com", "ips": ["1.2.3.4"]},
            "discovery": {"api_endpoints": ["/api/users"]}}


class TestFindingTemplates:
    def test_detect(self):
        from keris.modules.reporting import detect_finding_template

        assert detect_finding_template({"title": "SQL Injection found"}) == "sql_injection"
        assert detect_finding_template({"title": "Reflected XSS"}) == "xss"
        assert detect_finding_template({"title": "Random title"}) is None

    def test_apply_fills_gaps(self):
        from keris.modules.reporting import apply_finding_templates

        out = apply_finding_templates([{"title": "SQL Injection di /x",
                                        "endpoint": "/x", "severity": "HIGH"}])
        f = out[0]
        assert f["template_id"] == "sql_injection"
        assert f["remediation"]
        assert f["references"]
        assert "CWE-89" in f["references"]

    def test_apply_keeps_existing(self):
        from keris.modules.reporting import apply_finding_templates

        out = apply_finding_templates([{"title": "XSS", "remediation": "custom",
                                        "endpoint": "/", "severity": "LOW"}])
        assert out[0]["remediation"] == "custom"


class TestReportGenerator:
    def test_standard_sections(self):
        from keris.modules.reporting import ReportGenerator

        md = ReportGenerator(template="standard").generate(
            "https://x.com", {"host": "x.com"}, {}, _findings())
        assert "Ringkasan Eksekutif" in md
        assert "Lingkup Pengujian" in md
        assert "Detail Temuan" in md
        assert "SQL Injection" in md
        assert "Reflected XSS" in md

    def test_executive_only(self):
        from keris.modules.reporting import ReportGenerator

        md = ReportGenerator(template="standard",
                             options={"executive_only": True}).generate(
            "https://x.com", {}, {}, _findings())
        assert "Ringkasan Eksekutif" in md
        assert "Detail Temuan" not in md

    def test_compliance_owasp(self):
        from keris.modules.reporting import ReportGenerator, apply_finding_templates

        findings = apply_finding_templates(_findings())
        md = ReportGenerator(template="owasp").generate(
            "https://x.com", {}, {}, findings)
        assert "OWASP Top 10" in md
        assert "A03" in md

    def test_compliance_pci_hipaa(self):
        from keris.modules.reporting import (ReportGenerator,
                                             apply_finding_templates)

        findings = apply_finding_templates(_findings())
        pci = ReportGenerator(template="pci").generate(
            "https://x.com", {}, {}, findings)
        assert "PCI DSS" in pci
        hipaa = ReportGenerator(template="hipaa").generate(
            "https://x.com", {}, {}, findings)
        assert "HIPAA" in hipaa

    def test_ctf_template(self):
        from keris.modules.reporting import ReportGenerator

        md = ReportGenerator(template="ctf",
                             options={"flags": ["flag{test}"],
                                      "screenshots": []}).generate(
            "https://x.com", {}, {}, [])
        assert "Walkthrough" in md
        assert "flag{test}" in md

    def test_render_from_scan(self):
        from keris.modules.reporting import render_report_from_scan

        md = render_report_from_scan(_scan_data(), template="standard")
        assert "https://x.com" in md
        assert "SQL Injection" in md


class TestCli:
    def test_report_md(self, tmp_path):
        scan_file = tmp_path / "scan.json"
        with open(scan_file, "w", encoding="utf-8") as f:
            json.dump(_scan_data(), f)
        out = tmp_path / "report.md"
        r = subprocess.run(
            [sys.executable, "-m", "keris", "report", "--from-scan", str(scan_file),
             "--output", str(out), "--template", "owasp"],
            capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
        md = out.read_text(encoding="utf-8")
        assert "OWASP" in md
        assert "SQL Injection" in md

    def test_report_pdf(self, tmp_path):
        scan_file = tmp_path / "scan.json"
        with open(scan_file, "w", encoding="utf-8") as f:
            json.dump(_scan_data(), f)
        out = tmp_path / "report.pdf"
        r = subprocess.run(
            [sys.executable, "-m", "keris", "report", "--from-scan", str(scan_file),
             "--format", "pdf", "--output", str(out)],
            capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
        assert out.exists() and out.stat().st_size > 1000
        assert out.read_bytes()[:4] == b"%PDF"

    def test_report_batch(self, tmp_path):
        d = tmp_path / "scans"
        d.mkdir()
        for name in ("a.json", "b.json"):
            with open(d / name, "w", encoding="utf-8") as f:
                json.dump(_scan_data(), f)
        out_dir = tmp_path / "reports"
        r = subprocess.run(
            [sys.executable, "-m", "keris", "report", "--from-dir", str(d),
             "--out-dir", str(out_dir), "--format", "md"],
            capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
        assert (out_dir / "a.md").exists()
        assert (out_dir / "b.md").exists()

    def test_report_requires_input(self):
        r = subprocess.run([sys.executable, "-m", "keris", "report"],
                           capture_output=True, text=True)
        assert r.returncode != 0
        assert "from-scan" in r.stdout

    def test_report_pdf_with_attack_paths(self, tmp_path):
        from keris.modules.correlation import build_paths
        from keris.modules.mitre import annotate_paths, build_mitre_chains

        data = _scan_data()
        paths = build_paths(_findings(), path_depth=3)
        mitre_paths = annotate_paths(paths)
        data["attack_paths"] = mitre_paths
        data["mitre"] = {"chains": build_mitre_chains(mitre_paths)}
        scan_file = tmp_path / "scan.json"
        with open(scan_file, "w", encoding="utf-8") as f:
            json.dump(data, f)
        out = tmp_path / "report.pdf"
        r = subprocess.run(
            [sys.executable, "-m", "keris", "report", "--from-scan", str(scan_file),
             "--format", "pdf", "--output", str(out)],
            capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
        assert out.read_bytes()[:4] == b"%PDF"