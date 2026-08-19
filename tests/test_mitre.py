"""Tes v0.18.0: MITRE ATT&CK integration untuk attack chains."""

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
        {"id": "f2", "title": "Kredensial admin bocor di .git",
         "detail": ".git config berisi password", "endpoint": "https://x.com/.git/config",
         "severity": "MEDIUM", "type": "git-leak", "evidence": "password=admin123"},
        {"id": "f3", "title": "Admin panel login lemah",
         "detail": "default creds admin/admin", "endpoint": "https://x.com/admin",
         "severity": "MEDIUM", "type": "weak-login", "evidence": "login 200"},
        {"id": "f4", "title": "Remote Code Execution di /cmd",
         "detail": "command injection via ping", "endpoint": "https://x.com/cmd",
         "severity": "CRITICAL", "type": "rce", "evidence": "uid=0"},
    ]


class TestMapper:
    def test_map_by_tag(self):
        from keris.modules.mitre import MitreAttackMapper, TACTICS

        m = MitreAttackMapper()
        assert m.map_tags(["sqli"]) == "T1190"
        assert m.map_tags(["rce"]) == "T1059"
        assert m.map_tags(["git-leak"]) == "T1552.001"
        assert m.map_tags(["none"]) is None
        assert TACTICS[0] == "Reconnaissance"
        assert TACTICS[-1] == "Impact"

    def test_map_finding_by_type(self):
        from keris.modules.mitre import MitreAttackMapper

        m = MitreAttackMapper()
        d = m.map_finding({"type": "sql-injection", "severity": "HIGH"})
        assert d["id"] == "T1190"
        assert d["tactic"] == "Initial Access"
        d2 = m.map_finding({"type": "unknown-thing", "severity": "CRITICAL"})
        assert d2["id"] == "T1486"

    def test_tactic_rank(self):
        from keris.modules.mitre import TACTIC_RANK

        assert TACTIC_RANK["Initial Access"] < TACTIC_RANK["Credential Access"]
        assert TACTIC_RANK["Credential Access"] < TACTIC_RANK["Impact"]


class TestAnnotate:
    def test_annotate_paths(self):
        from keris.modules.correlation import build_paths, set_path_depth
        from keris.modules.mitre import annotate_paths, build_mitre_chains

        set_path_depth(3)
        paths = build_paths(_findings(), path_depth=3)
        assert paths, "harus ada minimal satu path"
        mitre_paths = annotate_paths(paths)
        chains = build_mitre_chains(mitre_paths)
        assert chains
        top = chains[0]
        assert top["technique_summary"]
        assert any("T1190" in t for t in top["techniques"])
        assert top["tactics"], "tactic progression tidak boleh kosong"
        # tiap step harus punya anotasi mitre
        for s in top["steps"]:
            assert s.get("mitre"), "step harus punya mitre"
            assert s["mitre"].get("id")

    def test_mitre_markdown(self):
        from keris.modules.correlation import build_paths
        from keris.modules.mitre import annotate_paths, build_mitre_chains, mitre_markdown

        paths = build_paths(_findings(), path_depth=3)
        chains = build_mitre_chains(annotate_paths(paths))
        md = mitre_markdown(chains)
        joined = "\n".join(md)
        assert "Attack Paths (MITRE ATT&CK)" in joined
        assert "Tactic Progression" in joined
        assert "T1190" in joined

    def test_render_mitre_dot(self):
        from keris.modules.correlation import build_paths
        from keris.modules.mitre import annotate_paths, render_mitre_dot

        paths = build_paths(_findings(), path_depth=3)
        dot = render_mitre_dot(annotate_paths(paths), "https://x.com")
        assert dot.startswith("digraph")
        assert "T1190" in dot


class TestCli:
    def test_chain_subcommand_markdown(self, tmp_path):
        scan_file = tmp_path / "scan.json"
        with open(scan_file, "w", encoding="utf-8") as f:
            json.dump({"target": "https://x.com", "findings": _findings()}, f)
        out = tmp_path / "paths.md"
        r = subprocess.run(
            [sys.executable, "-m", "keris", "chain", "--from-scan", str(scan_file),
             "--mitre", "--output", str(out)],
            capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        text = out.read_text(encoding="utf-8")
        assert "Attack Paths" in text
        assert "T1190" in text

    def test_chain_subcommand_dot(self, tmp_path):
        scan_file = tmp_path / "scan.json"
        with open(scan_file, "w", encoding="utf-8") as f:
            json.dump({"target": "https://x.com", "findings": _findings()}, f)
        dot = tmp_path / "graph.dot"
        r = subprocess.run(
            [sys.executable, "-m", "keris", "chain", "--from-scan", str(scan_file),
             "--mitre", "--graph-only", "--dot-output", str(dot)],
            capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        assert dot.exists()

    def test_chain_requires_scan_file(self):
        r = subprocess.run([sys.executable, "-m", "keris", "chain"],
                           capture_output=True, text=True)
        assert r.returncode != 0
        assert "from-scan" in r.stdout

    def test_scan_mitre_wiring(self, tmp_path):
        """--mitre tersedia di parser scan dan _write_json_output menyertakan mitre."""
        from keris.cli.common import _parse_args, _write_json_output

        args = _parse_args(["scan", "https://x.com", "--chain", "--mitre",
                            "--json-output", "out.json"])
        assert getattr(args, "mitre", False) is True
        assert getattr(args, "chain", False) is True

        out = str(tmp_path / "scan.json")
        from keris.modules.correlation import build_paths
        from keris.modules.mitre import annotate_paths, build_mitre_chains

        paths = build_paths(_findings(), path_depth=3)
        mitre_paths = annotate_paths(paths)
        chains = build_mitre_chains(mitre_paths)
        _write_json_output("https://x.com", _findings(), {}, {},
                           out, mitre_chains=chains,
                           attack_paths=mitre_paths)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        assert "attack_paths" in data
        assert data["mitre"]["chains"]
        # attack paths harus beranotasi mitre
        assert any("mitre" in s
                   for p in data["attack_paths"] for s in p.get("steps", []))