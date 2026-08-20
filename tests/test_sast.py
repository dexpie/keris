"""Tests untuk SAST client-side (keris/modules/sast.py)."""

import json
import os

import pytest

from keris.modules import sast as sast_mod
from keris.modules.sast import (analyze_source, build_sbom, check_cve_for,
                                check_dependencies, extract_dependencies,
                                sbom_markdown)
from keris.cli import common


# ---------------------------------------------------------------------------
# analyze_source
# ---------------------------------------------------------------------------

def test_analyze_source_eval_high():
    findings = analyze_source("function go() { return eval(userInput); }", "app.js")
    titles = [f.title for f in findings]
    assert any("eval" in t.lower() for t in titles)
    assert all(f.severity == "HIGH" for f in findings if "eval" in f.title)


def test_analyze_source_sqli():
    findings = analyze_source('query = "SELECT * FROM users WHERE id=" + uid', "db.py")
    assert any("SQL" in f.title for f in findings)


def test_analyze_source_clear_text():
    assert analyze_source("x = 1 + 2", "safe.py") == []


def test_analyze_source_multi_sinks_dedup():
    findings = analyze_source("eval(a); eval(b); innerHTML=c;", "app.js")
    # satu temuan per jenis sink (dedup berdasarkan title)
    evals = [f for f in findings if "eval" in f.title]
    assert len(evals) == 1


def test_analyze_source_secret_detected():
    findings = analyze_source("api_key = \"sk-abcdef0123456789ghij\"", "conf.py")
    assert any("redensial" in f.title or "Secret" in f.title or "kredensial" in f.title
               for f in findings)


# ---------------------------------------------------------------------------
# dependency CVE
# ---------------------------------------------------------------------------

def test_check_cve_for_vulnerable():
    hit = check_cve_for("lodash", "4.17.10")
    assert hit is not None
    assert hit[0] == "HIGH"


def test_check_cve_for_safe():
    assert check_cve_for("lodash", "4.17.21") is None
    assert check_cve_for("unknown-pkg", "1.0.0") is None


def test_check_cve_for_scoped_name():
    assert check_cve_for("@scope/lodash", "4.17.10") is None  # nama dasar tak cocok di sini
    hit = check_cve_for("next", "13.0.0")
    assert hit and hit[0] == "HIGH"


def test_check_dependencies_findings():
    findings = check_dependencies({"lodash": "4.17.10", "axios": "0.20.0"})
    titles = [f.title for f in findings]
    assert any("lodash" in t for t in titles)
    assert any("axios" in t for t in titles)


def test_cve_db_has_many_entries():
    assert len(sast_mod.CVE_DB) >= 25


# ---------------------------------------------------------------------------
# extract_dependencies / SBOM
# ---------------------------------------------------------------------------

def test_extract_dependencies_json():
    text = '{"dependencies": {"lodash": "4.17.10", "axios": "^0.21.0"}}'
    pkgs = extract_dependencies(text, "package.json")
    assert pkgs["lodash"] == "4.17.10"
    assert "axios" in pkgs


def test_extract_dependencies_requirements():
    text = "flask==2.0.0\nrequests==2.31.0\n# comment\n"
    pkgs = extract_dependencies(text, "requirements.txt")
    assert pkgs["flask"] == "2.0.0"
    assert pkgs["requests"] == "2.31.0"
    assert len(pkgs) == 2


def test_build_sbom_cyclonedx():
    sbom = build_sbom({"flask": "2.0.0"}, target="demo")
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.4"
    assert sbom["components"][0]["name"] == "flask"
    assert sbom["components"][0]["purl"].startswith("pkg:pypi/")


def test_sbom_markdown_table():
    sbom = build_sbom({"flask": "2.0.0"}, target="demo")
    md = sbom_markdown(sbom)
    assert "SBOM" in md
    assert "| flask | 2.0.0" in md
    assert "Total dependency" in md and "1" in md


# ---------------------------------------------------------------------------
# analyze_directory
# ---------------------------------------------------------------------------

def test_analyze_directory_walks(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\nos.system(user_input)\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"lodash": "4.17.10"}}', encoding="utf-8")
    res = sast_mod.analyze_directory(str(tmp_path), target="tmp")
    assert res["files_scanned"] == 2
    assert res["dependency_count"] == 1
    assert len(res["findings"]) >= 2  # os.system + lodash CVE


def test_analyze_directory_json_output(tmp_path):
    (tmp_path / "x.js").write_text("eval(a);", encoding="utf-8")
    out = str(tmp_path / "out.json")
    sast_mod.analyze_directory(str(tmp_path), target="tmp", json_output=out)
    assert os.path.exists(out)
    with open(out, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["files_scanned"] == 1


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

def test_sast_parser_registered():
    a = common._parse_args(["sast", "--dir", "src"])
    assert a.command == "sast"
    assert a.dir == "src"


def test_sast_handler_file(capsys, tmp_path):
    import argparse
    from keris.cli.scan import _cmd_sast

    f = tmp_path / "app.py"
    f.write_text("eval(a);", encoding="utf-8")
    args = argparse.Namespace(dir="", file=str(f), json_output="",
                              sbom_out="", max_assets=15,
                              targets=[], target=None,
                              exit_on="high", json_output2="")
    rc = _cmd_sast(args, None, None)
    out = capsys.readouterr().out
    assert rc in (0, 1)  # finding HIGH -> EXIT_FINDINGS=1
    assert "SBOM" in out


def test_sast_handler_missing_file(capsys):
    import argparse
    from keris.cli.scan import _cmd_sast

    args = argparse.Namespace(dir="", file="no-such-file.py", json_output="",
                              sbom_out="", max_assets=15,
                              targets=[], target=None, exit_on="high")
    rc = _cmd_sast(args, None, None)
    assert rc != 0