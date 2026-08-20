"""Tests untuk keris menu interaktif (keris/cli/menu.py)."""

from keris.cli import menu


def test_menu_tool_count():
    assert len(menu.TOOLS) == 14


def test_menu_build_scan():
    tool = menu.TOOLS[0]
    assert tool["need"] == "target"
    assert tool["build"]("https://example.com") == ["scan", "https://example.com"]


def test_menu_build_subdomain():
    tool = menu.TOOLS[5]
    assert tool["build"]("example.com") == ["subdomain", "example.com"]


def test_menu_http_multi():
    tool = menu.TOOLS[9]
    assert tool["build"]("https://a.com https://b.com") == [
        "http", "https://a.com", "https://b.com",
    ]


def test_menu_build_sast_url():
    tool = menu.TOOLS[11]
    assert tool["build"]("https://example.com") == ["sast", "https://example.com"]


def test_menu_build_sast_dir():
    tool = menu.TOOLS[11]
    assert tool["build"]("./src") == ["sast", "--dir", "./src"]


def test_menu_build_sast_empty():
    tool = menu.TOOLS[11]
    assert tool["build"]("") == ["sast"]


def test_menu_build_toolbox():
    tool = menu.TOOLS[12]
    assert tool["build"]("hash") == ["toolbox", "--tool", "hash"]
    assert tool["build"]("") == ["toolbox", "--tool", "list"]


def test_menu_active_tool_requires_confirmation():
    tool = menu.TOOLS[13]
    assert tool.get("active") is True
    assert tool["build"]("https://example.com") == [
        "dos", "https://example.com", "--yes", "--authorized",
    ]


def test_autopilot_steps_aliases():
    names = [s.get("alias") for s in menu.AUTOPILOT_STEPS]
    assert names == ["recon", "discover", "fuzz", "hunt", "scan"]


def test_autopilot_build_scan():
    step = menu.AUTOPILOT_STEPS[4]
    argv = step["build"]("https://example.com")
    assert argv[0] == "scan"
    assert "https://example.com" in argv
    assert "--chain" in argv


def test_autopilot_collect(tmp_path):
    import json

    f = tmp_path / "r.json"
    f.write_text(json.dumps({"findings": [{"severity": "HIGH", "title": "x"}]}), encoding="utf-8")
    assert menu._autopilot_collect([str(f)]) == [{"severity": "HIGH", "title": "x"}]
    assert menu._autopilot_collect(["nope.json"]) == []