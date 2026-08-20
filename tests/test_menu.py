"""Tests untuk keris menu interaktif (keris/cli/menu.py)."""

from keris.cli import menu


def test_menu_tool_count():
    assert len(menu.TOOLS) == 13


def test_menu_build_scan():
    tool = menu.TOOLS[0]
    assert tool["need"] == "target"
    assert tool["build"]("https://example.com") == ["scan", "https://example.com"]


def test_menu_build_subdomain():
    tool = menu.TOOLS[5]
    assert tool["build"]("example.com") == ["subdomain", "example.com"]


def test_menu_build_sast_url():
    tool = menu.TOOLS[10]
    assert tool["build"]("https://example.com") == ["sast", "https://example.com"]


def test_menu_build_sast_dir():
    tool = menu.TOOLS[10]
    assert tool["build"]("./src") == ["sast", "--dir", "./src"]


def test_menu_build_sast_empty():
    tool = menu.TOOLS[10]
    assert tool["build"]("") == ["sast"]


def test_menu_build_toolbox():
    tool = menu.TOOLS[11]
    assert tool["build"]("hash") == ["toolbox", "--tool", "hash"]
    assert tool["build"]("") == ["toolbox", "--tool", "list"]


def test_menu_active_tool_requires_confirmation():
    tool = menu.TOOLS[12]
    assert tool.get("active") is True
    assert tool["build"]("https://example.com") == [
        "dos", "https://example.com", "--yes", "--authorized",
    ]