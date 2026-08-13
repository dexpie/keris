"""Logging berwarna dan helper output untuk Keris."""

import sys
import threading
from datetime import datetime

# pastikan stdout bisa menampilkan karakter unicode (cp1252 di Windows)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(errors="replace")
    except Exception:
        pass

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
DIM = "\033[2m"

_lock = threading.Lock()
_quiet = False
_color_enabled = True


def set_quiet(q: bool) -> None:
    global _quiet
    _quiet = q


def disable_color() -> None:
    global _color_enabled
    _color_enabled = False


def _write(line: str) -> None:
    with _lock:
        if not _quiet:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()


def _color(text: str, color: str) -> str:
    if _quiet or not _color_enabled:
        return text
    return f"{color}{text}{RESET}"


def _sym(s: str) -> str:
    """Ganti simbol unicode dengan ASCII bila console tidak support."""
    try:
        s.encode(sys.stdout.encoding or "utf-8")
        return s
    except (UnicodeEncodeError, LookupError):
        return {"✓": "+", "✘": "x", "x": "x", "!": "!"}.get(s, s)


def info(msg: str) -> None:
    _write(f"[{_color('+', GREEN)}] {msg}")


def ok(msg: str) -> None:
    _write(f"[{_color(_sym('✓'), GREEN)}] {msg}")


def warn(msg: str) -> None:
    _write(f"[{_color(_sym('!'), YELLOW)}] {msg}")


def error(msg: str) -> None:
    _write(f"[{_color(_sym('x'), RED)}] {msg}")


def debug(msg: str) -> None:
    _write(f"[{_color(_sym('i'), BLUE)}] {msg}")


def severity(level: str, msg: str) -> None:
    _write(f"[{_color(level, BOLD)}] {msg}")


def timestamp() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
