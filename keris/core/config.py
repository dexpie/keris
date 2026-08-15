"""Muat konfigurasi Keris dari file dan CLI.

Prioritas nilai: CLI flag > config file > default.
Konfigurasi dibaca dari:
  1. `keris.json` di direktori saat ini
  2. Path via --config
  3. default bawaan
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any

DEFAULT_CONFIG = {
    "proxy": None,
    "timeout": 20.0,
    "retries": 1,
    "workers": 10,
    "delay": 0.0,
    "max_assets": 15,
    "insecure": False,
    "quiet": False,
    "token": None,
    "cookie": None,
    "username": None,
    "password": None,
    "headers": {},
    "plugins_dir": "plugins",
    "templates_dir": "",
    "login_paths": ["/login", "/signin", "/auth", "/account/login"],
    "findings": {},
}


@dataclass
class KerisConfig:
    proxy: Optional[str] = None
    timeout: float = 20.0
    retries: int = 1
    workers: int = 10
    delay: float = 0.0
    max_assets: int = 15
    insecure: bool = False
    quiet: bool = False
    token: Optional[str] = None
    cookie: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    plugins_dir: str = "plugins"
    templates_dir: str = ""
    login_paths: List[str] = field(default_factory=list)
    findings: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "KerisConfig":
        data = {}
        candidates = []
        if path:
            candidates.append(path)
        else:
            candidates.append("keris.json")
            candidates.append(os.path.join(os.path.expanduser("~"), ".config", "keris", "keris.json"))

        for cand in candidates:
            if os.path.exists(cand):
                try:
                    with open(cand, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    break
                except (json.JSONDecodeError, OSError):
                    pass

        merged = {k: data.get(k, v) for k, v in DEFAULT_CONFIG.items()}
        cfg = cls(**{k: v for k, v in merged.items() if k in cls.__dataclass_fields__})
        cfg.findings = data.get("findings", {})
        cfg.plugins_dir = data.get("plugins_dir", cfg.plugins_dir)
        cfg.templates_dir = data.get("templates_dir", cfg.templates_dir)
        cfg.login_paths = data.get("login_paths", cfg.login_paths)
        return cfg

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("headers", None)
        return d


def save_example_config(path: str = "keris.json.example") -> str:
    """Tulis contoh keris.json.example untuk dokumentasi."""
    example = {
        "proxy": "http://127.0.0.1:8080",
        "timeout": 20.0,
        "retries": 1,
        "workers": 10,
        "delay": 0.2,
        "max_assets": 15,
        "insecure": False,
        "quiet": False,
        "token": "Bearer-token-opsional",
        "cookie": "session=abc123",
        "username": None,
        "password": None,
        "headers": {"X-Custom": "value"},
        "plugins_dir": "plugins",
        "login_paths": ["/login", "/signin", "/auth", "/account/login"],
        "findings": {
            # override nilai minimum severity yang dianggap temuan penting
            "exit_codes": {"critical": 1, "high": 1},
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(example, f, indent=2)
    return path
