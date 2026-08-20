"""SharedMemory: state bersama antar agent (thread-safe).

Semua agent membaca/menulis data melalui objek ini sehingga hasil satu agent
dapat dipakai agent lain (mis. ScannerAgent memakai endpoint dari ReconAgent).
"""

import json
import threading
from typing import Any, Dict, List, Optional


class SharedMemory:
    """Kantong data bersama untuk satu misi pentest (multi-agent)."""

    def __init__(self, target: str = "", goal: str = "full-pentest"):
        self._lock = threading.RLock()
        self.data: Dict[str, Any] = {
            "target": target,
            "goal": goal,
            "recon": {},              # hasil recon (stack, headers, dns, ...)
            "endpoints": [],          # daftar endpoint/url yang ditemukan
            "findings": [],           # temuan mentah dari scanner/exploiter
            "validated": [],          # temuan setelah ValidatorAgent
            "exploited": [],          # temuan yang berhasil dieksploitasi
            "notes": [],              # catatan log antar agent
            "status": {},             # status tiap agent: running/done/skipped
            "started": 0,             # timestamp mulai
        }

    # -- akses data ---------------------------------------------------------
    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self.data[key] = value

    def append(self, key: str, item: Any) -> None:
        with self._lock:
            self.data.setdefault(key, []).append(item)

    def extend(self, key: str, items: List[Any]) -> None:
        with self._lock:
            self.data.setdefault(key, []).extend(items or [])

    def note(self, agent: str, msg: str) -> None:
        """Tulis catatan log dari agent tertentu."""
        with self._lock:
            self.data.setdefault("notes", []).append(
                {"agent": agent, "msg": msg})

    def status(self, agent: str, value: str) -> None:
        with self._lock:
            self.data.setdefault("status", {})[agent] = value

    # -- serialisasi --------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self.data, default=str))

    def save(self, path: str) -> None:
        with self._lock:
            payload = json.loads(json.dumps(self.data, default=str))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)

    def load(self, path: str) -> "SharedMemory":
        try:
            with open(path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                with self._lock:
                    for k, v in loaded.items():
                        if k in self.data and isinstance(self.data[k], dict) and isinstance(v, dict):
                            self.data[k].update(v)
                        else:
                            self.data[k] = v
        except (OSError, json.JSONDecodeError):
            pass
        return self