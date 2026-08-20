"""BaseAgent: fondasi semua agent dalam framework multi-agent."""

from typing import Any, Dict, Optional

from keris.agents.memory import SharedMemory
from keris.core.logger import debug, info, warn


class BaseAgent:
    """Agent dasar: nama, peran, memory bersama, hook fungsi modul.

    `hooks` memungkinkan injeksi fungsi untuk testing (tanpa network) dan
    override perilaku default.
    """

    name = "base"
    role = ""

    def __init__(self, memory: Optional[SharedMemory] = None,
                 hooks: Optional[Dict[str, Any]] = None,
                 authorized: bool = False, verbose: bool = False):
        self.memory = memory or SharedMemory()
        self.hooks = hooks or {}
        self.authorized = authorized
        self.verbose = verbose

    # -- util ---------------------------------------------------------------
    def log(self, msg: str) -> None:
        if self.verbose:
            debug(f"[{self.name}] {msg}")
        self.memory.note(self.name, msg)

    def run_hook(self, key: str, *args: Any, **kw: Any) -> Any:
        """Jalankan fungsi yang di-inject lewat hooks; fallback ke `_default_*`."""
        fn = self.hooks.get(key)
        if fn is not None:
            return fn(*args, **kw)
        fallback = getattr(self, f"_default_{key}", None)
        if fallback is not None:
            return fallback(*args, **kw)
        warn(f"[{self.name}] hook '{key}' tidak tersedia")
        return None

    def run(self) -> Dict[str, Any]:
        """Titik masuk utama agent; implementasi per subclass."""
        raise NotImplementedError