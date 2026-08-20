"""ReconAgent: pengumpul intelijen target (DNS, header, stack, endpoint)."""

from typing import Any, Dict, List

from keris.agents.base import BaseAgent


class ReconAgent(BaseAgent):
    """Fase pertama: kumpulkan profil target sebelum scanning."""

    name = "recon"
    role = "Mengumpulkan intelijen: DNS, header keamanan, stack teknologi, endpoint."

    def _default_fingerprint(self, target: str) -> Dict[str, Any]:
        """Fallback fingerprint tanpa network (untuk testing)."""
        from keris.core.utils import host_from_url, scheme_from_url

        host = host_from_url(target)
        return {
            "target": target,
            "host": host,
            "scheme": scheme_from_url(target),
            "stack": [],
            "headers": {},
            "dns": [],
        }

    def run(self) -> Dict[str, Any]:
        target = self.memory.get("target", "")
        self.log(f"Mulai recon untuk {target}")
        self.memory.status(self.name, "running")

        profile = self.run_hook("fingerprint", target)
        if not isinstance(profile, dict):
            profile = {}
        self.memory.set("recon", profile)

        endpoints = self.run_hook("discover", target) or []
        if not isinstance(endpoints, list):
            endpoints = []
        # simpan endpoint unik (normalisasi url)
        seen = set(self.memory.get("endpoints", []))
        for e in endpoints:
            if e and e not in seen:
                seen.add(e)
        self.memory.set("endpoints", sorted(seen))
        self.log(f"Recon selesai: {len(seen)} endpoint, "
                 f"stack={profile.get('stack', [])}")
        self.memory.status(self.name, "done")
        return {"agent": self.name, "recon": profile, "endpoints": sorted(seen)}