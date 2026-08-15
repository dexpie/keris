"""Orkestrator overpowered kit: gateway untuk modul ofensif berat.

- gitdump : full .git dump & source recovery
- authbypass : multi-teknik bypass kontrol akses
- spray   : mass password spraying (anti-lockout)
- dbdump  : ekstraksi database penuh dari SQLi
- cloud   : verifikasi & takeover cloud (AWS/GCP/Azure)
- xsshook : server capture untuk konfirmasi dampak XSS
- k8s     : enum & uji akses Kubernetes API (langsung / SSRF pivot)
- crack   : cracking hash offline

GUARD: semua butuh `authorized`; xsshook juga `yes`.
"""

from typing import Dict, List, Optional

from keris.core.http import KerisHTTP
from keris.core.logger import info, ok, warn
from keris.modules.scanner import Finding

SUPPORTED = ("gitdump", "authbypass", "spray", "dbdump", "cloud", "xsshook", "k8s", "crack")


def run_op_kit(base: str, client: KerisHTTP,
               endpoints: Optional[List[str]] = None,
               types: Optional[List[str]] = None,
               usernames: Optional[List[str]] = None,
               passwords: Optional[List[str]] = None,
               hashes: Optional[List[str]] = None,
               git_outdir: str = "",
               authorized: bool = False,
               yes: bool = False) -> List[Finding]:
    """Jalankan overpowered kit. Wajib `authorized`; xsshook butuh `yes`."""
    from keris.core.logger import error as _error

    if not authorized:
        _error("Overpowered kit memerlukan izin tertulis. Gunakan --authorized.")
        return []
    types = [t.strip() for t in (types or ["gitdump", "authbypass"]) if t.strip()]
    endpoints = endpoints or []
    findings: List[Finding] = []
    warn("OVERPOWERED KIT AKTIF — target harus milik Anda / berizin tertulis!")

    if "gitdump" in types:
        from keris.modules.gitdump import dump_git
        findings.extend(dump_git(base, client, outdir=git_outdir,
                                 authorized=authorized))
    if "authbypass" in types:
        from keris.modules.authbypass import test_bypass
        findings.extend(test_bypass(base, client, endpoints, authorized=authorized))
    if "spray" in types:
        if not usernames:
            warn("Spray butuh --users; dilewati.")
        else:
            from keris.modules.spray import spray
            findings.extend(spray(base, client, usernames, passwords,
                                  authorized=authorized))
    if "dbdump" in types:
        warn("DB dump butuh parameter terkonfirmasi: "
             "`keris dbdump --vuln-url --vuln-param`.")
    if "cloud" in types:
        from keris.modules.cloudtakeover import scan_cloud
        findings.extend(scan_cloud(base, client, [],
                                   authorized=authorized))
        warn("Cloud check butuh findings hunt: `keris cloud --from-scan`.")
    if "xsshook" in types:
        if not yes:
            warn("XSS hook butuh --yes; dilewati.")
    if "k8s" in types:
        warn("K8s scan: `keris k8s TARGET` (langsung) atau --ssrf-url/--ssrf-param.")
    if "crack" in types:
        if not hashes:
            warn("Crack butuh --hash; dilewati.")
        else:
            from keris.modules.hashcrack import crack_hashes
            findings.extend(crack_hashes(hashes, authorized=authorized))

    ok(f"Overpowered kit selesai: {len(findings)} temuan")
    return findings
