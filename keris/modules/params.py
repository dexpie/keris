"""Hidden parameter discovery: coba param umum pada endpoint untuk perilaku tersembunyi.

Deteksi perubahan respons (status, panjang body, refleksi) yang menandakan
parameter tidak dikenal diproses server.
"""

from typing import List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding
from keris.payloads import HIDDEN_PARAMS, HIDDEN_PARAM_VALUES


def discover_hidden_params(base: str, client: KerisHTTP,
                           endpoints: List[str], max_endpoints: int = 15) -> List[Finding]:
    """Cari parameter tersembunyi yang diproses server pada endpoint GET."""
    findings = []
    for ep in endpoints[:max_endpoints]:
        full = base + ep if not ep.startswith("http") else ep
        if "?" in full:
            continue  # hanya endpoint tanpa query agar baseline bersih
        # baseline
        try:
            r0 = client.get(full, timeout=10)
        except Exception:
            continue
        base_len = len(r0.content or b"")
        base_status = r0.status_code
        base_text = r0.text

        for param in HIDDEN_PARAMS:
            candidate = f"{full}?{urlencode({param: HIDDEN_PARAM_VALUES[0]})}"
            try:
                r = client.get(candidate, timeout=10)
            except Exception:
                continue
            body = r.text[:2000]
            delta = abs(len(r.content or b"") - base_len)
            value = HIDDEN_PARAM_VALUES[0]
            # refleksi harus nilai baru yang tidak ada di baseline (mis. "1" selalu ada)
            reflected = value in body and value not in base_text
            # sinyal: status berubah, refleksi baru, atau body jauh berbeda
            if reflected or (r.status_code != base_status and delta > 300):
                findings.append(Finding(
                    "LOW", "Hidden parameter merespons (perlu verifikasi manual)",
                    candidate,
                    f"Parameter `{param}` mengubah respons "
                    f"(status {base_status}->{r.status_code}, delta {delta} B, "
                    f"reflected={reflected}).",
                    f"param: {param}",
                ))
                debug(f"  hidden param: {param} -> status {r.status_code}, delta {delta}")
                break  # cukup satu sinyal per endpoint
    return findings
