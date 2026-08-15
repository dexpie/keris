"""Race condition / TOCTOU tester: kirim request paralel ke endpoint kritis.

Berguna untuk mendeteksi double-spend / double-use: kupon, topup, vote,
transfer, registrasi satu-kali, dsb. Mengirim N request identik secara
bersamaan lalu membandingkan respons sukses (2xx).
"""

import threading
from typing import Dict, List, Optional

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding


def _fire(client: KerisHTTP, url: str, method: str, data: Optional[dict],
          n: int) -> List[int]:
    results: List[int] = []
    barrier = threading.Barrier(n)
    lock = threading.Lock()

    def one() -> None:
        try:
            barrier.wait(timeout=8)
            if method == "post":
                r = client.post(url, data=data or {}, timeout=15)
            else:
                r = client.get(url, params=data or {}, timeout=15)
            with lock:
                results.append(r.status_code)
        except Exception:
            with lock:
                results.append(0)

    threads = [threading.Thread(target=one) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    return results


def race_test(base: str, endpoint: str, client: KerisHTTP,
              method: str = "post", data: Optional[dict] = None,
              concurrency: int = 8) -> Dict:
    """Kirim `concurrency` request identik serentak; cek double-apply."""
    url = endpoint if endpoint.startswith("http") else base.rstrip("/") + "/" + endpoint.lstrip("/")
    statuses = _fire(client, url, method, data, concurrency)
    success = [s for s in statuses if 200 <= s < 400]
    return {
        "url": url,
        "concurrency": concurrency,
        "statuses": statuses,
        "success_count": len(success),
        "unique": sorted(set(statuses)),
    }


def race_findings(base: str, endpoints: List[str], client: KerisHTTP,
                  method: str = "post", data: Optional[dict] = None,
                  concurrency: int = 8) -> List[Finding]:
    """Uji race condition pada daftar endpoint; kembalikan temuan."""
    findings: List[Finding] = []
    info(f"=== RACE CONDITION ({len(endpoints)} endpoint, {concurrency}x) ===")
    for ep in endpoints:
        res = race_test(base, ep, client, method=method, data=data, concurrency=concurrency)
        # double-apply jika hampir semua sukses dalam window bersamaan
        if res["success_count"] >= 2 and len(res["unique"]) <= 2:
            findings.append(Finding(
                "HIGH", f"Potensi race condition (double-apply): {ep}",
                ep,
                f"Endpoint menerima {res['success_count']} dari {concurrency} request "
                "identik serentak. Jika ini operasi sekali-pakai (kupon/topup/vote), "
                "nilai bisa dipakai lebih dari sekali.",
                f"status: {res['unique']}",
            ))
            severity_label = "HIGH"
        elif res["success_count"] >= 1:
            findings.append(Finding(
                "LOW", f"Endpoint merespons pada request serentak: {ep}",
                ep,
                f"{res['success_count']} request sukses; validasi manual disarankan.",
                f"status: {res['unique']}",
            ))
            severity_label = "LOW"
        else:
            severity_label = None
        if severity_label:
            debug(f"{severity_label} {ep} -> {res['unique']}")
        else:
            debug(f"OK {ep} -> tidak ada yang berhasil (endpoint menolak)")
    return findings