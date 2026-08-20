"""HTTP mass-scan: cek status/header/title banyak URL sekaligus.

Untuk penyaringan cepat aset: mana yang hidup (200/301/302/403), title-nya
apa, teknologi apa, dan di mana ada redirect. Zero-dep selain requests.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from keris.core.http import KerisHTTP
from keris.core.logger import info, ok, warn


def _title(html: str) -> str:
    low = html.lower()
    start = low.find("<title")
    if start == -1:
        return ""
    end = low.find("</title>", start)
    if end == -1:
        end = start + 200
    title = html[start:end].split(">", 1)[-1] if ">" in html[start:end] else ""
    return " ".join(title.split())[:80]


def _tech(headers: Any) -> List[str]:
    found = []
    server = headers.get("Server", "")
    if server:
        found.append(server.strip().split("/")[0])
    via = headers.get("Via", "")
    if via:
        found.append(via.strip().split()[0])
    xp = headers.get("X-Powered-By", "")
    if xp:
        found.append(xp.strip())
    return found


def _probe(base: str, client: KerisHTTP, timeout: float,
           follow: bool) -> Optional[dict]:
    try:
        allow_redirects = follow
        r = client.get(base, timeout=timeout, allow_redirects=allow_redirects)
        size = len(r.content or b"")
        title = ""
        if r.status_code == 200 and r.headers.get("Content-Type", "").startswith("text/"):
            title = _title(r.text)
        return {
            "url": base,
            "status": r.status_code,
            "title": title,
            "server": r.headers.get("Server", ""),
            "tech": _tech(r.headers),
            "location": r.headers.get("Location", ""),
            "size": size,
            "content_type": r.headers.get("Content-Type", "").split(";")[0],
            "final_url": r.url if follow else base,
        }
    except Exception as e:
        return {"url": base, "error": str(e)[:120], "status": 0}


def scan_urls(urls: List[str], workers: int = 20, timeout: float = 8.0,
              follow: bool = False, insecure: bool = False,
              proxy: str = "", headers: Optional[dict] = None,
              token: str = "", cookie: str = "") -> List[dict]:
    """Probe banyak URL. Kembalikan daftar hasil (status 0 = gagal)."""
    client = KerisHTTP(timeout=timeout, insecure=insecure, proxy=proxy,
                       extra_headers=headers, token=token, cookie=cookie)
    results = []
    try:
        info(f"Probe {len(urls)} URL (workers={workers}, follow={follow}) ...")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_probe, u, client, timeout, follow) for u in urls]
            for fut in as_completed(futures):
                res = fut.result()
                results.append(res)
    finally:
        client.close()
    results.sort(key=lambda r: (r.get("status") == 0, r.get("status", 0),
                                r.get("url", "")))
    alive = [r for r in results if r.get("status", 0) not in (0,)]
    dead = [r for r in results if r.get("status", 0) == 0]
    ok(f"Alive: {len(alive)}, gagal: {len(dead)}")
    return results


def summarize(results: List[dict]) -> None:
    """Tampilkan tabel ringkas hasil probe."""
    for r in results:
        if r.get("status") == 0:
            warn(f"[ERR] {r['url']}  {r.get('error', '')}")
            continue
        parts = [str(r["status"]), r["url"]]
        if r.get("title"):
            parts.append(f"\"{r['title']}\"")
        if r.get("server"):
            parts.append(r["server"])
        if r.get("location"):
            parts.append(f"-> {r['location'][:60]}")
        ok(" | ".join(parts))