"""Web UI lokal untuk Keris.

`python -m keris serve` menjalankan server HTTP kecil (standar lib saja) di
127.0.0.1:8181. Di halaman tersebut Anda cukup menempelkan link target lalu
mengklik tombol Scan — Keris menjalankan scan lengkap di background dengan
menggunakan `scan` command (subprocess) sehingga bisa dihentikan, log live
di-streaming ke browser, dan hasilnya bisa diunduh (MD/HTML/PDF/JSON).

Jangan expose ke jaringan publik. Target harus memiliki izin untuk diuji.
"""

import io
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from keris import __version__

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8181

# urutan stage scan + estimasi progres (persen)
STAGES = [
    ("PASSIVE RECON", 8),
    ("AUTO LOGIN", 12),
    ("RECON", 20),
    ("DISCOVERY", 40),
    ("SCANNER", 75),
    ("PLUGINS", 88),
]

# pemetaan opsi UI -> flag CLI `scan`
MODULE_FLAGS = {
    "passive": "--passive",
    "platform_checks": "--platform-checks",
    "waf": "--waf",
    "tls_cert": "--tls-cert",
    "buckets": "--buckets",
    "fuzz": "--fuzz",
    "hidden_params": "--hidden-params",
    "hidden_endpoints": "--hidden-endpoints",
    "cache_poisoning": "--cache-poisoning",
    "host_header": "--host-header",
    "websocket": "--websocket",
    "js_analysis": "--js-analysis",
    "sensitive_data": "--sensitive-data",
}
ACTIVE_FLAGS = {
    "exploit": "--exploit",
    "brute_extended": "--brute-extended",
    "username_enum": "--username-enum",
    "exploit_cve": "--exploit-cve",
}
DEFAULT_MODULES = set(MODULE_FLAGS.keys())

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _guess_stage(line: str):
    """Tebak stage scan dari baris log; kembalikan (nama, persen) atau None."""
    for name, pct in STAGES:
        if f"=== {name} ===" in line.upper() or name in line.upper():
            return name, pct
    return None


class ScanJob:
    """Satu pekerjaan (scan penuh atau uji DoS) yang berjalan sebagai subprocess."""

    def __init__(self, target: str, options: dict, kind: str = "scan"):
        self.id = uuid.uuid4().hex[:10]
        self.target = target
        self.options = options
        self.kind = kind  # scan | dos
        self.status = "queued"  # queued | running | done | error | stopped
        self.stage = ""
        self.progress = 0.0
        self.error = None
        self.created = time.time()
        self.started = None
        self.finished = None
        self.log = deque(maxlen=4000)
        self.summary = {}
        self.findings = []
        self.workdir = None
        self.process = None
        self._lock = threading.Lock()
        self._stop = False

    def to_dict(self, full: bool = False) -> dict:
        with self._lock:
            d = {
                "id": self.id,
                "target": self.target,
                "kind": self.kind,
                "status": self.status,
                "stage": self.stage,
                "progress": self.progress,
                "error": self.error,
                "created": self.created,
                "summary": self.summary,
                "finding_count": len(self.findings),
            }
            if full:
                d["findings"] = self.findings
                d["log"] = list(self.log)
            return d


class UIServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, jobs, jobs_lock):
        self.jobs = jobs
        self.jobs_lock = jobs_lock
        super().__init__(addr, UIHandler)


class UIHandler(BaseHTTPRequestHandler):
    server_version = f"KerisUI/{__version__}"

    def log_message(self, *a):
        pass

    # --- helpers ---
    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, body: str, code=200, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _file(self, path: str, ctype: str):
        if not path or not os.path.exists(path):
            self._json({"error": "laporan belum tersedia"}, 404)
            return
        with open(path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(path)}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _find_job(self, job_id: str):
        with self.server.jobs_lock:
            return self.server.jobs.get(job_id)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    # --- GET ---
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/" or path == "/index.html":
            self._text(_PAGE)
            return
        if path == "/api/health":
            self._json({"ok": True, "version": __version__})
            return
        if path == "/api/jobs":
            with self.server.jobs_lock:
                jobs = sorted(self.server.jobs.values(), key=lambda j: j.created, reverse=True)
            self._json({"jobs": [j.to_dict() for j in jobs[:50]]})
            return
        if path.startswith("/api/jobs/"):
            rest = path[len("/api/jobs/"):]
            parts = rest.split("/")
            job = self._find_job(parts[0])
            if not job:
                self._json({"error": "job tidak ditemukan"}, 404)
                return
            if len(parts) == 1:
                self._json(job.to_dict(full=True))
                return
            if len(parts) == 2 and parts[1] == "report":
                fmt = (self.path.split("?")[1].split("=")[1] if "=" in self.path else "json") if "?" in self.path else "json"
                fmt = fmt.split("&")[0]
                self._serve_report(job, fmt)
                return
        self._json({"error": "not found"}, 404)

    def _serve_report(self, job: ScanJob, fmt: str):
        ext = fmt if fmt in ("md", "html", "pdf", "json") else "json"
        fname = os.path.join(job.workdir or "", f"report.{ext}")
        ctypes = {
            "md": "text/markdown; charset=utf-8",
            "html": "text/html; charset=utf-8",
            "pdf": "application/pdf",
            "json": "application/json; charset=utf-8",
        }
        if not os.path.exists(fname):
            # mungkin gagal saat generate; coba bangun ulang dari findings
            if job.findings:
                _regenerate_reports(job, [fmt])
                if os.path.exists(fname):
                    self._file(fname, ctypes.get(fmt, ctypes["json"]))
                    return
            self._json({"error": "laporan tidak tersedia"}, 404)
            return
        self._file(fname, ctypes.get(fmt, ctypes["json"]))

    # --- POST ---
    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/api/scan":
            body = self._read_body()
            target = (body.get("target") or "").strip()
            if not target:
                self._json({"error": "target wajib diisi"}, 400)
                return
            options = body.get("options") or {}
            # satu scan berjalan pada satu waktu
            with self.server.jobs_lock:
                running = [j for j in self.server.jobs.values() if j.status in ("queued", "running")]
            if running:
                self._json({"error": f"Scan sedang berjalan: {running[0].target}"}, 409)
                return
            job = ScanJob(target, options)
            with self.server.jobs_lock:
                self.server.jobs[job.id] = job
            t = threading.Thread(target=_worker, args=(job,), daemon=True)
            t.start()
            self._json({"id": job.id, "status": job.status})
            return
        if path == "/api/dos":
            body = self._read_body()
            target = (body.get("target") or "").strip()
            if not target:
                self._json({"error": "target wajib diisi"}, 400)
                return
            if not body.get("confirmed"):
                self._json({"error": "Konfirmasi izin tertulis wajib untuk uji DoS"}, 400)
                return
            with self.server.jobs_lock:
                running = [j for j in self.server.jobs.values() if j.status in ("queued", "running")]
            if running:
                self._json({"error": f"Pekerjaan sedang berjalan: {running[0].target}"}, 409)
                return
            options = dict(body.get("options") or {})
            options["confirmed"] = True
            job = ScanJob(target, options, kind="dos")
            with self.server.jobs_lock:
                self.server.jobs[job.id] = job
            t = threading.Thread(target=_worker, args=(job,), daemon=True)
            t.start()
            self._json({"id": job.id, "status": job.status})
            return
        if path.startswith("/api/jobs/"):
            parts = path[len("/api/jobs/"):].split("/")
            job = self._find_job(parts[0])
            if not job:
                self._json({"error": "job tidak ditemukan"}, 404)
                return
            if len(parts) == 2 and parts[1] == "stop":
                _stop_job(job)
                self._json({"id": job.id, "status": job.status})
                return
        self._json({"error": "not found"}, 404)


def _build_argv(job: ScanJob) -> list:
    opts = job.options or {}
    preset = opts.get("preset") or "fast"
    flags = ["--no-color", "--preset", preset]
    for key, flag in MODULE_FLAGS.items():
        if opts.get(key, True):
            flags.append(flag)
    if opts.get("authorized"):
        flags.append("--authorized")
        for key, flag in ACTIVE_FLAGS.items():
            if opts.get(key, False):
                flags.append(flag)
    return flags


def _build_dos_argv(job: ScanJob) -> list:
    opts = job.options or {}
    flags = ["--no-color", "--yes"]
    k = opts.get("type") or "all"
    if k in ("slowloris", "slowpost", "flood", "all"):
        flags += ["--type", k]
    concurrency = int(opts.get("concurrency") or 10)
    duration = float(opts.get("duration") or 20.0)
    total = int(opts.get("requests") or 200)
    flags += ["--concurrency", str(concurrency),
              "--duration", str(duration), "--requests", str(total)]
    return flags


def _worker(job: ScanJob):
    with job._lock:
        job.status = "running"
        job.started = time.time()
    workdir = os.path.join(ROOT, ".keris-ui", job.id)
    os.makedirs(workdir, exist_ok=True)
    job.workdir = workdir

    if job.kind == "dos":
        argv = _build_dos_argv(job)
        cmd = [sys.executable, "-m", "keris", "dos", job.target]
        cmd += argv
        cmd += ["--json-output", os.path.join(workdir, "report.json")]
    else:
        argv = _build_argv(job)
        cmd = [sys.executable, "-m", "keris", "scan", job.target]
        cmd += argv
        cmd += [
            "-o", os.path.join(workdir, "report.md"),
            "--html", os.path.join(workdir, "report.html"),
            "--pdf", os.path.join(workdir, "report.pdf"),
            "--json-output", os.path.join(workdir, "report.json"),
        ]
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    if job._stop:
        with job._lock:
            job.status = "stopped"
            job.finished = time.time()
        return
    try:
        job.process = subprocess.Popen(
            cmd, cwd=ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
    except Exception as e:  # pragma: no cover
        with job._lock:
            job.status = "error"
            job.error = f"gagal menjalankan scan: {e}"
            job.finished = time.time()
        return

    # baca stdout live
    for raw in iter(job.process.stdout.readline, b""):
        if job._stop:
            break
        try:
            line = raw.decode("utf-8", errors="replace").rstrip("\n")
        except Exception:
            line = str(raw)[:200]
        with job._lock:
            job.log.append(line)
            st = _guess_stage(line)
            if st:
                job.stage, job.progress = st[0], float(st[1])

    job.process.wait()
    rc = job.process.returncode

    if job._stop:
        with job._lock:
            job.status = "stopped"
            job.finished = time.time()
        return

    # parse hasil JSON
    jpath = os.path.join(workdir, "report.json")
    result = {}
    if os.path.exists(jpath):
        try:
            with open(jpath, "r", encoding="utf-8") as f:
                result = json.load(f)
        except (json.JSONDecodeError, OSError):
            result = {}

    with job._lock:
        job.findings = result.get("findings", [])
        summary = result.get("summary") or {}
        if not summary:
            # subcommand dos tidak menyediakan summary -> hitung dari findings
            summary = {"total": len(job.findings)}
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                summary[s] = sum(1 for f in job.findings
                                 if f.get("severity", "INFO").upper() == s)
        job.summary = summary
        if rc in (0, 1):
            job.status = "done"
            job.progress = 100.0
            if job.findings:
                sevs = " ".join(f"{s}:{job.summary.get(s, 0)}"
                                for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
                job.log.append(f"[UI] Selesai dengan {len(job.findings)} temuan ({sevs})")
            else:
                job.log.append("[UI] Selesai, tidak ada temuan.")
        else:
            job.status = "error"
            job.error = result.get("error") or f"pekerjaan gagal (exit code {rc})"
        job.finished = time.time()

    # uji DoS: laporan MD/HTML/PDF tidak dihasilkan subprocess -> bangun ulang
    if job.kind == "dos" and job.status == "done":
        try:
            _regenerate_reports(job, ["md", "html", "pdf"])
        except Exception:
            pass


def _stop_job(job: ScanJob):
    job._stop = True
    if job.process and job.process.poll() is None:
        try:
            job.process.terminate()
        except Exception:
            pass


def _regenerate_reports(job: ScanJob, formats):
    """Bangun ulang laporan MD/HTML/PDF dari findings yang tersimpan."""
    if not job.findings:
        return
    try:
        from keris.report import write_report
        from keris.report_html import write_html_report

        recon = {"host": job.target, "stack": [], "security_headers": []}
        disc = {"api_endpoints": [], "js_assets": [], "secrets": []}
        options = {"mode": "Web UI Keris"}
        out = os.path.join(job.workdir, "report.")
        if "md" in formats:
            write_report(recon, disc, job.findings, out + "md", job.target, options)
        if "html" in formats:
            write_html_report(recon, disc, job.findings, out + "html", job.target, options)
        if "pdf" in formats:
            from keris.report_pdf import write_pdf_report

            write_pdf_report(recon, disc, job.findings, out + "pdf", job.target, options)
    except Exception:
        pass


def run_ui(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    jobs = {}
    jobs_lock = threading.Lock()
    server = UIServer((host, port), jobs, jobs_lock)
    print(f"Keris Web UI  v{__version__}  ->  http://{host}:{port}")
    print("Tutup dengan Ctrl+C. Jangan expose ke jaringan publik.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nMenghentikan UI...")
    finally:
        for job in jobs.values():
            _stop_job(job)
        server.server_close()


_PAGE = r"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Keris — Web UI</title>
<style>
:root{
  --bg:#07070b; --panel:rgba(255,255,255,.045); --panel2:rgba(255,255,255,.08);
  --glass-border:rgba(255,255,255,.12); --glass-border-hi:rgba(255,255,255,.22);
  --txt:#d6dae0; --muted:#9aa1ac; --dim:#5c626c;
  --brass:#e3b45e; --brass-dim:#8a6a2a; --brass-ink:#141005;
  --crit:#ff6b64; --high:#ff9a66; --med:#ffd166; --low:#b7c85a; --info:#6cb4ff;
  --mono:"JetBrains Mono","Cascadia Code",Consolas,"Courier New",monospace;
  --blur:18px;
}
*{box-sizing:border-box}
::selection{background:var(--brass);color:var(--brass-ink)}
html,body{margin:0;padding:0}
body{
  min-height:100vh;
  background:
    radial-gradient(900px 600px at 8% -8%, rgba(227,180,94,.16), transparent 60%),
    radial-gradient(800px 620px at 100% 6%, rgba(108,180,255,.13), transparent 60%),
    radial-gradient(760px 560px at 12% 108%, rgba(255,107,100,.10), transparent 60%),
    radial-gradient(700px 500px at 96% 92%, rgba(255,209,102,.08), transparent 60%),
    var(--bg);
  color:var(--txt);
  font-family:var(--mono);
  font-size:13px;
  line-height:1.5;
}
body::before{
  content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background:repeating-linear-gradient(0deg, rgba(255,255,255,.014) 0 1px, transparent 1px 3px);
}
body::after{
  content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background:radial-gradient(2px 2px at 20% 30%, rgba(255,255,255,.06), transparent 100%),
    radial-gradient(2px 2px at 70% 20%, rgba(255,255,255,.05), transparent 100%),
    radial-gradient(1.5px 1.5px at 40% 80%, rgba(255,255,255,.05), transparent 100%),
    radial-gradient(2px 2px at 90% 60%, rgba(255,255,255,.05), transparent 100%);
}
.blob{position:fixed;z-index:0;pointer-events:none;border-radius:50%;
  filter:blur(70px);opacity:.5;will-change:transform}
.blob-1{width:520px;height:520px;left:-140px;top:-120px;
  background:radial-gradient(circle at 35% 35%, rgba(227,180,94,.5), rgba(227,180,94,.08) 60%);
  animation:drift1 26s ease-in-out infinite alternate}
.blob-2{width:460px;height:460px;right:-120px;top:12%;
  background:radial-gradient(circle at 60% 40%, rgba(108,180,255,.42), rgba(108,180,255,.06) 60%);
  animation:drift2 32s ease-in-out infinite alternate}
.blob-3{width:420px;height:420px;left:30%;bottom:-160px;
  background:radial-gradient(circle at 50% 50%, rgba(255,107,100,.35), rgba(255,107,100,.05) 60%);
  animation:drift3 38s ease-in-out infinite alternate}
@keyframes drift1{from{transform:translate(0,0) scale(1)}to{transform:translate(90px,50px) scale(1.18)}}
@keyframes drift2{from{transform:translate(0,0) scale(1)}to{transform:translate(-70px,80px) scale(.9)}}
@keyframes drift3{from{transform:translate(0,0) scale(1)}to{transform:translate(60px,-70px) scale(1.12)}}
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulseGlow{0%,100%{box-shadow:0 0 18px rgba(227,180,94,.25)}50%{box-shadow:0 0 34px rgba(227,180,94,.5)}}
@keyframes blink{0%,60%{opacity:1}61%,100%{opacity:0}}
.wrap{position:relative;z-index:1;max-width:1120px;margin:0 auto;padding:18px}
header{
  position:sticky;top:0;z-index:50;
  display:flex;align-items:center;gap:14px;
  padding:10px 18px;margin:10px 14px 0;
  border:1px solid var(--glass-border);
  border-radius:16px;
  background:rgba(255,255,255,.06);
  backdrop-filter:blur(var(--blur)) saturate(150%);
  -webkit-backdrop-filter:blur(var(--blur)) saturate(150%);
  box-shadow:0 8px 32px rgba(0,0,0,.45);
}
header .emblem{color:var(--brass);font-size:11px;line-height:1.15;white-space:pre;
  padding-right:14px;border-right:1px solid var(--glass-border)}
.emblem-core{
  display:inline-block;width:26px;height:40px;position:relative;color:var(--brass);
  text-shadow:0 0 12px rgba(227,180,94,.55);
}
.emblem-core::before{
  content:"";position:absolute;left:8px;top:0;width:10px;height:32px;
  background:linear-gradient(180deg, #f0c46a, var(--brass) 55%, #8a6a2a);
  clip-path:polygon(50% 0, 100% 26%, 82% 100%, 18% 100%, 0 26%);
  box-shadow:0 0 16px rgba(227,180,94,.4);
}
.emblem-core::after{
  content:"";position:absolute;left:6px;top:30px;width:14px;height:5px;
  background:linear-gradient(180deg, var(--brass), #8a6a2a);
  clip-path:polygon(0 0, 100% 0, 78% 100%, 22% 100%);
}
header .wordmark{font-size:17px;letter-spacing:4px;color:var(--brass);font-weight:700;
  text-shadow:0 0 24px rgba(227,180,94,.35)}
header .wordmark small{color:var(--muted);font-size:10px;letter-spacing:2px;
  display:block;font-weight:400;margin-top:2px}
header .hdr-right{margin-left:auto;text-align:right;color:var(--muted);font-size:11px}
header .hdr-right b{color:var(--txt)}
.pane{
  border:1px solid var(--glass-border);
  border-radius:18px;
  background:var(--panel);
  backdrop-filter:blur(var(--blur)) saturate(140%);
  -webkit-backdrop-filter:blur(var(--blur)) saturate(140%);
  box-shadow:0 10px 40px rgba(0,0,0,.35), inset 0 1px 0 rgba(255,255,255,.06);
  margin-bottom:16px;overflow:hidden;
  animation:rise .5s ease both;
  transition:transform .2s ease, box-shadow .2s ease, border-color .2s ease;
}
.pane:nth-child(2){animation-delay:.05s}
.pane:nth-child(3){animation-delay:.1s}
.pane:nth-child(4){animation-delay:.15s}
.pane:nth-child(5){animation-delay:.2s}
.pane:hover{
  transform:translateY(-2px);
  box-shadow:0 16px 48px rgba(0,0,0,.45), inset 0 1px 0 rgba(255,255,255,.08);
  border-color:var(--glass-border-hi);
}
.pane-head{display:flex;align-items:center;gap:8px;padding:8px 14px;
  background:rgba(255,255,255,.05);
  border-bottom:1px solid var(--glass-border);
  color:var(--brass);font-size:11px;letter-spacing:2px;text-transform:uppercase}
.pane-head .no{color:var(--dim);letter-spacing:0}
.pane-head .fill{flex:1}
.pane-body{padding:16px}
label{display:block;font-size:11px;color:var(--muted);margin:10px 0 4px;letter-spacing:.5px}
input[type=text],select{
  width:100%;padding:8px 10px;
  border:1px solid var(--glass-border);background:rgba(255,255,255,.05);color:var(--txt);
  font-family:var(--mono);font-size:13px;border-radius:10px;
  backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);
  transition:border-color .15s, box-shadow .15s;
}
input[type=text]:focus,select:focus{outline:none;border-color:var(--brass);
  box-shadow:0 0 0 3px rgba(227,180,94,.18), inset 0 -2px 0 rgba(227,180,94,.5)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:700px){.grid{grid-template-columns:1fr}}
.chk{display:flex;align-items:center;gap:8px;font-size:12px;margin:4px 0;cursor:pointer}
.chk input{appearance:none;width:13px;height:13px;border:1px solid var(--muted);
  background:rgba(255,255,255,.06);border-radius:4px;cursor:pointer;position:relative;flex:none}
.chk input:checked{background:var(--brass);border-color:var(--brass)}
.chk input:checked::after{content:"\2713";position:absolute;left:2px;top:-2px;
  color:var(--brass-ink);font-size:11px;font-weight:700}
.chk input:disabled{opacity:.35}
.btn{cursor:pointer;border:1px solid var(--glass-border-hi);background:rgba(255,255,255,.06);
  color:var(--txt);padding:9px 16px;font-family:var(--mono);font-size:12px;
  letter-spacing:1px;text-transform:uppercase;border-radius:10px;
  backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);
  transition:transform .12s, border-color .15s, box-shadow .15s;
}
.btn:hover{border-color:var(--brass);color:var(--brass);
  box-shadow:0 0 18px rgba(227,180,94,.18)}
.btn:active{transform:translateY(1px)}
.btn:disabled{opacity:.4;cursor:not-allowed}
#go{background:linear-gradient(135deg, rgba(227,180,94,.92), rgba(212,162,78,.78));
  border-color:rgba(227,180,94,.6);color:var(--brass-ink);font-weight:700;width:100%;margin-top:14px;
  box-shadow:0 4px 24px rgba(227,180,94,.3);
  animation:pulseGlow 3.5s ease-in-out infinite}
#go:hover{background:linear-gradient(135deg, #eec06b, #dba64f);color:var(--brass-ink);
  box-shadow:0 6px 32px rgba(227,180,94,.45)}
#crit{background:rgba(255,107,100,.12);border-color:rgba(255,107,100,.45);color:var(--crit);font-weight:700}
#crit:hover{background:rgba(255,107,100,.22);color:#ff857f;box-shadow:0 0 18px rgba(255,107,100,.2)}
#stop{background:transparent;border-color:var(--crit);color:var(--crit)}
#stop:hover{background:rgba(255,107,100,.1);box-shadow:0 0 14px rgba(255,107,100,.15)}
#go_dos{background:linear-gradient(135deg, rgba(255,107,100,.8), rgba(240,80,70,.65));
  border-color:rgba(255,107,100,.5);color:#160b09;font-weight:700;margin-top:12px}
#go_dos:hover{background:linear-gradient(135deg, #ff827b, #f25a4e);color:#160b09;
  box-shadow:0 4px 24px rgba(255,107,100,.3)}
.fbtn{background:rgba(255,255,255,.05);border:1px solid var(--glass-border);color:var(--muted);
  padding:5px 10px;font-family:var(--mono);font-size:11px;text-transform:uppercase;border-radius:8px;
  cursor:pointer;transition:all .15s}
.fbtn:hover{border-color:var(--brass);color:var(--brass)}
.fbtn.active{border-color:var(--brass);color:var(--brass);background:rgba(227,180,94,.12);
  box-shadow:0 0 12px rgba(227,180,94,.15)}
.hint{color:var(--muted);font-size:11px;margin-top:8px;line-height:1.5}
.sev{display:inline-block;padding:1px 8px;font-size:11px;font-weight:700;
  letter-spacing:1px;text-align:center;min-width:68px;border:1px solid currentColor;border-radius:6px}
.sev.critical{color:var(--crit);background:rgba(255,107,100,.1)}
.sev.high{color:var(--high);background:rgba(255,154,102,.1)}
.sev.medium{color:var(--med);background:rgba(255,209,102,.1)}
.sev.low{color:var(--low);background:rgba(183,200,90,.1)}
.sev.info{color:var(--info);background:rgba(108,180,255,.1)}
#status{margin-bottom:10px}
#stage{color:var(--brass)}
#stage::after{content:"_";animation:blink 1.1s steps(1) infinite;color:var(--brass-dim)}
#progress{height:6px;background:rgba(255,255,255,.07);border:1px solid var(--glass-border);
  border-radius:99px;margin-top:8px;overflow:hidden}
#progress>div{height:100%;background:linear-gradient(90deg, var(--brass), #f0c46a);
  width:0%;transition:width .5s;box-shadow:0 0 12px rgba(227,180,94,.5)}
pre#log{background:rgba(0,0,0,.35);border:1px solid var(--glass-border);
  border-radius:12px;padding:12px;height:280px;overflow-y:auto;font-size:12px;line-height:1.55;
  white-space:pre-wrap;word-break:break-word;color:#aeb7c2;
  font-family:var(--mono);
  backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
.cards{display:flex;flex-wrap:wrap;border:1px solid var(--glass-border);border-radius:12px;overflow:hidden}
.sum{flex:1;min-width:110px;background:rgba(255,255,255,.04);padding:10px 8px;text-align:center;
  border-right:1px solid var(--glass-border)}
.sum:last-child{border-right:none}
.sum b{display:block;font-size:22px;font-weight:700}
.sum b.grad{background:linear-gradient(135deg,var(--brass),#f0c46a);
  -webkit-background-clip:text;background-clip:text;color:transparent}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{border:1px solid var(--glass-border);padding:7px 10px;text-align:left;vertical-align:top}
th{background:rgba(255,255,255,.05);color:var(--muted);font-size:10px;letter-spacing:1px;
  text-transform:uppercase}
td{transition:background .15s}
tr.f:hover td{background:rgba(255,255,255,.04)}
tr.hidden{display:none}
.dl a{display:inline-block;margin:4px 8px 4px 0;padding:7px 12px;
  background:rgba(255,255,255,.05);border:1px solid var(--glass-border);color:var(--txt);
  text-decoration:none;font-size:12px;text-transform:uppercase;letter-spacing:1px;border-radius:8px;
  transition:all .15s}
.dl a:hover{border-color:var(--brass);color:var(--brass);box-shadow:0 0 12px rgba(227,180,94,.15)}
.empty{color:var(--muted);font-size:12px}
code{color:var(--brass);background:rgba(255,255,255,.06);padding:0 3px;border-radius:4px}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.14);border:2px solid transparent;
  border-radius:99px;background-clip:padding-box}
::-webkit-scrollbar-thumb:hover{background:rgba(227,180,94,.35);background-clip:padding-box}
.error{color:var(--crit)}
footer{color:var(--dim);font-size:11px;text-align:center;padding:14px;letter-spacing:1px}
.ver{color:var(--muted);font-size:11px}
@media (prefers-reduced-motion: reduce){
  *{animation:none !important;transition:none !important}
  .blob{display:none}
}
</style>
</head>
<body>
<div class="blob blob-1"></div>
<div class="blob blob-2"></div>
<div class="blob blob-3"></div>
<header>
  <div class="emblem"><span class="emblem-core">/\</span></div>
  <div>
    <div class="wordmark">KERIS<small>MODULAR WEB PENTEST TOOLKIT</small></div>
  </div>
  <div class="hdr-right">
    <div>v<span id="ver"></span></div>
    <div id="running"><b>[ idle ]</b></div>
  </div>
</header>
<div class="wrap">

  <div class="pane">
    <div class="pane-head"><span class="no">01</span> SCAN TARGET <span class="fill"></span><span class="no">CVE &amp; WEB</span></div>
    <div class="pane-body">
      <form id="frm">
        <label for="target">target_url</label>
        <input type="text" id="target" placeholder="https://example.com"
               value="http://127.0.0.1:8099" required>
        <div class="grid" style="margin-top:12px">
          <div>
            <label for="preset">preset_kecepatan</label>
            <select id="preset">
              <option value="fast">fast (cepat, agresif)</option>
              <option value="stealth">stealth (lambat, hati-hati)</option>
              <option value="aggressive">aggressive (paling dalam)</option>
            </select>
          </div>
          <div>
            <label for="authorized">izin_serangan_aktif</label>
            <div class="chk"><input type="checkbox" id="authorized">
              <span>saya punya izin tertulis untuk menguji target</span></div>
          </div>
        </div>
        <label>modul_tambahan (aktif otomatis)</label>
        <div class="grid" id="modgrid"></div>
        <div class="hint">web cache poisoning, host header, WebSocket, JS analysis,
          sensitive data, hidden endpoint, fuzz, dsb. -- otomatis dijalankan pada
          setiap scan penuh.</div>
        <div style="display:flex;gap:8px">
          <button type="submit" id="go" class="btn">MULAI SCAN</button>
          <button type="button" id="crit" class="btn">CARIKRITIKAL</button>
          <button type="button" id="stop" class="btn" style="display:none">HENTIKAN</button>
        </div>
      </form>
    </div>
  </div>

  <div class="pane" id="panel-dos">
    <div class="pane-head"><span class="no">02</span> UJI DOS (APP-LAYER) <span class="fill"></span><span class="no">TERUKUR</span></div>
    <div class="pane-body">
      <div class="grid">
        <div>
          <label for="dos_type">jenis_uji</label>
          <select id="dos_type">
            <option value="all">all (slowloris + slow POST + flood)</option>
            <option value="slowloris">slowloris</option>
            <option value="slowpost">slow POST (RUDY)</option>
            <option value="flood">flood GET terukur</option>
          </select>
        </div>
        <div>
          <label for="dos_concurrency">koneksi/thread bersamaan</label>
          <input type="text" id="dos_concurrency" value="10">
        </div>
        <div>
          <label for="dos_duration">durasi (detik)</label>
          <input type="text" id="dos_duration" value="20">
        </div>
        <div>
          <label for="dos_requests">batas total request (flood)</label>
          <input type="text" id="dos_requests" value="200">
        </div>
      </div>
      <div class="chk" style="margin-top:10px">
        <input type="checkbox" id="dos_confirm">
        <span style="color:var(--crit)">saya punya IZIN TERTULIS dan memahami uji
          ini membebani layanan target</span>
      </div>
      <button type="button" id="go_dos" class="btn">JALANKAN UJI DOS</button>
      <div class="hint">non-destruktif &amp; terukur: durasi &amp; jumlah request
        dibatasi. tanpa izin tertulis uji tidak dijalankan.</div>
    </div>
  </div>

  <div class="pane" id="panel-live" style="display:none">
    <div class="pane-head"><span class="no">03</span> STATUS <span class="fill"></span><span class="no" id="elapsed"></span></div>
    <div class="pane-body">
      <div id="status"><b id="stage">menyiapkan...</b></div>
      <div id="progress"><div></div></div>
      <pre id="log"></pre>
    </div>
  </div>

  <div class="pane" id="panel-results" style="display:none">
    <div class="pane-head"><span class="no">04</span> HASIL <span class="fill"></span><span class="no">TEMUAN</span></div>
    <div class="pane-body">
      <div class="cards" id="sumcards"></div>
      <div style="margin-top:12px" class="dl">
        <b class="ver">filter:</b>
        <button type="button" class="fbtn" data-f="all">Semua</button>
        <button type="button" class="fbtn" data-f="critical">Kritis</button>
        <button type="button" class="fbtn" data-f="high">High</button>
        <button type="button" class="fbtn" data-f="medium">Medium</button>
        <button type="button" class="fbtn" data-f="low">Low</button>
      </div>
      <div style="margin-top:12px" class="dl" id="downloads"></div>
      <table style="margin-top:12px" id="tbl">
        <thead><tr><th>Severity</th><th>Lokasi</th><th>Temuan</th></tr></thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </div>

  <div class="pane" id="panel-history" style="display:none">
    <div class="pane-head"><span class="no">05</span> RIWAYAT SCAN <span class="fill"></span></div>
    <div class="pane-body"><div id="history"></div></div>
  </div>

</div>
<footer>Keris — Modular Web Pentest Toolkit. Pastikan Anda memiliki izin
sebelum menguji target apa pun.</footer>

<script>
const MODULES = [
  ["cache_poisoning","Web cache poisoning"],
  ["host_header","Host header injection"],
  ["websocket","WebSocket security"],
  ["js_analysis","JS analysis (DOM XSS)"],
  ["sensitive_data","Sensitive data"],
  ["hidden_endpoints","Hidden endpoints"],
  ["hidden_params","Hidden params"],
  ["fuzz","Parameter fuzzing"],
  ["platform_checks","Platform checks"],
  ["waf","Deteksi WAF"],
  ["tls_cert","Analisis TLS cert"],
  ["buckets","Cloud buckets"],
  ["passive","Passive recon (crt.sh)"],
];
const ACTIVE = [
  ["exploit","Auto-exploit (SQLi/CMDI/SSTI/XSS)"],
  ["brute_extended","Brute-force extended"],
  ["username_enum","Enumerasi username"],
  ["exploit_cve","Probe CVE platform"],
];
let cur = null;
const $ = s => document.querySelector(s);
const esc = s => String(s==null?"":s).replace(/[&<>"']/g,
  c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

function buildModules(){
  const grid = $("#modgrid");
  MODULES.forEach(([k,l])=>{
    const d=document.createElement("label"); d.className="chk";
    d.innerHTML=`<input type="checkbox" id="m_${k}" checked><span>${l}</span>`;
    grid.appendChild(d);
  });
  const auth=$("#authorized");
  ACTIVE.forEach(([k,l])=>{
    const d=document.createElement("label"); d.className="chk";
    d.innerHTML=`<input type="checkbox" id="a_${k}"><span>${l}</span>`;
    d.style.opacity="0.5";
    auth.addEventListener("change",()=>{
      const on=auth.checked;
      d.style.opacity=on?"1":"0.5";
      $("#a_"+k).disabled=!on;
    });
    grid.appendChild(d);
  });
}
function collectOptions(){
  const o={preset:$("#preset").value, authorized:$("#authorized").checked};
  MODULES.forEach(([k])=>{o[k]=$("#m_"+k).checked});
  ACTIVE.forEach(([k])=>{o[k]=$("#a_"+k).checked});
  return o;
}
function sevClass(s){return String(s||"").toLowerCase()}
function renderResults(j){
  $("#panel-results").style.display="";
  const s=j.summary||{};
  $("#sumcards").innerHTML=["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(x=>
    `<div class="sum"><b style="color:${x==="CRITICAL"?"#f87171":x==="HIGH"?"#fb7185":x==="MEDIUM"?"#f59e0b":x==="LOW"?"#eab308":"#60a5fa"}">${s[x]||0}</b>${x}</div>`
  ).join("");
  const jid=j.id;
  $("#downloads").innerHTML=["md","html","pdf","json"].map(f=>
    `<a href="/api/jobs/${jid}/report?fmt=${f}">Download ${f.toUpperCase()}</a>`
  ).join("");
  const rows=(j.findings||[]).slice().sort(
    (a,b)=>(SEV_ORDER(a.severity)-SEV_ORDER(b.severity)));
  $("#tbody").innerHTML=rows.map(f=>{
    const detail=esc(f.detail||f.evidence||"");
    const meta=[f.cvss?("CVSS "+f.cvss):"",f.owasp?f.owasp:""].filter(Boolean).join(" ");
    return `<tr class="f" data-s="${sevClass(f.severity)}">
      <td><span class="sev ${sevClass(f.severity)}">${esc(f.severity||"INFO")}</span></td>
      <td><code>${esc(f.endpoint||"-")}</code>${meta?`<br><span class="ver">${esc(meta)}</span>`:""}</td>
      <td><b>${esc(f.title||"")}</b>${detail?`<br><span class="ver">${detail}</span>`:""}</td></tr>`;
  }).join("") || `<tr><td colspan="3" class="empty">Tidak ada temuan.</td></tr>`;
  if(window.filterSev){applyFilter()}
}
function applyFilter(){
  const sev=window.filterSev||"all";
  document.querySelectorAll("#tbody tr.f").forEach(tr=>{
    const s=tr.dataset.s;
    let show;
    if(sev==="all")show=true;
    else if(sev==="critical")show=(s==="critical");
    else if(sev==="high")show=(s==="high");
    else show=(s===sev);
    tr.classList.toggle("hidden", !show);
  });
}
function setFilter(sev){
  window.filterSev=sev;
  document.querySelectorAll(".fbtn").forEach(b=>{
    b.classList.toggle("active", b.dataset.f===sev);
  });
  applyFilter();
}
function SEV_ORDER(s){return {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}[String(s).toUpperCase()]??5}

async function poll(id){
  const r=await fetch(`/api/jobs/${id}`);
  const j=await r.json();
  cur=j;
  $("#panel-live").style.display="";
  $("#stage").textContent=j.stage?`${j.stage} — ${Math.round(j.progress)}%`:(j.status==="running"?"Menjalankan...":"...");
  $("#progress>div").style.width=Math.max(j.progress||0,5)+"%";
  const log=$("#log");
  if(j.log&&j.log.length){
    log.textContent=j.log.join("\n");
    log.scrollTop=log.scrollHeight;
  }
  if(j.elapsed==null&&j.started){} 
  if(j.status==="running"||j.status==="queued"){
    $("#go").disabled=true; $("#stop").style.display="";
    setTimeout(()=>poll(id),1200);
  }else{
    $("#go").disabled=false; $("#stop").style.display="none";
    if(j.status==="error"){$("#stage").textContent="GAGAL: "+(j.error||"error");
      $("#stage").style.color="#f87171";}
    else{$("#stage").textContent=j.status==="done"?"SELESAI":"DIHENTIKAN";}
    renderResults(j);
    refreshHistory();
  }
}
async function refreshHistory(){
  const r=await fetch("/api/jobs");
  const d=await r.json();
  const hist=$("#history");
  if(!d.jobs.length){$("#panel-history").style.display="none";return}
  $("#panel-history").style.display="";
  hist.innerHTML=d.jobs.map(j=>{
    const st=j.status==="done"?"<span class='sev info'>done</span>":
      j.status==="error"?`<span class='sev high'>error</span>`:`<span class='sev medium'>${j.status}</span>`;
    const cnt=Object.entries(j.summary||{}).filter(([k])=>"CRITICAL,HIGH,MEDIUM,LOW,INFO".includes(k))
      .map(([k,v])=>`<b>${k} ${v}</b>`).join(" · ");
    return `<div style="margin:8px 0;padding:8px;border:1px solid var(--border);background:var(--bg2)">
      <code>${esc(j.target)}</code> ${st}
      <span class="ver" style="float:right">${new Date(j.created*1000).toLocaleString()}</span>
      ${cnt?`<div class="ver">${cnt}</div>`:""}</div>`;
  }).join("");
}
$("#frm").addEventListener("submit",async e=>{
  e.preventDefault();
  const target=$("#target").value.trim();
  if(!target)return;
  const r=await fetch("/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({target,options:collectOptions()})});
  const d=await r.json();
  if(d.error){alert(d.error);return}
  $("#panel-live").style.display="";
  $("#log").textContent="";
  poll(d.id);
});
$("#crit").addEventListener("click",async()=>{
  // cari yang kritis: aktifkan semua modul + serangan aktif, lalu filter CRITICAL/HIGH
  $("#authorized").checked=true;
  ACTIVE.forEach(([k])=>{$("#a_"+k).checked=true});
  MODULES.forEach(([k])=>{$("#m_"+k).checked=true});
  const target=$("#target").value.trim();
  if(!target){alert("Isi target dulu");return}
  const r=await fetch("/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({target,options:collectOptions()})});
  const d=await r.json();
  if(d.error){alert(d.error);return}
  window.filterSev="critical";
  $("#panel-live").style.display="";
  $("#log").textContent="";
  poll(d.id);
});
$("#go_dos").addEventListener("click",async()=>{
  if(!$("#dos_confirm").checked){alert("Centang konfirmasi izin tertulis terlebih dahulu");return}
  const target=$("#target").value.trim();
  if(!target){alert("Isi target dulu");return}
  const options={
    type:$("#dos_type").value,
    concurrency:parseInt($("#dos_concurrency").value)||10,
    duration:parseFloat($("#dos_duration").value)||20,
    requests:parseInt($("#dos_requests").value)||200,
  };
  const r=await fetch("/api/dos",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({target,confirmed:true,options})});
  const d=await r.json();
  if(d.error){alert(d.error);return}
  $("#panel-live").style.display="";
  $("#log").textContent="";
  poll(d.id);
});
$("#stop").addEventListener("click",async()=>{
  if(cur)await fetch(`/api/jobs/${cur.id}/stop`,{method:"POST"});
});
document.querySelectorAll(".fbtn").forEach(b=>{
  b.addEventListener("click",()=>setFilter(b.dataset.f));
});
fetch("/api/health").then(r=>r.json()).then(d=>{$("#ver").textContent=d.version||""});
buildModules();
refreshHistory();
</script>
</body>
</html>
"""