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
    """Satu pekerjaan scan yang berjalan sebagai subprocess."""

    def __init__(self, target: str, options: dict):
        self.id = uuid.uuid4().hex[:10]
        self.target = target
        self.options = options
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
            # pdf mungkin gagal saat generate; coba bangun ulang dari hasil scan
            if fmt == "pdf" and job.findings:
                self._regenerate(job, ["pdf"])
                if os.path.exists(fname):
                    self._file(fname, ctypes["pdf"])
                    return
            self._json({"error": "laporan tidak tersedia"}, 404)
            return
        self._file(fname, ctypes.get(fmt, ctypes["json"]))

    def _regenerate(self, job: ScanJob, formats):
        """Bangun ulang laporan dari findings yang sudah ada (mis. PDF gagal)."""
        try:
            from keris.report import write_report
            from keris.report_html import write_html_report

            recon = {"host": job.target, "stack": [], "security_headers": []}
            disc = {"api_endpoints": [], "js_assets": [], "secrets": []}
            options = {"mode": "Web UI Keris"}
            if "md" in formats:
                write_report(recon, disc, job.findings,
                             os.path.join(job.workdir, "report.md"), job.target, options)
            if "html" in formats:
                write_html_report(recon, disc, job.findings,
                                  os.path.join(job.workdir, "report.html"), job.target, options)
            if "pdf" in formats:
                from keris.report_pdf import write_pdf_report

                write_pdf_report(recon, disc, job.findings,
                                 os.path.join(job.workdir, "report.pdf"), job.target, options)
        except Exception:
            pass

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


def _worker(job: ScanJob):
    with job._lock:
        job.status = "running"
        job.started = time.time()
    workdir = os.path.join(ROOT, ".keris-ui", job.id)
    os.makedirs(workdir, exist_ok=True)
    job.workdir = workdir

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
        job.summary = result.get("summary", {})
        if rc in (0, 1):
            job.status = "done"
            job.progress = 100.0
            if job.findings:
                sevs = " ".join(f"{s}:{job.summary.get(s, 0)}"
                                for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
                job.log.append(f"[UI] Scan selesai dengan {len(job.findings)} temuan ({sevs})")
            else:
                job.log.append("[UI] Scan selesai, tidak ada temuan.")
        else:
            job.status = "error"
            job.error = result.get("error") or f"scan gagal (exit code {rc})"
        job.finished = time.time()


def _stop_job(job: ScanJob):
    job._stop = True
    if job.process and job.process.poll() is None:
        try:
            job.process.terminate()
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
  --bg:#0b0f17; --panel:#121826; --panel2:#0f1522; --border:#1e2a3f;
  --txt:#d7e0ea; --muted:#7a8aa0; --accent:#3b82f6; --ok:#22c55e;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
  font-family:"Segoe UI",system-ui,Arial,sans-serif}
header{padding:16px 24px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:12px}
header h1{font-size:18px;margin:0;letter-spacing:1px}
header h1 span{color:var(--accent)}
header .ver{color:var(--muted);font-size:12px}
.wrap{max-width:1100px;margin:0 auto;padding:20px}
.card{background:var(--panel);border:1px solid var(--border);
  border-radius:10px;padding:18px;margin-bottom:18px}
label{display:block;font-size:12px;color:var(--muted);margin:10px 0 4px}
input[type=text]{width:100%;padding:10px 12px;border-radius:8px;
  border:1px solid var(--border);background:var(--panel2);color:var(--txt);
  font-size:15px}
select{padding:9px 10px;border-radius:8px;border:1px solid var(--border);
  background:var(--panel2);color:var(--txt)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:700px){.grid{grid-template-columns:1fr}}
.chk{display:flex;align-items:center;gap:8px;font-size:13px;margin:5px 0}
.chk input{accent-color:var(--accent)}
button{cursor:pointer;border:none;border-radius:8px;padding:11px 18px;
  font-size:14px;font-weight:600}
#go{background:var(--accent);color:#fff;width:100%;margin-top:14px}
#go:disabled{opacity:.5;cursor:not-allowed}
#stop{background:#b91c1c;color:#fff;margin-left:8px}
.hint{color:var(--muted);font-size:12px;margin-top:6px}
.sev{display:inline-block;padding:2px 10px;border-radius:20px;font-size:11px;
  font-weight:700;text-align:center;min-width:70px}
.critical{background:#7f1d1d;color:#fca5a5}
.high{background:#881337;color:#fda4af}
.medium{background:#78350f;color:#fcd34d}
.low{background:#3f2d04;color:#fde68a}
.info{background:#1e3a5f;color:#93c5fd}
#status{margin-bottom:12px}
#progress{height:8px;background:var(--panel2);border-radius:4px;overflow:hidden;margin-top:8px}
#progress>div{height:100%;background:var(--accent);width:0%;transition:width .5s}
pre#log{background:#070b12;border:1px solid var(--border);border-radius:8px;
  padding:12px;height:260px;overflow-y:auto;font-size:12px;line-height:1.5;
  white-space:pre-wrap;word-break:break-word;color:#9fb3c8}
.cards{display:flex;gap:10px;flex-wrap:wrap}
.sum{flex:1;min-width:90px;background:var(--panel2);border:1px solid var(--border);
  border-radius:8px;padding:10px;text-align:center}
.sum b{display:block;font-size:22px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{border:1px solid var(--border);padding:8px 10px;text-align:left;vertical-align:top}
th{background:var(--panel2);color:var(--muted);font-size:11px;text-transform:uppercase}
tr.hidden{display:none}
.dl a{display:inline-block;margin:4px 6px 4px 0;padding:8px 14px;border-radius:8px;
  background:var(--panel2);border:1px solid var(--border);color:var(--txt);
  text-decoration:none;font-size:13px}
.dl a:hover{border-color:var(--accent)}
.empty{color:var(--muted);font-size:13px}
pre#log::-webkit-scrollbar,table::-webkit-scrollbar{height:8px;width:8px}
pre#log::-webkit-scrollbar-thumb,table::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
.error{color:#f87171}
footer{color:var(--muted);font-size:11px;text-align:center;padding:16px}
</style>
</head>
<body>
<header>
  <h1>KERIS <span>WEB UI</span></h1>
  <span class="ver">v<span id="ver"></span></span>
  <span style="flex:1"></span>
  <span class="ver" id="running"></span>
</header>
<div class="wrap">
  <div class="card">
    <form id="frm">
      <label for="target">Target URL</label>
      <input type="text" id="target" placeholder="https://example.com"
             value="http://127.0.0.1:8099" required>
      <div class="grid" style="margin-top:12px">
        <div>
          <label for="preset">Preset kecepatan</label>
          <select id="preset">
            <option value="fast">Fast (cepat, agresif)</option>
            <option value="stealth">Stealth (lambat, hati-hati)</option>
            <option value="aggressive">Aggressive (paling dalam)</option>
          </select>
        </div>
        <div>
          <label for="authorized">Izin serangan aktif</label>
          <div class="chk"><input type="checkbox" id="authorized">
            <span>Saya punya izin tertulis untuk menguji target</span></div>
        </div>
      </div>
      <label>Modul tambahan (semua aktif secara default)</label>
      <div class="grid" id="modgrid"></div>
      <div class="hint">Catatan: web cache poisoning, host header, WebSocket,
        JS analysis, sensitive data, hidden endpoint, fuzz, dsb. otomatis
        dijalankan pada setiap scan penuh.</div>
      <div style="display:flex;gap:8px">
        <button type="submit" id="go">MULAI SCAN</button>
        <button type="button" id="stop" style="display:none">HENTIKAN</button>
      </div>
    </form>
  </div>

  <div class="card" id="panel-live" style="display:none">
    <div id="status"><b id="stage">Menyiapkan...</b>
      <span class="ver" id="elapsed"></span></div>
    <div id="progress"><div></div></div>
    <pre id="log"></pre>
  </div>

  <div class="card" id="panel-results" style="display:none">
    <h3 style="margin-top:0">Hasil Scan</h3>
    <div class="cards" id="sumcards"></div>
    <div style="margin-top:14px" class="dl" id="downloads"></div>
    <table style="margin-top:14px" id="tbl">
      <thead><tr><th>Severity</th><th>Lokasi</th><th>Temuan</th></tr></thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>

  <div class="card" id="panel-history" style="display:none">
    <h3 style="margin-top:0">Riwayat Scan</h3>
    <div id="history"></div>
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
  const sev=window.filterSev;
  document.querySelectorAll("#tbody tr.f").forEach(tr=>{
    tr.classList.toggle("hidden", !(sev==="all"||tr.dataset.s===sev));
  });
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
    return `<div style="margin:8px 0;padding:8px;border:1px solid var(--border);border-radius:8px">
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
$("#stop").addEventListener("click",async()=>{
  if(cur)await fetch(`/api/jobs/${cur.id}/stop`,{method:"POST"});
});
fetch("/api/health").then(r=>r.json()).then(d=>{$("#ver").textContent=d.version||""});
buildModules();
refreshHistory();
</script>
</body>
</html>
"""