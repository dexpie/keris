"""AI Pentesting Agent (v0.16.0): LLM-agent yang merencanakan & menjalankan serangan.

Agent menerima goal (mis. "Ambil alih server example.com"), lalu:

1. **Planning** - memecah goal menjadi langkah-langkah via LLM (OpenAI-compatible)
   atau planner rule-based (fallback offline).
2. **Execution** - menjalankan modul `keris` sebagai subprocess
   (`python -m keris <subcommand> ...`) atau fungsi impor langsung.
3. **Evaluation** - menilai hasil tiap langkah (LLM atau rule-based).
4. **Next-step** - memutuskan langkah selanjutnya berdasarkan hasil.
5. **Checkpoint** - state tersimpan ke file JSON sehingga bisa di-resume.
6. **Report** - `agent-report.md` berisi seluruh proses dan hasil.

Konfigurasi LLM lewat env:
- `KERIS_LLM_API_KEY`  (wajib untuk mode LLM)
- `KERIS_LLM_BASE_URL` (default https://api.openai.com/v1)
- `KERIS_LLM_MODEL`    (default gpt-4o-mini)

GUARD: eksekusi modul serangan tetap menghormati `--authorized`; tanpa itu
agent hanya menjalankan langkah non-destruktif.
"""

import json
import os
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional

import requests

from keris.core.logger import debug, info, ok, warn

AGENT_REPORT = "agent-report.md"
AGENT_STATE = "agent-state.json"

# peta tindakan -> subcommand keris
ACTION_COMMANDS = {
    "recon": "recon",
    "passive": "passive",
    "discover": "discover",
    "scan": "scan",
    "hidden": "hidden",
    "hunt": "hunt",
    "exploit": "exploit",
    "shell": "shell",
    "pivot": "pivot",
    "gitdump": "gitdump",
    "authbypass": "authbypass",
    "spray": "spray",
    "dbdump": "dbdump",
    "fuzz": "fuzz",
    "takeover": "takeover",
    "waf": "waf",
    "tls": "tls",
    "dns": "dns",
    "subdomain": "subdomain",
}

# urutan langkah default planner rule-based
_DEFAULT_PLAN = [
    ("recon", "Recon: identifikasi stack, header, teknologi"),
    ("discover", "Discovery: kumpulkan endpoint API, JS, secret"),
    ("scan", "Scan: deteksi kerentanan + laporan"),
    ("hunt", "Hunt: cari kredensial/secret yang bocor"),
    ("exploit", "Exploit: konfirmasi kerentanan aktif"),
]


# ---------------------------------------------------------------------------
# LLM client (OpenAI-compatible)
# ---------------------------------------------------------------------------

class LLMClient:
    """Klien chat-completion OpenAI-compatible minimal (via requests)."""

    def __init__(self, api_key: str = "", base_url: str = "",
                 model: str = "", timeout: float = 60.0):
        self.api_key = api_key or os.environ.get("KERIS_LLM_API_KEY", "")
        self.base_url = (base_url or os.environ.get("KERIS_LLM_BASE_URL")
                         or "https://api.openai.com/v1").rstrip("/")
        self.model = model or os.environ.get("KERIS_LLM_MODEL") or "gpt-4o-mini"
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def chat(self, messages: List[Dict], temperature: float = 0.2,
             max_tokens: int = 1200) -> str:
        """Kirim percakapan; return konten asisten."""
        if not self.available:
            raise RuntimeError("KERIS_LLM_API_KEY belum di-set")
        resp = requests.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"model": self.model, "messages": messages,
                  "temperature": temperature, "max_tokens": max_tokens},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"] or ""

    def json_chat(self, messages: List[Dict], **kw) -> Dict:
        """Chat yang diharapkan mengembalikan JSON murni."""
        content = self.chat(messages, **kw)
        return _parse_json(content)


def _parse_json(text: str) -> Dict:
    """Parsing JSON dari output LLM (tahan terhadap ```json fence)."""
    t = (text or "").strip()
    if t.startswith("```"):
        t = t.strip("`")
        if t.startswith("json"):
            t = t[4:]
        t = t.strip()
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        # ambil blok { ... } terakhir yang valid
        import re
        for m in re.finditer(r"\{.*\}", t, re.DOTALL):
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                continue
    return {}


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

class Planner:
    """Memecah goal menjadi daftar langkah."""

    def __init__(self, llm: Optional[LLMClient] = None):
        self.llm = llm or LLMClient()

    def plan(self, goal: str, target: str) -> List[Dict]:
        """Kembalikan daftar step dict {action, description, params}."""
        if self.llm.available:
            try:
                return self._plan_llm(goal, target)
            except Exception as e:
                warn(f"Planner LLM gagal, fallback rule-based: {e}")
        return self._plan_rule(goal, target)

    def _plan_llm(self, goal: str, target: str) -> List[Dict]:
        sys_prompt = (
            "Kamu adalah perencana serangan keamanan web (pentest agent). "
            "Pecah goal menjadi langkah konkret. Untuk tiap langkah pilih "
            "action dari: " + ", ".join(sorted(ACTION_COMMANDS)) + ". "
            "Kembalikan JSON: {\"steps\":[{\"action\":\"...\","
            "\"description\":\"...\",\"params\":{}}]} . "
            "Max 8 langkah. Hanya JSON, tanpa teks lain."
        )
        data = self.llm.json_chat([
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": f"Goal: {goal}\nTarget: {target}"},
        ])
        steps = data.get("steps", [])
        if not isinstance(steps, list):
            return self._plan_rule(goal, target)
        out = []
        for s in steps[:8]:
            action = str(s.get("action", "")).strip().lower()
            if action in ACTION_COMMANDS:
                out.append({"action": action,
                            "description": str(s.get("description", action)),
                            "params": s.get("params", {}) or {}})
        return out or self._plan_rule(goal, target)

    def _plan_rule(self, goal: str, target: str) -> List[Dict]:
        out = []
        for action, desc in _DEFAULT_PLAN:
            out.append({"action": action, "description": desc, "params": {}})
        # goal menyebutkan kata kunci -> tambah langkah relevan
        g = goal.lower()
        for kw, action, desc in (
            ("shell", "shell", "Shell: siapkan payload/konfirmasi RCE"),
            ("pivot", "pivot", "Pivot: tunnel ke jaringan internal"),
            ("db", "dbdump", "DB dump: ekstraksi data"),
            ("takeover", "takeover", "Takeover: cek subdomain takeover"),
            ("api", "fuzz", "Fuzz: uji parameter API"),
        ):
            if kw in g and action not in {a["action"] for a in out}:
                out.append({"action": action, "description": desc, "params": {}})
        return out


# ---------------------------------------------------------------------------
# Module runner
# ---------------------------------------------------------------------------

def build_command(action: str, target: str, params: Dict,
                  authorized: bool = False, extra: List[str] = None) -> List[str]:
    """Bangun argv `python -m keris <action> <target> ...`."""
    cmd = [sys.executable, "-m", "keris", ACTION_COMMANDS.get(action, action)]
    if target:
        cmd.append(target)
    for key, val in (params or {}).items():
        if val is True:
            cmd.append(f"--{key}")
        elif val not in (None, "", False):
            cmd.append(f"--{key}")
            cmd.append(str(val))
    for flag in (extra or []):
        cmd.append(flag)
    if authorized:
        cmd.append("--authorized")
    cmd += ["--json-output", "agent-step.json", "--quiet"]
    return cmd


class AgentRunner:
    """Eksekusi langkah agent: subprocess atau fungsi kustom."""

    def __init__(self, executor: Optional[Callable] = None):
        self._executor = executor  # untuk testing: (action, target, params) -> dict

    def run(self, action: str, target: str, params: Dict,
            authorized: bool = False) -> Dict:
        if self._executor is not None:
            return self._executor(action, target, params)
        cmd = build_command(action, target, params, authorized=authorized)
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=300)
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "timeout", "command": " ".join(cmd)}
        except OSError as e:
            return {"ok": False, "error": str(e), "command": " ".join(cmd)}
        out = {}
        if os.path.exists("agent-step.json"):
            try:
                with open("agent-step.json", "r", encoding="utf-8") as f:
                    out = json.load(f)
            except (OSError, json.JSONDecodeError):
                pass
            finally:
                try:
                    os.remove("agent-step.json")
                except OSError:
                    pass
        findings = out.get("findings", []) if isinstance(out, dict) else []
        return {"ok": r.returncode == 0, "exit_code": r.returncode,
                "findings": findings, "command": " ".join(cmd),
                "stdout": (r.stdout or b"").decode("utf-8", "replace")[-2000:]}


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

class Evaluator:
    """Menilai hasil langkah; putuskan lanjut/henti."""

    def __init__(self, llm: Optional[LLMClient] = None):
        self.llm = llm or LLMClient()

    def evaluate(self, step: Dict, result: Dict, goal: str) -> Dict:
        if self.llm.available:
            try:
                return self._evaluate_llm(step, result, goal)
            except Exception:
                pass
        return self._evaluate_rule(step, result)

    def _evaluate_llm(self, step: Dict, result: Dict, goal: str) -> Dict:
        sys_prompt = (
            "Kamu adalah pentester. Nilai hasil satu langkah serangan dan "
            "putuskan tindakan berikutnya. Kembalikan JSON: "
            "{\"verdict\":\"success|partial|failed\",\"reason\":\"...\","
            "\"next_action\":\"...\"} . next_action boleh salah satu action "
            "valid atau \"done\". Hanya JSON."
        )
        data = self.llm.json_chat([
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": json.dumps({
                "goal": goal, "step": step, "result": {
                    "ok": result.get("ok"),
                    "exit_code": result.get("exit_code"),
                    "num_findings": len(result.get("findings", [])),
                }})},
        ])
        verdict = str(data.get("verdict", "partial")).lower()
        if verdict not in ("success", "partial", "failed"):
            verdict = "partial"
        return {"verdict": verdict,
                "reason": str(data.get("reason", "")),
                "next_action": str(data.get("next_action", "done")).lower()}

    def _evaluate_rule(self, step: Dict, result: Dict) -> Dict:
        findings = result.get("findings", [])
        if not result.get("ok", False) and result.get("error"):
            return {"verdict": "failed",
                    "reason": f"eksekusi gagal: {result.get('error')}",
                    "next_action": ""}
        sevs = [str(f.get("severity", "")).upper() for f in findings]
        if any(s in ("CRITICAL", "HIGH") for s in sevs):
            return {"verdict": "success",
                    "reason": f"{len(findings)} temuan ({','.join(sevs[:3])})",
                    "next_action": ""}
        if findings:
            return {"verdict": "partial",
                    "reason": f"{len(findings)} temuan (low/medium)",
                    "next_action": ""}
        return {"verdict": "failed",
                "reason": "tidak ada temuan yang dihasilkan",
                "next_action": ""}


# ---------------------------------------------------------------------------
# State / checkpoint
# ---------------------------------------------------------------------------

class AgentState:
    """Checkpoint state agent: simpan & resume."""

    def __init__(self, path: str = AGENT_STATE):
        self.path = path
        self.data = {"goal": "", "target": "", "created": 0,
                     "steps": [], "results": {}, "done": False}

    def load(self) -> "AgentState":
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    self.data = loaded
            except (OSError, json.JSONDecodeError):
                pass
        return self

    def save(self) -> None:
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2, default=str)
        except OSError as e:
            warn(f"Checkpoint gagal disimpan: {e}")

    def clear(self) -> None:
        if os.path.exists(self.path):
            try:
                os.remove(self.path)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

class Agent:
    """Orkestrator utama: plan -> execute -> evaluate -> next."""

    def __init__(self, goal: str, target: str, max_steps: int = 10,
                 verbose: bool = False, authorized: bool = False,
                 llm: Optional[LLMClient] = None, planner: Optional[Planner] = None,
                 evaluator: Optional[Evaluator] = None, runner: Optional[AgentRunner] = None,
                 state: Optional[AgentState] = None):
        self.goal = goal
        self.target = target
        self.max_steps = max_steps
        self.verbose = verbose
        self.authorized = authorized
        self.llm = llm or LLMClient()
        self.planner = planner or Planner(self.llm)
        self.evaluator = evaluator or Evaluator(self.llm)
        self.runner = runner or AgentRunner()
        self.state = state or AgentState()
        self.state.data["goal"] = goal
        self.state.data["target"] = target
        if not self.state.data.get("created"):
            self.state.data["created"] = int(time.time())

    def run(self) -> Dict:
        info(f"AGENT: goal='{self.goal}' target={self.target}")
        if self.verbose:
            debug(f"LLM tersedia: {self.llm.available} "
                  f"({self.llm.model})")
        if not self.authorized:
            warn("Tanpa --authorized, agent hanya menjalankan langkah non-destruktif.")

        steps = self.state.data.get("steps") or self.planner.plan(self.goal, self.target)
        if not self.state.data.get("steps"):
            self.state.data["steps"] = steps
        for i, step in enumerate(steps):
            if self.state.data["done"]:
                break
            if self.state.data["results"].get(str(step.get("action"))):
                continue  # sudah dieksekusi (resume)
            if i >= self.max_steps:
                break
            if self.verbose:
                info(f"STEP {i + 1}/{len(steps)}: "
                     f"{step.get('action')} - {step.get('description')}")
            result = self.runner.run(
                step["action"], self.target, step.get("params", {}),
                authorized=self.authorized)
            if self.verbose:
                info(f"  -> exit={result.get('exit_code')} "
                     f"findings={len(result.get('findings', []))}")
            eval_res = self.evaluator.evaluate(step, result, self.goal)
            self.state.data["results"][step["action"]] = {
                "step": step, "result": result, "eval": eval_res,
                "ts": int(time.time()),
            }
            self.state.save()
            if self.verbose:
                debug(f"  verdict={eval_res.get('verdict')} "
                      f"reason={eval_res.get('reason')}")
            if eval_res.get("verdict") == "success":
                ok(f"Langkah {step['action']} berhasil: {eval_res.get('reason')}")
                nxt = eval_res.get("next_action") or ""
                if nxt and nxt in ACTION_COMMANDS:
                    desc = f"Lanjutan dari {step['action']}"
                    if not any(s["action"] == nxt for s in steps):
                        steps.append({"action": nxt, "description": desc, "params": {}})
                        self.state.data["steps"] = steps
            elif eval_res.get("verdict") == "failed" and i == 0:
                warn(f"Langkah pertama gagal: {eval_res.get('reason')}")
        self.state.data["done"] = True
        self.state.save()
        return self.summary()

    def summary(self) -> Dict:
        res = self.state.data["results"]
        total = len(res)
        ok_count = sum(1 for r in res.values() if r["eval"]["verdict"] == "success")
        all_findings = []
        for r in res.values():
            all_findings.extend(r["result"].get("findings", []))
        return {"goal": self.goal, "target": self.target,
                "steps_executed": total, "successes": ok_count,
                "total_findings": len(all_findings),
                "findings": all_findings,
                "results": res,
                "state_file": self.state.path}

    def report_markdown(self) -> str:
        """Buat konten agent-report.md."""
        s = self.summary()
        lines = ["# Agent Report", ""]
        lines.append(f"**Goal:** {s['goal']}")
        lines.append(f"**Target:** `{s['target']}`")
        lines.append(f"**Langklah dieksekusi:** {s['steps_executed']}")
        lines.append(f"**Berhasil:** {s['successes']}")
        lines.append(f"**Total temuan:** {s['total_findings']}")
        lines.append("")
        lines.append("## Proses")
        lines.append("")
        for action, rec in s["results"].items():
            step = rec["step"]
            ev = rec["eval"]
            lines.append(f"### {step.get('action')}: {ev.get('verdict')}")
            lines.append("")
            lines.append(f"- Deskripsi: {step.get('description', '')}")
            lines.append(f"- Hasil: {ev.get('reason', '')}")
            lines.append(f"- Command: `{rec['result'].get('command', '')}`")
            fnds = rec["result"].get("findings", [])
            if fnds:
                lines.append("- Temuan:")
                for f_ in fnds[:5]:
                    lines.append(f"  - `[{f_.get('severity')}]` "
                                 f"{f_.get('title')} @ `{f_.get('endpoint')}`")
            lines.append("")
        lines.append("## Rekomendasi")
        lines.append("")
        lines.append("Tinjau setiap temuan dan lakukan verifikasi manual "
                     "sebelum pelaporan akhir.")
        lines.append("")
        return "\n".join(lines)

    def write_report(self, path: str = AGENT_REPORT) -> str:
        md = self.report_markdown()
        with open(path, "w", encoding="utf-8") as f:
            f.write(md)
        return path


def run_agent(goal: str, target: str, max_steps: int = 10,
              verbose: bool = False, authorized: bool = False,
              resume: bool = False, state_file: str = AGENT_STATE,
              report_file: str = AGENT_REPORT,
              executor: Optional[Callable] = None) -> Dict:
    """Fungsi utama agent; return ringkasan dict."""
    state = AgentState(state_file).load()
    if not resume:
        state.clear()
        state = AgentState(state_file)
    runner = AgentRunner(executor=executor)
    agent = Agent(goal, target, max_steps=max_steps, verbose=verbose,
                  authorized=authorized, runner=runner, state=state)
    summary = agent.run()
    report = agent.write_report(report_file)
    ok(f"Agent selesai. Report: {report}")
    return summary