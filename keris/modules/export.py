"""Export sesi request sebagai perintah curl atau format Burp Suite (XML)."""

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional


def _header_list(headers: Optional[Dict]) -> List[str]:
    if not headers:
        return []
    return [f"{k}: {v}" for k, v in headers.items()]


def to_curl(method: str, url: str, headers: Optional[Dict] = None,
            data: Optional[str] = None, cookies: Optional[Dict] = None) -> str:
    """Bangun perintah curl setara dengan request."""
    parts = ["curl", "-X", method.upper(), "--max-time", "30"]
    for h in _header_list(headers):
        parts.append(f"-H '{h}'")
    if cookies:
        joined = "; ".join(f"{k}={v}" for k, v in cookies.items())
        parts.append(f"-H 'Cookie: {joined}'")
    if data:
        parts.append(f"--data-raw '{data}'")
    parts.append(f"'{url}'")
    return " ".join(parts)


def to_burp_xml(method: str, url: str, headers: Optional[Dict] = None,
                data: Optional[str] = None) -> str:
    """Bangun item request dalam format Burp Suite (item XML)."""
    # headers termasuk request line
    lines = [f"{method} {url.split('//', 1)[1].split('/', 1)[1] if '/' in url.split('//', 1)[1] else '/'} HTTP/1.1"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    lines.append(f"Host: {url.split('//', 1)[1].split('/', 1)[0]}")
    if data:
        lines.append(f"Content-Length: {len(data.encode())}")
    raw = "\r\n".join(lines) + "\r\n\r\n" + (data or "")

    item = ET.Element("item")
    ET.SubElement(item, "time").text = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    ET.SubElement(item, "url").text = url
    ET.SubElement(item, "host").text = url.split("//", 1)[1].split("/", 1)[0]
    ET.SubElement(item, "port").text = "443" if url.startswith("https") else "80"
    ET.SubElement(item, "protocol").text = "https" if url.startswith("https") else "http"
    ET.SubElement(item, "method").text = method.upper()
    ET.SubElement(item, "path").text = "/" + url.split("//", 1)[1].split("/", 1)[1] if "/" in url.split("//", 1)[1] else "/"
    ET.SubElement(item, "request", {"base64": "true"}).text = _b64(raw)
    ET.SubElement(item, "status").text = "200"
    ET.SubElement(item, "responselength").text = str(len(raw))
    ET.SubElement(item, "mimetype").text = ""

    # serialize
    xml_str = ET.tostring(item, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str


def _b64(s: str) -> str:
    import base64

    return base64.b64encode(s.encode()).decode()


def export_requests(findings: List[dict], fmt: str, target: str) -> str:
    """Export temuan sebagai curl/burp. Mengembalikan string teks."""
    blocks = []
    for f in findings:
        endpoint = f.get("endpoint", "")
        if not endpoint:
            continue
        method = "GET"
        # coba ambil method dari evidence bila ada
        ev = f.get("evidence", "")
        if "POST" in ev[:200]:
            method = "POST"
        if fmt == "burp":
            blocks.append(to_burp_xml(method, endpoint, {"User-Agent": "Keris"}))
        else:
            blocks.append(to_curl(method, endpoint, {"User-Agent": "Keris"}))
    if fmt == "burp":
        # gabung dalam <items>
        return f'<?xml version="1.0" encoding="UTF-8"?>\n<items>{chr(10).join(blocks)}</items>'
    return "\n\n".join(blocks) if blocks else "# Tidak ada endpoint untuk diexport"
