"""Import sesi HTTP dari HAR / Postman Collection + session recorder.

v0.14.0:
- `parse_har(path)` — ubah file HAR (1.2) menjadi daftar request terstruktur:
  method, url, headers, cookies, body.
- `parse_postman(path)` — ubah Postman Collection v2.x menjadi daftar request.
- `requests_from_file(path)` — auto-detect HAR / Postman Collection.
- `RequestsRecorder` — recorder ringan: menangkap request yang dikirim lewat
  `client.request(...)` selama satu alur, lalu diexport ke HAR/JSON. Dipakai
  untuk memutar ulang sesi terautentikasi tanpa menulis ulang kredensial.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from keris.core.logger import debug, info, ok, warn


@dataclass
class RecordedRequest:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    data: Optional[str] = None

    def to_har_entry(self, started: float = 0.0) -> Dict[str, Any]:
        headers = [{"name": k, "value": v} for k, v in self.headers.items()]
        cookies = [{"name": k, "value": v} for k, v in self.cookies.items()]
        body = self.data or ""
        entry = {
            "startedDateTime": "2024-01-01T00:00:00.000Z",
            "time": 0,
            "request": {
                "method": self.method.upper(),
                "url": self.url,
                "httpVersion": "HTTP/1.1",
                "cookies": cookies,
                "headers": headers,
                "queryString": [],
                "postData": {"mimeType": "application/x-www-form-urlencoded",
                             "text": body} if body else {},
                "headersSize": -1,
                "bodySize": len(body.encode("utf-8")) if body else 0,
            },
            "response": {
                "status": 0,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": [],
                "content": {"size": 0, "mimeType": "", "text": ""},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": 0,
            },
            "cache": {},
            "timings": {"send": 0, "wait": 0, "receive": 0},
        }
        return entry


class RequestsRecorder:
    """Recorder pasif: menangkap request dari KerisHTTP untuk replay sesi."""

    def __init__(self):
        self.entries: List[Dict[str, Any]] = []

    def record(self, method: str, url: str, headers: Dict[str, str],
               cookies: Optional[Dict[str, str]] = None, data: Optional[str] = None) -> None:
        self.entries.append(RecordedRequest(
            method=method, url=url, headers=dict(headers or {}),
            cookies=dict(cookies or {}), data=data,
        ).to_har_entry())

    def wrap(self, client):
        """Bungkus client.request() agar otomatis tercatat."""
        original = client.request

        def wrapped(method, url, **kwargs):
            r = original(method, url, **kwargs)
            headers = {k: v for k, v in (kwargs.get("headers") or {}).items()}
            cookies = {}
            data = kwargs.get("data") or kwargs.get("json")
            if isinstance(data, (dict, list)):
                import json as _json

                data = _json.dumps(data)
            self.record(method, str(url), headers, cookies, str(data) if data else None)
            return r

        client.request = wrapped
        return client

    def to_har(self) -> Dict[str, Any]:
        return {
            "log": {
                "version": "1.2",
                "creator": {"name": "Keris", "version": "0.14.0"},
                "entries": self.entries,
            }
        }

    def save(self, path: str) -> str:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_har(), f, indent=2)
        info(f"Sesi dicatat: {path} ({len(self.entries)} request)")
        return path


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _har_entries(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    log = data.get("log", {})
    if isinstance(log, dict):
        return log.get("entries", []) or []
    return []


def _headers_to_dict(header_list) -> Dict[str, str]:
    out = {}
    if not isinstance(header_list, list):
        return out
    for h in header_list:
        if isinstance(h, dict) and h.get("name"):
            out[h["name"]] = str(h.get("value", ""))
    return out


def _cookies_to_dict(cookie_list) -> Dict[str, str]:
    out = {}
    if not isinstance(cookie_list, list):
        return out
    for c in cookie_list:
        if isinstance(c, dict) and c.get("name"):
            out[c["name"]] = str(c.get("value", ""))
    return out


def _body_text(post_data) -> str:
    if not isinstance(post_data, dict):
        return ""
    return str(post_data.get("text", "") or "")


def parse_har(path: str) -> List[RecordedRequest]:
    """Parse file HAR 1.2 menjadi daftar RecordedRequest."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out = []
    for e in _har_entries(data):
        req = e.get("request", {})
        if not isinstance(req, dict) or not req.get("url"):
            continue
        r = RecordedRequest(
            method=str(req.get("method", "GET")).upper(),
            url=str(req["url"]),
            headers=_headers_to_dict(req.get("headers", [])),
            cookies=_cookies_to_dict(req.get("cookies", [])),
            data=_body_text(req.get("postData")),
        )
        out.append(r)
    return out


def _postman_items(items) -> List[Dict[str, Any]]:
    """Flatten Postman items (folder bersarang)."""
    out = []
    if not isinstance(items, list):
        return out
    for it in items:
        if not isinstance(it, dict):
            continue
        if it.get("request") is not None:
            out.append(it)
        elif it.get("item") is not None:
            out.extend(_postman_items(it.get("item")))
    return out


def parse_postman(path: str) -> List[RecordedRequest]:
    """Parse Postman Collection v2.x menjadi daftar RecordedRequest."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("info", {}).get("_postman_id") is None and "item" not in data:
        raise ValueError("Bukan Postman Collection v2")
    out = []
    for it in _postman_items(data.get("item", [])):
        req = it.get("request", {})
        if not isinstance(req, dict):
            continue
        url = req.get("url", {})
        if isinstance(url, dict):
            u = url.get("raw") or ""
            if not u:
                scheme = (url.get("protocol") or "http") + "://"
                host = ".".join(url.get("host", []))
                path = "/" + "/".join(url.get("path", []))
                u = scheme + host + path
        else:
            u = str(url)
        if not u:
            continue
        header_map = {}
        for h in req.get("header", []) or []:
            if isinstance(h, dict) and h.get("key"):
                header_map[h["key"]] = str(h.get("value", ""))
        body = req.get("body", {})
        raw = ""
        if isinstance(body, dict):
            raw = str(body.get("raw", "") or "")
            if body.get("mode") == "urlencoded":
                parts = []
                for kv in body.get("urlencoded", []) or []:
                    if isinstance(kv, dict):
                        parts.append(f"{kv.get('key','')}={kv.get('value','')}")
                raw = "&".join(parts)
        out.append(RecordedRequest(
            method=str(req.get("method", "GET")).upper(),
            url=u,
            headers=header_map,
            data=raw,
        ))
    return out


def requests_from_file(path: str) -> List[RecordedRequest]:
    """Auto-detect HAR vs Postman Collection dari isi file."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read(4096)
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(text)
        except Exception:
            raise ValueError(f"File JSON tidak valid: {path}")
        if "log" in data and "entries" in (data.get("log", {}) or {}):
            return parse_har(path)
        if "item" in data or (data.get("info", {}).get("_postman_id")):
            return parse_postman(path)
        raise ValueError(f"Format file tidak dikenal (bukan HAR/Postman): {path}")
    raise ValueError(f"File tidak berisi JSON valid: {path}")