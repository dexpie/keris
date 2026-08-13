"""Klien HTTP dengan dukungan auth (cookie, token, basic), retry, dan proxy."""

import time
from typing import Optional, Dict, Any
import threading

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from keris.core.logger import debug


class KerisHTTP:
    """Pembungkus requests.Session dengan fitur pentest."""

    def __init__(
        self,
        token: Optional[str] = None,
        cookie: Optional[str] = None,
        basic_auth: Optional[tuple] = None,
        proxy: Optional[str] = None,
        timeout: float = 20.0,
        retries: int = 1,
        user_agent: Optional[str] = None,
        insecure: bool = False,
        delay: float = 0.0,
        extra_headers: Optional[dict] = None,
    ) -> None:
        self.session = requests.Session()
        self.timeout = timeout
        self.token = token
        self.cookie_header = cookie
        self.basic_auth = basic_auth
        self.insecure = insecure
        self.delay = delay
        self.last_request: Optional[requests.PreparedRequest] = None
        self._rate_lock = threading.Lock()
        self._last_request_time = 0.0

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
            # dukungan SOCKS5 (mis. Tor: socks5h://127.0.0.1:9050)
            if proxy.lower().startswith("socks"):
                try:
                    import socks  # noqa: F401
                except ImportError:
                    raise RuntimeError(
                        "Proxy SOCKS membutuhkan PySocks. Install: pip install PySocks"
                    )

        if insecure:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        retry = Retry(
            total=retries,
            connect=retries,
            read=retries,
            backoff_factor=0.2,
            # jangan retry 5xx: dalam konteks pentest, 500/503 justru sinyal penting
            # (mis. error-based SQLi) dan bukan kondisi jaringan transient.
            status_forcelist=[429],
            allowed_methods=None,  # semua method
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.session.headers.update(
            {
                "User-Agent": user_agent
                or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
            }
        )
        if extra_headers:
            self.session.headers.update(extra_headers)

    def _apply_auth(self, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = dict(headers or {})
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if self.cookie_header:
            h["Cookie"] = self.cookie_header
        return h

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Any = None,
        json: Any = None,
        allow_redirects: bool = True,
        stream: bool = False,
        **kwargs: Any,
    ) -> requests.Response:
        h = self._apply_auth(headers)
        # sesuaikan header konten untuk body
        if json is not None and "Content-Type" not in {k.lower() for k in h}:
            h.setdefault("Content-Type", "application/json")
        if data is not None and "Content-Type" not in {k.lower() for k in h}:
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")

        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", not self.insecure)
        try:
            # throttle untuk menghindari overload / deteksi rate limit
            if self.delay > 0:
                with self._rate_lock:
                    wait = self.delay - (time.monotonic() - self._last_request_time)
                    if wait > 0:
                        time.sleep(wait)
                    self._last_request_time = time.monotonic()
            resp = self.session.request(
                method, url, headers=h, data=data, json=json,
                allow_redirects=allow_redirects, stream=stream, **kwargs
            )
        except requests.exceptions.RequestException:
            raise
        self.last_request = resp.request
        return resp

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("DELETE", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("OPTIONS", url, **kwargs)

    def close(self) -> None:
        self.session.close()
