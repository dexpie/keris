"""Helper auth: membangun header/sesi dari berbagai jenis kredensial."""

from typing import Optional, Tuple

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info


def build_client(
    token: Optional[str] = None,
    cookie: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    proxy: Optional[str] = None,
    insecure: bool = False,
    timeout: float = 20.0,
) -> KerisHTTP:
    """Bangun KerisHTTP dengan auth yang diberikan."""
    basic = (username, password) if username and password else None
    return KerisHTTP(
        token=token,
        cookie=cookie,
        basic_auth=basic,
        proxy=proxy,
        insecure=insecure,
        timeout=timeout,
    )


def parse_cookie_string(cookie_str: str) -> dict:
    """Parse string cookie menjadi dict."""
    result = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip()
    return result
