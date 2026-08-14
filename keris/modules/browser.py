"""Headless browser module (Playwright, optional).

Renders JS-heavy targets, runs a browser-side DOM pass (DOM XSS sinks,
leaked secrets, hidden links) and can capture screenshots as evidence.

Requires: pip install playwright && playwright install chromium
The import is lazy so the core toolkit works without it.
"""

import os
import re
from typing import Dict, List, Optional

from keris.core.logger import info, ok, warn

_DOM_SINKS = ["innerHTML", "outerHTML", "document.write", "eval(", "insertAdjacentHTML"]
_LEAK_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[=:]\s*['\"][^'\"]+"), "HIGH"),
    (re.compile(r"(?i)aws[_-]?(access[_-]?key)?[^=]{0,20}=['\"][A-Z0-9]{16,}"), "HIGH"),
]


def _import_playwright():
    try:
        from playwright.sync_api import sync_playwright
        return sync_playwright
    except ImportError:
        raise ImportError(
            "Modul browser butuh Playwright: pip install playwright && "
            "python -m playwright install chromium"
        )


def _scan_dom(text: str) -> List[Dict]:
    findings = []
    for sink in _DOM_SINKS:
        if sink in text:
            findings.append({
                "severity": "MEDIUM",
                "title": f"DOM XSS sink terdeteksi di halaman render: {sink}",
                "endpoint": "page",
                "detail": f"Setelah eksekusi JS, halaman mengandung sink berbahaya '{sink}'. "
                          "Jika diumpan input user tanpa sanitasi bisa jadi XSS client-side.",
                "evidence": text[max(0, text.find(sink) - 120): text.find(sink) + 120],
                "source": "browser",
            })
    for pat, sev in _LEAK_PATTERNS:
        m = pat.search(text)
        if m:
            findings.append({
                "severity": sev,
                "title": "Kemungkinan secret bocor di halaman render",
                "endpoint": "page",
                "detail": "Pola secret (API key/token) ditemukan di DOM hasil render browser.",
                "evidence": m.group(0)[:200],
                "source": "browser",
            })
    return findings


def browser_pass(base: str, screenshot: Optional[str] = None,
                 login: Optional[Dict] = None, timeout: int = 30) -> List[Dict]:
    """Runs a headless browser pass. Returns findings. Raises ImportError if Playwright missing."""
    sync_playwright = _import_playwright()
    findings: List[Dict] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            if login and login.get("url") and login.get("username"):
                info(f"Auto-login browser: {login['url']}")
                page.goto(login["url"], timeout=timeout * 1000)
                page.fill("input[name=username], input[name=email], input[id=username]", login["username"], timeout=5000)
                page.fill("input[type=password], input[name=password], input[id=password]", login.get("password", ""), timeout=5000)
                page.click("button[type=submit], input[type=submit]", timeout=5000)
                page.wait_for_load_state("networkidle", timeout=timeout * 1000)
            info(f"Browser render: {base}")
            page.goto(base, timeout=timeout * 1000)
            page.wait_for_load_state("networkidle", timeout=timeout * 1000)
            text = page.content()
            findings.extend(_scan_dom(text))

            # hidden links discovered at runtime
            links = page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href).filter(h => h.startsWith(location.origin))")
            uniq = sorted(set(links))
            if uniq:
                info(f"Browser menemukan {len(uniq)} link internal via render")

            if screenshot:
                os.makedirs(os.path.dirname(os.path.abspath(screenshot)) or ".", exist_ok=True)
                page.screenshot(path=screenshot, full_page=True)
                ok(f"Screenshot: {screenshot}")
        except Exception as e:
            warn(f"Browser pass: {e}")
        finally:
            browser.close()
    return findings