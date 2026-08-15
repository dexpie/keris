"""Server demo lokal dengan kerentanan untuk menguji Keris.

Celah yang disimulasikan:
- SQL injection error-based pada /search?id=
- Directory listing terbuka pada /uploads/
- Tanpa security headers
- Endpoint /api/auth/login tanpa rate limit (selalu 401)
"""

import json
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


class VulnerableHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send(self, code, body, content_type="application/json", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        path = parsed.path

        if path == "/":
            html = (b"<html><body><h1>Demo Vuln Site</h1>"
                    b"<script src='/app.js'></script>"
                    b"<a href='/api/fetch?url=http://example.com'>fetch</a>"
                    b"</body></html>")
            self._send(200, html, "text/html")
            return

        if path == "/favicon.ico":
            # favicon statis (dummy PNG) agar fingerprint bisa dihitung
            import base64
            png = base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
            )
            self._send(200, png, "image/x-icon")
            return

        if path == "/refl":
            # cache poisoning + host header: refleksikan X-Forwarded-Host & Host
            xfh = self.headers.get("X-Forwarded-Host", "")
            host = self.headers.get("Host", "")
            html = (
                f"<html><meta content='https://{xfh}/'><a href='//{host}/reset'>"
                f"<script src='//{xfh}/x.js'></script></body></html>"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Cache", "HIT")
            self.send_header("Cache-Control", "public, max-age=60")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return

        if path == "/uploads/":
            listing = b"<html><body><h1>Index of /uploads/</h1><a href='file1.jpg'>file1.jpg</a><a href='proof.png'>proof.png</a></body></html>"
            self._send(200, listing, "text/html")
            return

        if path in ("/backup.zip", "/db.sql", "/.env.bak"):
            self._send(200, b"SECRET_DATA_PLACEHOLDER", "application/octet-stream")
            return

        if path == "/.git/HEAD":
            self._send(200, b"ref: refs/heads/main\n", "text/plain")
            return

        if path == "/.git/config":
            self._send(200, b"[core]\n\turl = https://github.com/acme/secret-repo.git\n", "text/plain")
            return

        if path == "/.git/index":
            # DIRC header: version 2, 2 entries, then padded entries
            import struct

            entries = [
                (b"config/credentials.json", b"a" * 20),
                (b"src/app/secrets.py", b"b" * 20),
            ]
            data = b"DIRC" + struct.pack(">II", 2, len(entries))
            for name, sha in entries:
                header = struct.pack(">IIIIIIIIII", 0, 0, 0, 0, 0o100644, 0, 0, 0, 0, 0) + sha + struct.pack(">H", len(name))
                entry = header + name + b"\x00"
                pad = (8 - len(entry) % 8) % 8
                data += entry + b"\x00" * pad
            self._send(200, data, "application/octet-stream")
            return

        if path == "/.env":
            self._send(200, b"DB_PASSWORD='sup3rsecret123'\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", "text/plain")
            return

        if path == "/admin":
            self._send(200, json.dumps({"admin_panel": True, "secret": "ADMIN_SECRET_XYZ"}).encode())
            return

        if path == "/api/auth/login":
            self._send(401, json.dumps({"error": "invalid credentials"}).encode())
            return

        if path == "/login":
            # form login: GET menampilkan form, POST memvalidasi kredensial
            html = ("<html><body><form action='/login' method='post'>"
                    "<input name='username'><input name='password' type='password'>"
                    "<button type='submit'>Login</button></form></body></html>").encode()
            self._send(200, html, "text/html")
            return

        if path == "/search":
            # SQLi error-based
            ident = qs.get("id", ["1"])[0]
            try:
                conn = sqlite3.connect(":memory:")
                cur = conn.cursor()
                cur.execute("SELECT * FROM users WHERE id = " + ident)
                rows = cur.fetchall()
                conn.close()
                self._send(200, json.dumps({"rows": rows}).encode())
            except Exception as e:
                body = json.dumps({"error": f"SQLite error: {e}"}).encode()
                self._send(500, body)
            return

        # JWT: endpoint menerima token lemah (secret "secret") — vuln simulasi
        if path in ("/api/me", "/api/user"):
            auth = self.headers.get("Authorization", "")
            tok = qs["token"][0] if "token" in qs else (auth.split(" ", 1)[1] if auth.startswith("Bearer ") else "")
            if tok:
                try:
                    import base64
                    import json as _j
                    import hmac
                    import hashlib
                    hdr, pay, sig = tok.split(".")
                    def _b64d(s):
                        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
                    payload = _j.loads(_b64d(pay))
                    # verifikasi signature dengan secret "secret"
                    signing = (hdr + "." + pay).encode()
                    expect = base64.urlsafe_b64encode(hmac.new(b"secret", signing, hashlib.sha256).digest()).rstrip(b"=").decode()
                    if hmac.compare_digest(sig, expect) and payload.get("admin"):
                        self._send(200, json.dumps({"ok": True, "user": payload.get("user", "?"), "admin": True}).encode())
                    else:
                        self._send(403, json.dumps({"error": "forbidden"}).encode())
                except Exception:
                    self._send(400, json.dumps({"error": "bad token"}).encode())
            else:
                self._send(401, json.dumps({"error": "no token"}).encode())
            return

        # area terproteksi: memerlukan cookie session=admin-ok
        if path in ("/dashboard", "/account", "/profile"):
            if self.headers.get("Cookie") == "session=admin-ok":
                body = f"<html><body><h1>{path}</h1><p>account detail: password='secret', nik='320101...'</p></body></html>".encode()
                self._send(200, body, "text/html")
            else:
                self._send(302, b"", {"Location": "/login"})
            return

        # race: operasi sekali-pakai (claim kupon). Server sengaja lambat -> double-apply
        if path in ("/api/claim", "/api/coupon", "/api/topup", "/api/vote"):
            time.sleep(0.3)
            self._send(200, json.dumps({"ok": True, "applied": 1, "remaining": "none"}).encode())
            return

        if path == "/search2":
            # reflected XSS
            q = qs.get("q", [""])[0]
            html = f"<html><body><p>Search result for: {q}</p></body></html>".encode()
            self._send(200, html, "text/html")
            return

        if path == "/api/users":
            # IDOR-like: return data user
            uid = qs.get("uid", ["1"])[0]
            self._send(200, json.dumps({"user": {"id": uid, "name": "Admin", "email": "admin@demo.local", "secret_key": "SK12345"}}).encode())
            return

        if path == "/api/fetch":
            # SSRF: fetch URL dari parameter `url` (tanpa validasi!)
            import urllib.request

            target_url = qs.get("url", [""])[0]
            if not target_url:
                self._send(400, json.dumps({"error": "url required"}).encode())
                return
            try:
                if "169.254.169.254" in target_url and "security-credentials" in target_url:
                    # simulasi metadata AWS untuk pengujian SSRF
                    fake = json.dumps({
                        "Code": "Success",
                        "Type": "AWS-HMAC",
                        "AccessKeyId": "AKIAFAKEFORSSRFTEST",
                        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        "Token": "FAKETOKENFORSSRF",
                        "Expiration": "2027-01-01T00:00:00Z",
                    })
                    self._send(200, fake.encode())
                    return
                import urllib.parse as _up
                up = _up.urlparse(target_url)
                if up.hostname == "127.0.0.1":
                    banners = {3306: b"8.0.36-MySQL\x00", 6379: b"-ERR unknown command\r\n",
                               9200: b'{"version":{"number":"8.11.0"}}',
                               5432: b"PostgreSQL 15.3", 5000: b"flask app"}
                    if up.port in banners:
                        self._send(200, banners[up.port])
                        return
                with urllib.request.urlopen(target_url, timeout=4) as resp:
                    data = resp.read(1024)
                self._send(200, json.dumps({"fetched": data.decode("utf-8", "replace")}).encode())
            except Exception as e:
                self._send(502, json.dumps({"error": str(e)}).encode())
            return

        if path == "/openapi.json":
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "Demo API", "version": "1.0"},
                "paths": {
                    "/api/users": {
                        "get": {
                            "summary": "Get user",
                            "parameters": [
                                {"name": "uid", "in": "query", "schema": {"type": "integer"}},
                            ],
                            "responses": {"200": {"description": "ok"}},
                        }
                    },
                    "/search": {
                        "get": {
                            "summary": "Search",
                            "parameters": [
                                {"name": "id", "in": "query", "required": True,
                                 "schema": {"type": "integer"}},
                            ],
                            "responses": {"200": {"description": "ok"}},
                        }
                    },
                },
            }
            self._send(200, json.dumps(spec).encode())
            return

        if path == "/fetch":
            # SSRF: mengambil URL dari param
            url = qs.get("url", [""])[0]
            if url:
                try:
                    import urllib.request

                    with urllib.request.urlopen(url, timeout=5) as resp:
                        data = resp.read(200)
                    self._send(200, json.dumps({"fetched": data.decode(errors="replace")}).encode())
                except Exception as e:
                    self._send(502, json.dumps({"error": str(e)}).encode())
            else:
                self._send(400, json.dumps({"error": "url param required"}).encode())
            return

        if path == "/login":
            html = b"""<html><body>
            <form method="POST" action="/login">
              <input type="hidden" name="csrf" value="TOKEN123">
              <input type="text" name="username">
              <input type="password" name="password">
              <input type="submit" name="submit" value="Login">
            </form></body></html>"""
            self._send(200, html, "text/html")
            return

        if path == "/dashboard":
            self._send(200, json.dumps({"protected": True, "user": "demo"}).encode())
            return

        if path == "/poison":
            # web cache poisoning: refleksikan X-Forwarded-Host + penanda cache
            host = self.headers.get("X-Forwarded-Host", "")
            html = f"<html><meta content='https://{host}/'><script src='//{host}/x.js'></script></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Cache", "HIT")
            self.send_header("Cache-Control", "public, max-age=60")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return

        if path == "/reset":
            # host header injection: endpoint reset yang merefleksikan Host
            h = self.headers.get("Host", "")
            body = f"<html><p>Link reset: https://{h}/reset-password?token=SECRET123</p></html>".encode()
            self._send(200, body, "text/html")
            return

        if path == "/app.js":
            body = (
                "var a = document.getElementById('x').innerHTML = location.hash;\n"
                "eval(location.search.slice(1));\n"
                "fetch('/api/internal/users');\n"
                "var k = 'AKIAIOSFODNN7EXAMPLE';\n"
            ).encode()
            self._send(200, body, "text/javascript")
            return

        self._send(404, json.dumps({"error": "not found"}).encode())

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/auth/login":
            self._send(401, json.dumps({"error": "invalid credentials"}).encode())
            return
        if parsed.path == "/login":
            from urllib.parse import unquote_plus
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8", "replace")
            vals = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
            user = unquote_plus(vals.get("username", ""))
            pw = unquote_plus(vals.get("password", ""))
            if user == "admin" and pw == "password123":
                html = b"<html><body><h1>Welcome, admin</h1><a href='/logout'>logout</a></body></html>"
                self._send(200, html, "text/html", {"Set-Cookie": "session=admin-ok; Path=/; HttpOnly"})
            else:
                self._send(401, json.dumps({"error": "invalid credentials"}).encode())
            return
        if parsed.path in ("/api/claim", "/api/coupon", "/api/topup", "/api/vote"):
            time.sleep(0.3)
            self._send(200, json.dumps({"ok": True, "applied": 1, "remaining": "none"}).encode())
            return
        self._send(404, json.dumps({"error": "not found"}).encode())


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8099), VulnerableHandler)
    print("Demo vuln server running at http://127.0.0.1:8099")
    server.serve_forever()
