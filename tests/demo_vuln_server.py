"""Server demo lokal dengan kerentanan untuk menguji Keris.

Celah yang disimulasikan:
- SQL injection error-based pada /search?id=
- Directory listing terbuka pada /uploads/
- Tanpa security headers
- Endpoint /api/auth/login tanpa rate limit (selalu 401)
"""

import json
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


class VulnerableHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send(self, code, body, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        path = parsed.path

        if path == "/":
            html = b"<html><body><h1>Demo Vuln Site</h1><script src='/app.js'></script></body></html>"
            self._send(200, html, "text/html")
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
            self._send(302, b"", "text/html")
            return
        self._send(404, json.dumps({"error": "not found"}).encode())


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8099), VulnerableHandler)
    print("Demo vuln server running at http://127.0.0.1:8099")
    server.serve_forever()
