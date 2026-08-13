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
            html = b"<html><body><h1>Demo Vuln Site</h1></body></html>"
            self._send(200, html, "text/html")
            return

        if path == "/uploads/":
            listing = b"<html><body><h1>Index of /uploads/</h1><a href='file1.jpg'>file1.jpg</a><a href='proof.png'>proof.png</a></body></html>"
            self._send(200, listing, "text/html")
            return

        if path in ("/backup.zip", "/db.sql", "/.env.bak"):
            self._send(200, b"SECRET_DATA_PLACEHOLDER", "application/octet-stream")
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

        self._send(404, json.dumps({"error": "not found"}).encode())

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/auth/login":
            self._send(401, json.dumps({"error": "invalid credentials"}).encode())
            return
        self._send(404, json.dumps({"error": "not found"}).encode())


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8099), VulnerableHandler)
    print("Demo vuln server running at http://127.0.0.1:8099")
    server.serve_forever()
