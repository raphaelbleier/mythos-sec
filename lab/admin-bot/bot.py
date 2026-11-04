"""Admin bot for stored/blind XSS: POST /visit {"url": "..."} opens the URL in
headless Chromium carrying an admin cookie (ADMIN_COOKIE_NAME/VALUE from env).
Only hosts in ALLOWED_HOSTS are visited, and the cookie is scoped to that host."""
import json, os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

NAME = os.environ.get("ADMIN_COOKIE_NAME", "token")
VALUE = os.environ.get("ADMIN_COOKIE_VALUE", "")
ALLOWED = set(os.environ.get("ALLOWED_HOSTS", "vulnapp,juiceshop,dvwa,vampi,dvga,vuln-bank-web").split(","))


def visit(url):
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path="/usr/bin/chromium", args=["--no-sandbox"])
        ctx = b.new_context()
        if VALUE:
            ctx.add_cookies([{"name": NAME, "value": VALUE, "url": url}])
        page = ctx.new_page()
        try:
            page.goto(url, wait_until="networkidle", timeout=15000)
            page.wait_for_timeout(2000)
        finally:
            b.close()


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        code, msg = 404, "not found"
        if self.path == "/visit":
            try:
                url = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))["url"]
                u = urlparse(url)
                if u.scheme not in ("http", "https") or u.hostname not in ALLOWED:
                    code, msg = 403, "host not allowed"
                else:
                    visit(url); code, msg = 200, "visited"
            except Exception as e:
                code, msg = 400, str(e)[:200]
        self.send_response(code); self.end_headers(); self.wfile.write(msg.encode())
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"POST /visit {url}")


HTTPServer(("0.0.0.0", 8000), H).serve_forever()
