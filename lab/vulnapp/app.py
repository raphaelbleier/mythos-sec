"""Deliberately vulnerable web app — Mythos engine ground truth.

Each route carries a known, labelled vulnerability so the test suite and the
evaluation harness can measure detection coverage and false-positive rate.
This app is for local testing only. Do not deploy it.

EASY ground truth (lab/vulnapp/ground_truth.json):
  /search?q=        reflected XSS
  /user?id=         error-based SQL injection (sqlite)
  /go?next=         open redirect
  /download?file=   path traversal
  /api/data         CORS: reflects arbitrary Origin with credentials
  /.env             exposed environment file
  /profile          insecure session cookie (no HttpOnly/Secure/SameSite)
  /safe?q=          NOT vulnerable (encoded) — must not be flagged

HARD ground truth (lab/vulnapp/ground_truth_hard.json):
  /render?name=     SSTI (Jinja2)
  /ping?host=       OS command injection (time-based sleep oracle)
  /blind?id=        blind SQL injection (time-based sleep oracle)
  /log?msg=         CRLF / header injection
  /fetch?url=       SSRF (server fetches the URL)
  /graphql          GraphQL introspection enabled
  /api/login        issues a JWT signed with a weak secret ("secret")
  /api/account?id=  IDOR / BOLA (no authorization check)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import re
import sqlite3
import time

import requests
from flask import Flask, request, redirect, Response, make_response, render_template_string

app = Flask(__name__)
JWT_SECRET = "secret"  # intentionally weak

ACCOUNTS = {
    1: {"user": "alice", "balance": 4200, "iban": "AT61_1904_3002_3457_3201"},
    2: {"user": "bob", "balance": 15, "iban": "AT61_1904_3002_3457_9999"},
    3: {"user": "carol", "balance": 999999, "iban": "AT61_1904_3002_3457_0001"},
}


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    con.executemany("INSERT INTO users VALUES (?, ?)",
                    [(1, "alice"), (2, "bob"), (3, "carol")])
    return con


def _jwt(payload: dict) -> str:
    def b64(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps(payload).encode())
    signing = f"{header}.{body}".encode()
    sig = b64(hmac.new(JWT_SECRET.encode(), signing, hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


# ---- EASY routes -------------------------------------------------------
@app.route("/")
def index():
    return """<html><head><title>Mythos VulnApp</title></head><body>
    <h1>VulnApp</h1>
    <a href="/search?q=hello">search</a>
    <a href="/user?id=1">user</a>
    <a href="/download?file=readme.txt">download</a>
    <a href="/go?next=/">go</a>
    <a href="/render?name=guest">render</a>
    <a href="/ping?host=localhost">ping</a>
    <a href="/blind?id=1">blind</a>
    <a href="/log?msg=hi">log</a>
    <a href="/fetch?url=http://localhost/">fetch</a>
    <a href="/api/account?id=1">account</a>
    <a href="/api/debug">debug</a>
    <a href="/dom">dom</a>
    <a href="/item/readme">item</a>
    <form action="/search" method="get"><input name="q"><input type="submit"></form>
    <script src="/static/app.js"></script>
    </body></html>"""


@app.route("/dom")
def dom():
    # VULN: DOM-based XSS — client-side sink writes location.hash into innerHTML.
    # The server response is benign; only a real browser executing the JS triggers it.
    return """<html><head><title>DOM</title></head><body>
    <div id="out"></div>
    <script>
      document.getElementById('out').innerHTML =
          decodeURIComponent(location.hash.slice(1));
    </script></body></html>"""


@app.route("/static/app.js")
def appjs():
    js = ('fetch("/api/data?token=1");const u="/profile?id=1";'
          'fetch("/graphql");fetch("/api/login?user=alice");')
    return Response(js, mimetype="application/javascript")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<html><body>Results for: {q}</body></html>"


@app.route("/safe")
def safe():
    q = request.args.get("q", "")
    return f"<html><body>Results for: {html.escape(q)}</body></html>"


@app.route("/user")
def user():
    uid = request.args.get("id", "1")
    con = _db()
    try:
        cur = con.execute(f"SELECT name FROM users WHERE id = {uid}")
        return {"users": [r[0] for r in cur.fetchall()]}
    except sqlite3.Error as e:
        return Response(f"sqlite3.OperationalError: {e}", status=500)
    finally:
        con.close()


@app.route("/go")
def go():
    return redirect(request.args.get("next", "/"), code=302)


@app.route("/download")
def download():
    name = request.args.get("file", "readme.txt")
    try:
        with open(name, "r", errors="replace") as fh:
            return Response(fh.read(), mimetype="text/plain")
    except OSError:
        return Response("not found", status=404)


@app.route("/api/data")
def api_data():
    origin = request.headers.get("Origin", "")
    resp = make_response({"data": [1, 2, 3]})
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@app.route("/openapi.json")
def openapi():
    # advertises the API surface so the engine builds query/path/body injection points
    return {
        "openapi": "3.0.0",
        "paths": {
            "/api/jsonlogin": {"post": {"requestBody": {"content": {"application/json": {
                "schema": {"properties": {"username": {}, "password": {}}}}}}}},
            "/item/{thing}": {"get": {"parameters": [{"name": "thing", "in": "path"}]}},
            "/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
            "/user": {"get": {"parameters": [{"name": "id", "in": "query"}]}},
        },
    }


@app.route("/.env")
def env_file():
    return Response("DB_PASSWORD=sup3rs3cret\nAPI_KEY=mythos_test_key\n",
                    mimetype="text/plain")


@app.route("/profile")
def profile():
    resp = make_response("profile")
    resp.set_cookie("session", "abc123")
    return resp


# ---- HARD routes -------------------------------------------------------
@app.route("/render")
def render():
    # VULN: SSTI — user input rendered as a Jinja2 template
    name = request.args.get("name", "guest")
    return render_template_string("<p>Hello " + name + "</p>")


@app.route("/ping")
def ping():
    # VULN: command injection — emulated time-based sleep oracle.
    # A real target would pass host to a shell; here we emulate the observable
    # (a delay) when a shell metacharacter + sleep is present, so detection is
    # deterministic and safe.
    host = request.args.get("host", "")
    m = re.search(r"sleep\s+(\d+)", host)
    if m and re.search(r"[;&|`$]", host):
        time.sleep(min(int(m.group(1)), 6))
    return Response(f"PING {host}", mimetype="text/plain")


@app.route("/blind")
def blind():
    # VULN: blind time-based SQLi — emulated sleep oracle on SLEEP()/pg_sleep().
    uid = request.args.get("id", "1")
    m = re.search(r"(?:SLEEP|pg_sleep)\s*\(\s*(\d+)\s*\)", uid, re.I)
    if m and ("'" in uid or " AND " in uid.upper() or " OR " in uid.upper()):
        time.sleep(min(int(m.group(1)), 6))
    return {"ok": True}


@app.route("/log")
def log():
    # VULN: CRLF / header injection — msg copied into a response header
    msg = request.args.get("msg", "")
    resp = make_response("logged")
    # Werkzeug blocks \r\n in header values, so emulate a permissive server
    # that splits the raw value into extra headers.
    for part in re.split(r"\r\n|\n", msg):
        if ":" in part and part is not msg:
            k, v = part.split(":", 1)
            resp.headers[k.strip()] = v.strip()
    if "\r\n" in msg or "\n" in msg:
        first = re.split(r"\r\n|\n", msg)
        for p in first[1:]:
            if ":" in p:
                k, v = p.split(":", 1)
                resp.headers[k.strip()] = v.strip()
    return resp


@app.route("/fetch")
def fetch():
    # VULN: SSRF — server fetches an attacker-supplied URL
    url = request.args.get("url", "")
    if not url:
        return Response("no url", status=400)
    try:
        r = requests.get(url, timeout=3)
        return Response(f"fetched {len(r.content)} bytes", mimetype="text/plain")
    except Exception as e:
        return Response(f"fetch error: {e}", status=502)


@app.route("/graphql", methods=["GET", "POST"])
def graphql():
    # VULN: introspection enabled
    return {"data": {"__schema": {"types": [
        {"name": "Query"}, {"name": "User"}, {"name": "Account"}]}}}


@app.route("/api/login")
def api_login():
    # issues a JWT signed with a weak secret
    user = request.args.get("user", "guest")
    token = _jwt({"sub": user, "role": "user"})
    return {"token": token}


@app.route("/api/account")
def api_account():
    # VULN: IDOR / BOLA — returns any account by id with no authorization
    aid = int(request.args.get("id", "1") or "1")
    return ACCOUNTS.get(aid, {"error": "not found"})


@app.route("/api/jsonlogin", methods=["POST"])
def api_jsonlogin():
    # VULN: SQLi via a JSON request-body field (API-style injection)
    data = request.get_json(silent=True) or {}
    u = data.get("username", "")
    con = _db()
    try:
        con.execute(f"SELECT name FROM users WHERE name = '{u}'")
        return {"ok": True}
    except sqlite3.Error as e:
        return Response(f"sqlite3.OperationalError: {e}", status=500)
    finally:
        con.close()


ORDERS = {1: {"owner": "tokenA", "item": "laptop", "total": 1299},
          2: {"owner": "tokenB", "item": "phone", "total": 799}}


@app.route("/api/order/<int:oid>")
def order(oid):
    # VULN: BOLA — returns the order regardless of which user's token is presented.
    # A correct implementation would check that the order's owner == caller.
    o = ORDERS.get(oid)
    if not o:
        return Response("not found", status=404)
    return {"id": oid, "item": o["item"], "total": o["total"], "owner": o["owner"]}


@app.route("/item/<thing>")
def item(thing):
    # VULN: SQLi via a PATH segment (REST-style path parameter injection)
    con = _db()
    try:
        con.execute(f"SELECT name FROM users WHERE name = '{thing}'")
        return {"ok": True, "thing": thing}
    except sqlite3.Error as e:
        return Response(f"sqlite3.OperationalError: {e}", status=500)
    finally:
        con.close()


@app.route("/api/debug")
def api_debug():
    # VULN: excessive data exposure — dumps every user's credentials unauth
    return {"users": [
        {"name": "alice", "password": "s3cr3t", "token": "ey.alice"},
        {"name": "bob", "password": "hunter2", "token": "ey.bob"},
    ]}


if __name__ == "__main__":
    import os
    # threaded so the dev server survives concurrent scanner traffic
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")),
            threaded=True, use_reloader=False)
