"""Cache poisoning / deception / normalization fixture — two tiers that disagree.

Stdlib only, loopback only, deliberately vulnerable. Two servers:

  origin   normalizes like a framework: strips path parameters (`;x=1`), decodes
           %-escapes, resolves dot segments, routes `/account<anything>` to the
           account page, reads the LAST value of a repeated query parameter, and
           reflects `X-Forwarded-Host` into an absolute URL on `/`.
  edge     a cache in front of it whose key is (method, raw request target with
           only the FIRST value of each parameter kept). No header is in the key,
           `Vary` is ignored, the path is never decoded or normalized, and any
           path whose last segment ends in a static extension is stored even when
           the origin said `private, no-store`.

That is five bugs on purpose:

  1. unkeyed `X-Forwarded-Host` reflected into a cached response (poisoning)
  2. `.css`/`.js` suffix on a private route stored and served anonymously
     (deception)
  3. a GET carrying a body or a method-override header reaches the origin's
     POST handler and is cached under the GET key (fat GET)
  4. `?cb=A&cb=B` keys on A and is answered with B (parameter cloaking)
  5. the edge forwards `%2e%2e`, `%2f`, `;` and dot segments verbatim, so the
     path the cache keyed is not the path the origin served (normalization)

Every fake credential is the single canary string `MYTHOS_LAB_CANARY`.

A client `Cache-Control: no-cache` or `Pragma: no-cache` evicts the entry and
refetches, which is what `scripts/cache` uses to clean up after itself.

    python3 lab/cachelab/cachelab.py                  # edge 5027, origin 5028
    python3 lab/cachelab/cachelab.py --edge-port 8080 --origin-port 8081

Both bind 127.0.0.1 unless --bind says otherwise. Local lab only. Do not deploy.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import re
import socket
import socketserver
import sys
import threading
import time
import urllib.parse

CANARY = "MYTHOS_LAB_CANARY"
SESSION = "owner-session-MYTHOS_LAB_CANARY"
STATIC_EXT = (".css", ".js", ".png", ".ico", ".svg", ".woff2", ".gif", ".jpg")

# ------------------------------------------------------------------- origin


def resolve(target: str) -> tuple[str, list[tuple[str, str]]]:
    """What a framework sees: path parameters gone, escapes decoded, dots resolved."""
    path, _, query = target.partition("?")
    path = urllib.parse.unquote(path)
    # `;x=1` path parameters, per segment, the way Tomcat and friends drop them.
    segments = [s.partition(";")[0] for s in path.split("/")]
    out: list[str] = []
    for seg in segments:
        if seg == ".":
            continue
        if seg == "..":
            if out[1:]:
                out.pop()
            continue
        out.append(seg)
    path = "/".join(out) or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path, urllib.parse.parse_qsl(query, keep_blank_values=True)


def last(params: list[tuple[str, str]], name: str, default: str = "") -> str:
    """The origin reads the LAST occurrence. The edge keys on the first."""
    vals = [v for k, v in params if k == name]
    return vals[-1] if vals else default


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "cachelab-origin/1.0"
    sys_version = ""

    def log_message(self, fmt, *args):  # quiet
        pass

    def reply(self, status: int, body: str, ctype="text/html; charset=utf-8",
              cache="no-store", extra: dict | None = None) -> None:
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Origin-Served", "cachelab")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def body_bytes(self) -> bytes:
        n = self.headers.get("Content-Length")
        if n and n.isdigit():
            return self.rfile.read(min(int(n), 65536))
        return b""

    def effective_method(self, params: list[tuple[str, str]], body: bytes) -> str:
        """Bug 3: the override is honoured on a GET, which is how a fat GET lands
        in the POST handler while the cache still sees a cacheable GET."""
        for h in ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"):
            if self.headers.get(h):
                return self.headers[h].strip().upper()
        if last(params, "_method"):
            return last(params, "_method").strip().upper()
        form = urllib.parse.parse_qsl(body.decode("latin-1", "replace"),
                                      keep_blank_values=True)
        if last(form, "_method"):
            return last(form, "_method").strip().upper()
        return self.command

    def route(self) -> None:
        path, params = resolve(self.path)
        body = self.body_bytes()
        method = self.effective_method(params, body)
        session = ""
        for cookie in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = cookie.strip().partition("=")
            if k == "session":
                session = v
        # Bug 1: an absolute URL built from a client-supplied header.
        host = (self.headers.get("X-Forwarded-Host")
                or self.headers.get("Host") or "cachelab")

        if path == "/" or path == "/index.html":
            cb = last(params, "cb")
            return self.reply(200, (
                "<!doctype html><title>cachelab</title>\n"
                f'<link rel="canonical" href="http://{host}/">\n'
                f'<script src="http://{host}/static/app.js"></script>\n'
                f"<p>front page, cb={cb}</p>\n"), cache="public, max-age=60")

        if path.startswith("/static/"):
            return self.reply(200, f"/* {path} */\n", ctype="text/css",
                              cache="public, max-age=300")

        if path == "/account" or path.startswith("/account"):
            # Bug 2's origin half: the route matches whatever follows /account,
            # so /account/profile.css is the account page.
            if session != SESSION:
                return self.reply(401, "<p>sign in</p>\n")
            return self.reply(200, (
                "<h1>account</h1>\n"
                "<p>owner: owner@cachelab.invalid</p>\n"
                f"<p>api_token: {CANARY}</p>\n"
                f"<p>reset_token: reset-{CANARY}</p>\n"),
                cache="private, no-store")

        if path == "/api/item":
            if method != "POST":
                return self.reply(405, '{"error":"POST required"}\n',
                                  ctype="application/json")
            return self.reply(200, (
                '{"method":"POST","item":"widget-42",'
                f'"origin_saw":"{self.command}","price":19}}\n'),
                ctype="application/json", cache="public, max-age=60")

        if path == "/echo":
            return self.reply(200, json.dumps({
                "path": path, "raw": self.path, "method": method,
                "xfh": self.headers.get("X-Forwarded-Host") or "",
                "body_len": len(body), "cb": last(params, "cb"),
                # The last occurrence, which is the half of bug 4 the edge
                # never keyed.
                "x_last": last(params, "x")}) + "\n",
                ctype="application/json", cache="public, max-age=60")

        return self.reply(404, "<p>not found</p>\n")

    do_GET = do_POST = do_HEAD = route


# --------------------------------------------------------------------- edge


def cache_key(method: str, target: str) -> str:
    """Bug 4 and bug 5 live here: no header is keyed, the path is never
    normalized, and only the FIRST value of each parameter reaches the key."""
    path, _, query = target.partition("?")
    seen: dict[str, str] = {}
    for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True):
        seen.setdefault(k, v)
    canon = "&".join(f"{k}={v}" for k, v in sorted(seen.items()))
    return f"{method} {path}?{canon}"


def looks_static(target: str) -> bool:
    """Bug 2's edge half: extension beats the origin's `Cache-Control`."""
    path = target.partition("?")[0]
    return path.lower().endswith(STATIC_EXT)


def cacheable(method: str, target: str, status: int, headers: list[tuple[str, str]]) -> bool:
    if method != "GET" or status != 200:
        return False
    if looks_static(target):
        return True
    cc = " ".join(v.lower() for k, v in headers if k.lower() == "cache-control")
    return "public" in cc or "max-age" in cc and "no-store" not in cc


class Edge(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, origin):
        self.origin = origin
        self.store: dict[str, tuple[float, int, list[tuple[str, str]], bytes]] = {}
        self.hits: dict[str, int] = {}
        self.lock = threading.Lock()
        super().__init__(addr, EdgeHandler)


HEAD_END = re.compile(rb"\r?\n\r?\n")


class EdgeHandler(socketserver.StreamRequestHandler):
    timeout = 10

    def handle(self) -> None:
        head = bytearray()
        while not HEAD_END.search(head):
            chunk = self.rfile.read(1)
            if not chunk:
                return
            head += chunk
            if len(head) > 65536:
                return
        text = head.decode("latin-1")
        lines = text.replace("\r\n", "\n").rstrip("\n").split("\n")
        bits = lines[0].split(" ")
        if len(bits) < 2:
            return self.raw_reply(400, [], b"bad request line\n")
        method, target = bits[0], bits[1]
        # Folded continuation lines are joined here, which is what hides a
        # header from a cache that keyed before the join — not that this one
        # keys any header at all.
        hdrs: list[tuple[str, str]] = []
        for line in lines[1:]:
            if line[:1] in (" ", "\t") and hdrs:
                hdrs[-1] = (hdrs[-1][0], hdrs[-1][1] + " " + line.strip())
            elif ":" in line:
                k, _, v = line.partition(":")
                hdrs.append((k.strip(), v.strip()))
        get = lambda n: next((v for k, v in hdrs if k.lower() == n), "")  # noqa: E731

        body = b""
        length = get("content-length")
        if length.isdigit():
            body = self.rfile.read(min(int(length), 65536))
        elif "chunked" in get("transfer-encoding").lower():
            body = self.read_chunked()

        key = cache_key(method, target)
        bust = "no-cache" in get("cache-control").lower() or "no-cache" in get("pragma").lower()
        srv = self.server
        if bust:
            with srv.lock:
                srv.store.pop(key, None)
                srv.hits.pop(key, None)
        else:
            with srv.lock:
                entry = srv.store.get(key)
                if entry:
                    stored, status, out, payload = entry
                    srv.hits[key] = srv.hits.get(key, 0) + 1
                    n = srv.hits[key]
                    return self.raw_reply(status, out, payload, "HIT",
                                          int(time.time() - stored), n)

        try:
            status, out, payload = self.upstream(method, target, hdrs, body)
        except OSError as e:
            return self.raw_reply(502, [], f"edge: origin unreachable: {e}\n".encode())
        if cacheable(method, target, status, out):
            with srv.lock:
                srv.store[key] = (time.time(), status, out, payload)
        return self.raw_reply(status, out, payload, "MISS", 0, 0)

    def read_chunked(self) -> bytes:
        out = bytearray()
        while True:
            line = self.rfile.readline(64)
            if not line:
                break
            try:
                n = int(line.strip().split(b";")[0] or b"0", 16)
            except ValueError:
                break
            if n == 0:
                self.rfile.readline(64)
                break
            out += self.rfile.read(n)
            self.rfile.readline(8)
        return bytes(out)

    def upstream(self, method, target, hdrs, body):
        """Forward the request target verbatim: no decode, no normalization."""
        keep = [(k, v) for k, v in hdrs
                if k.lower() not in ("connection", "transfer-encoding", "content-length",
                                     "accept-encoding", "host")]
        host, port = self.server.origin
        req = bytearray(f"{method} {target} HTTP/1.1\r\n".encode("latin-1"))
        req += f"Host: {host}:{port}\r\n".encode()
        for k, v in keep:
            req += f"{k}: {v}\r\n".encode("latin-1")
        req += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
        req += body
        with socket.create_connection((host, port), 10) as s:
            s.sendall(bytes(req))
            got = bytearray()
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                got += chunk
        split = HEAD_END.search(got)
        if not split:
            return 502, [], b"edge: unparsable origin response\n"
        text = got[:split.start()].decode("latin-1")
        payload = bytes(got[split.end():])
        lines = text.replace("\r\n", "\n").split("\n")
        status = int(lines[0].split(" ")[1]) if len(lines[0].split(" ")) > 1 else 502
        out = []
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                if k.strip().lower() not in ("content-length", "connection",
                                             "transfer-encoding"):
                    out.append((k.strip(), v.strip()))
        return status, out, payload

    def raw_reply(self, status, hdrs, payload, xcache="MISS", age=0, hits=0):
        reason = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found",
                  405: "Method Not Allowed", 502: "Bad Gateway"}.get(status, "OK")
        head = bytearray(f"HTTP/1.1 {status} {reason}\r\n".encode())
        for k, v in hdrs:
            head += f"{k}: {v}\r\n".encode("latin-1")
        head += f"Content-Length: {len(payload)}\r\n".encode()
        head += b"Server: cachelab-edge/1.0\r\nVia: 1.1 mythos-cachelab (cachelab)\r\n"
        head += f"X-Cache: {xcache}\r\nAge: {age}\r\nX-Cache-Hits: {hits}\r\n".encode()
        head += b"Connection: close\r\n\r\n"
        try:
            self.wfile.write(bytes(head) + payload)
        except OSError:
            pass


# ---------------------------------------------------------------------- run


def start(bind="127.0.0.1", edge_port=5027, origin_port=5028):
    """Both servers on background threads. Returns (edge_addr, origin_addr, stop)."""
    o = http.server.ThreadingHTTPServer((bind, origin_port), Origin)
    o.daemon_threads = True
    e = Edge((bind, edge_port), (bind, o.server_address[1]))
    for srv in (o, e):
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    def stop():
        for srv in (e, o):
            srv.shutdown()
            srv.server_close()

    return e.server_address, o.server_address, stop


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--edge-port", type=int, default=5027)
    ap.add_argument("--origin-port", type=int, default=5028)
    a = ap.parse_args()
    # Inside the container the servers must bind 0.0.0.0 for docker to publish
    # them; the compose file publishes on 127.0.0.1 only, so the exposure is the
    # same. Run on the host and the guard holds.
    if (a.bind not in ("127.0.0.1", "::1", "localhost")
            and os.environ.get("CACHELAB_ALLOW_ANY_BIND") != "1"):
        print("cachelab: this fixture is deliberately vulnerable; refusing to bind "
              f"{a.bind}. Loopback only (set CACHELAB_ALLOW_ANY_BIND=1 inside a "
              "container whose ports are published on loopback).", file=sys.stderr)
        return 2
    edge, origin, _ = start(a.bind, a.edge_port, a.origin_port)
    print(f"cachelab edge   http://{edge[0]}:{edge[1]}")
    print(f"cachelab origin http://{origin[0]}:{origin[1]}  (session={SESSION})")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
