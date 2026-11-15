"""Dangling-reference target — fixture for the supply-chain/takeover package.

Two things in one small server, because `scripts/takeover` needs both ends:

1. A victim page that references names which do not exist:
     GET /                      HTML + a real CSP header
                                - a third-party <script src> with NO integrity=
                                - a <link rel=preconnect> to a dangling S3 bucket
                                - an <img> on a dangling GCS bucket
                                - a bucket name built in a JS string, never a URL
                                - CSP report-uri and form-action on dead domains
     GET /static/app.js         a bundle with //# sourceMappingURL
     GET /static/app.js.map     a source map whose sourceRoot is another bucket
     GET /api/config            an app config that discloses the OAuth
                                redirect_uri allowlist, one entry of which is a
                                dead domain
     Every hostname on those pages ends in `.invalid` or is an obviously fake
     name under a real provider suffix, so nothing here can resolve and nothing
     here can be claimed by accident.

2. Stand-ins for three providers' own unclaimed-host responses, so the
   fingerprint matcher can be pointed at this server with
   `takeover ... --map <host>=http://127.0.0.1:5030/fp/<service>` instead of at
   the real provider:
     GET /fp/s3                 404 + S3 <Code>NoSuchBucket</Code>
     GET /fp/github-pages       404 + "There isn't a GitHub Pages site here."
     GET /fp/heroku             404 + "No such app"
     GET /fp/live               200, a normal page: the negative control, so a
                                run can show the matcher saying not-dangling

Fake credentials are the single canary string `MYTHOS_LAB_CANARY`, as in the
rest of the lab, so a run greps for one token and nothing here resembles a real
key.

Local lab only. Do not deploy it. Standard library only, so it also runs
directly on the host for a quick check:

    python3 lab/takeoverlab/app.py            # 127.0.0.1:5030
"""

from __future__ import annotations

import http.server
import json
import os
import socketserver

PORT = int(os.environ.get("PORT", "5030"))
# Bound to loopback by default. The compose file publishes it on 127.0.0.1 too;
# inside the container BIND is 0.0.0.0 because the port mapping is what keeps it
# off the network.
BIND = os.environ.get("BIND", "127.0.0.1")

CANARY = "MYTHOS_LAB_CANARY"

# Every one of these is unresolvable on purpose. `.invalid` is reserved by
# RFC 2606 and can never be registered; the provider-suffix names are nonsense
# labels under real suffixes, which is what makes them match the fingerprint
# table's CNAME suffixes without pointing at anything real.
DEAD_SCRIPT_HOST = "cdn.takeoverlab-vendor.invalid"
DEAD_BUCKET = "takeoverlab-legacy-assets.s3.amazonaws.com"
DEAD_GCS = "takeoverlab-img.storage.googleapis.com"
DEAD_MAP_BUCKET = "takeoverlab-sourcemaps.s3.eu-west-1.amazonaws.com"
DEAD_REPORT = "csp-reports.takeoverlab-monitoring.invalid"
DEAD_FORM_ACTION = "pay.takeoverlab-checkout.invalid"
DEAD_REDIRECT = "legacy-app.takeoverlab-partner.invalid"
LIVE_SCRIPT_HOST = "cdn.takeoverlab-ok.invalid"

CSP = (
    "default-src 'self'; "
    f"script-src 'self' https://{DEAD_SCRIPT_HOST} https://{LIVE_SCRIPT_HOST}; "
    f"img-src 'self' https://{DEAD_GCS}; "
    f"form-action 'self' https://{DEAD_FORM_ACTION}; "
    f"report-uri https://{DEAD_REPORT}/csp"
)

PAGE = f"""<!doctype html>
<html><head>
<title>takeoverlab</title>
<!-- a third-party script with no integrity=: a takeover of this host is stored
     XSS on every page that loads it -->
<script src="https://{DEAD_SCRIPT_HOST}/widget.js"></script>
<!-- the same vendor, pinned, for the SRI-coverage denominator -->
<script src="https://{LIVE_SCRIPT_HOST}/pinned.js"
        integrity="sha384-{CANARY}0000000000000000000000000000000000000000000"
        crossorigin="anonymous"></script>
<link rel="preconnect" href="https://{DEAD_BUCKET}">
<link rel="stylesheet" href="/static/app.css">
</head>
<body>
<h1>takeoverlab</h1>
<img src="https://{DEAD_GCS}/logo.png" alt="logo">
<form method="POST" action="https://{DEAD_FORM_ACTION}/pay">
  <input name="card"><button>pay</button>
</form>
<script src="/static/app.js"></script>
</body></html>
"""

# The bucket name never appears as a URL here: it is concatenated at runtime,
# which is the case a regex over <script src> misses.
BUNDLE = f"""// takeoverlab bundle
var ASSET_BUCKET = "{DEAD_BUCKET}";
var API_KEY = "{CANARY}_takeoverlab_api_key";
function asset(p) {{ return "https://" + ASSET_BUCKET + "/" + p; }}
//# sourceMappingURL=/static/app.js.map
"""

SOURCEMAP = json.dumps({
    "version": 3,
    "file": "app.js",
    "sourceRoot": f"https://{DEAD_MAP_BUCKET}/src/",
    "sources": [f"https://{DEAD_MAP_BUCKET}/src/index.ts", "webpack://app/boot.ts"],
    "names": [],
    "mappings": "",
})

CONFIG = json.dumps({
    "client_id": "takeoverlab-client",
    "client_secret": f"{CANARY}_takeoverlab_client_secret",
    "redirect_uris": [
        "http://127.0.0.1:5030/cb",
        f"https://{DEAD_REDIRECT}/oauth/callback",
    ],
    "note": "the second redirect_uri's host no longer resolves",
}, indent=1)

S3_NOSUCHBUCKET = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    "<Error><Code>NoSuchBucket</Code>"
    "<Message>The specified bucket does not exist</Message>"
    "<BucketName>takeoverlab-legacy-assets</BucketName>"
    "<RequestId>MYTHOSLAB000000</RequestId></Error>"
)
GH_PAGES_404 = (
    "<!DOCTYPE html><html><head><title>Site not found &middot; GitHub Pages</title>"
    "</head><body><h1>404</h1>"
    "<p>There isn't a GitHub Pages site here.</p></body></html>"
)
HEROKU_404 = (
    "<!DOCTYPE html><html><head><title>No such app</title></head><body>"
    "<h1>No such app</h1><p>There's nothing here, yet.</p></body></html>"
)

ROUTES = {
    "/": (200, "text/html; charset=utf-8", PAGE, True),
    "/static/app.js": (200, "application/javascript", BUNDLE, False),
    "/static/app.js.map": (200, "application/json", SOURCEMAP, False),
    "/static/app.css": (200, "text/css",
                        f"body{{background:url(https://{DEAD_GCS}/bg.png)}}", False),
    "/api/config": (200, "application/json", CONFIG, False),
    "/fp/s3": (404, "application/xml", S3_NOSUCHBUCKET, False),
    "/fp/github-pages": (404, "text/html; charset=utf-8", GH_PAGES_404, False),
    "/fp/heroku": (404, "text/html; charset=utf-8", HEROKU_404, False),
    "/fp/live": (200, "text/html; charset=utf-8",
                 "<html><body><h1>takeoverlab tenant</h1>"
                 "<p>a claimed, serving host: the negative control</p>"
                 "</body></html>", False),
}

INDEX_NOTE = (
    "takeoverlab: / is the victim page. /fp/<s3|github-pages|heroku|live> are "
    "provider stand-ins for --map. See lab/README.md."
)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "takeoverlab/1.0"

    def _send(self, code, ctype, body, with_csp=False):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        if with_csp:
            self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/__routes":
            return self._send(200, "application/json",
                              json.dumps({"note": INDEX_NOTE,
                                          "routes": sorted(ROUTES)}, indent=1))
        route = ROUTES.get(path)
        if route is None:
            return self._send(404, "text/plain", INDEX_NOTE)
        code, ctype, body, csp = route
        self._send(code, ctype, body, csp)

    do_HEAD = do_GET

    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        self.rfile.read(length)
        self._send(405, "text/plain",
                   "takeoverlab serves GET only; the form action points at a dead host "
                   "on purpose")

    def log_message(self, fmt, *args):
        print("takeoverlab " + fmt % args, flush=True)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server((BIND, PORT), Handler) as srv:
        print(f"takeoverlab on http://{BIND}:{PORT}  ({INDEX_NOTE})", flush=True)
        srv.serve_forever()
