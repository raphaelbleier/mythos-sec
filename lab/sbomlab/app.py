"""Stale front end with a published source map — sbomlab fixture.

Ground truth for `scripts/sbom`. Everything a black-box inventory can read is
here, and every row has a known right answer:

  GET /                      HTML: two external scripts (one with `integrity`,
                             one without), a CDN stylesheet, a Google font, a
                             wasm module, and a CSP that trusts three hosts
  GET /static/app.bundle.js  bundle with banner comments, runtime version
                             assignments and webpack `./node_modules/<pkg>/`
                             module paths
  GET /static/app.bundle.js.map  source map whose `sources` are node_modules
                             paths and whose `sourcesContent` carries two
                             package.json files with versions
  GET /static/img-decode.wasm    wasm with a `producers` custom section
  GET /static/vendor.css     stylesheet with a framework banner
  GET /config.json           fake client config with the canary credential
  GET /__inventory           the ground truth, so a test can assert against it

Response headers name a stale `nginx/1.18.0` and `Express/4.16.0`.

Every fake credential is the single canary string `MYTHOS_LAB_CANARY`, as in
the other capability targets. Nothing here is exploitable by design — the bug
class is *what the target tells you about its dependencies*. Bound to
127.0.0.1 only. Local lab only. Do not deploy it.
"""

from __future__ import annotations

import http.server
import json
import os
import socketserver

CANARY = "MYTHOS_LAB_CANARY"

# The right answers. `/__inventory` serves this, so a check never has to
# restate what the fixture ships.
GROUND_TRUTH = {
    "client": [
        {"name": "jquery", "version": "1.12.4", "marker": "banner+runtime"},
        {"name": "angularjs", "version": "1.5.8", "marker": "banner+runtime"},
        {"name": "lodash", "version": "3.10.1", "marker": "banner+runtime"},
        {"name": "moment", "version": "2.18.1", "marker": "sourcemap-package-json"},
        {"name": "dompurify", "version": "2.0.7", "marker": "sourcemap-package-json"},
        {"name": "bootstrap", "version": "3.3.7", "marker": "css-banner"},
    ],
    "server": [
        {"name": "nginx", "version": "1.18.0", "marker": "server-header"},
        {"name": "express", "version": "4.16.0", "marker": "x-powered-by"},
    ],
    "sri": {"with_integrity": ["cdn.jsdelivr.net"],
            "without_integrity": ["cdn.sbom-analytics.test", "cdn.jsdelivr.net (css)"]},
}

INDEX = """<!doctype html>
<html><head><meta charset="utf-8"><title>sbomlab</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' cdn.jsdelivr.net cdn.sbom-analytics.test *.s3.amazonaws.com 'unsafe-inline'; style-src 'self' cdn.jsdelivr.net fonts.googleapis.com">
<link rel="stylesheet" href="/static/vendor.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@3.3.7/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap">
<link rel="preload" as="fetch" href="/static/img-decode.wasm" crossorigin="anonymous">
</head><body>
<h1>sbomlab</h1>
<form action="/pay" method="post"><input name="card"><button>pay</button></form>
<script src="/static/app.bundle.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jquery@1.12.4/dist/jquery.min.js"
        integrity="sha384-nvAa0+6Qg9clwYCGGPpDQLVpLNn0fRaROjHqs13t4Ggj3Ez496YnClsNJDh56hcV"
        crossorigin="anonymous"></script>
<script src="https://cdn.sbom-analytics.test/track/v2/t.js" async></script>
<script>fetch('/static/img-decode.wasm').then(r=>WebAssembly.instantiateStreaming(r));</script>
</body></html>
"""

# Banners, runtime assignments and webpack module paths, in the shapes real
# bundlers emit. The versions here are the old ones on purpose.
BUNDLE = """/*! jQuery v1.12.4 | (c) jQuery Foundation, Inc. | jquery.org/license */
/*! AngularJS v1.5.8 (c) 2010-2016 Google, Inc. http://angularjs.org License: MIT */
/**
 * @license
 * Lodash 3.10.1 <https://lodash.com/>
 * Copyright 2012-2015 The Dojo Foundation <http://dojofoundation.org/>
 */
(function (global) {
  var jQuery = function () {};
  jQuery.fn = jQuery.prototype = { jquery: "1.12.4" };
  var angular = { version: { full: "1.5.8", major: 1, minor: 5, dot: 8 } };
  var lodash = { VERSION: '3.10.1' };
  global.jQuery = global.$ = jQuery;
  global.angular = angular;
  global._ = lodash;
  // Build-time config. Fake credentials: the single lab canary.
  global.__APP_CONFIG__ = {
    analyticsKey: "%(canary)s-analytics",
    uploadToken: "%(canary)s-upload",
    api: "/api/v1"
  };
})(window);

/***/ "./node_modules/moment/moment.js":
/*!*****************************************!*\\
  !*** ./node_modules/moment/moment.js ***!
  \\*****************************************/
/***/ (function (module, exports, __webpack_require__) {
  __webpack_require__("./node_modules/dompurify/dist/purify.js");
  __webpack_require__("./node_modules/moment/locale/de.js");
/***/ }),

//# sourceMappingURL=app.bundle.js.map
""" % {"canary": CANARY}

SOURCEMAP = {
    "version": 3,
    "file": "app.bundle.js",
    "sources": [
        "webpack:///./src/index.js",
        "webpack:///./node_modules/jquery/dist/jquery.js",
        "webpack:///./node_modules/moment/package.json",
        "webpack:///./node_modules/dompurify/package.json",
        "webpack:///./node_modules/lodash/lodash.js",
    ],
    "sourcesContent": [
        "import 'moment';\nimport DOMPurify from 'dompurify';\n",
        "/*! jQuery v1.12.4 */\n",
        '{\n  "name": "moment",\n  "version": "2.18.1",\n  "main": "./moment.js"\n}\n',
        '{\n  "name": "dompurify",\n  "version": "2.0.7",\n  "main": "dist/purify.js"\n}\n',
        "/* Lodash 3.10.1 */\n",
    ],
    "names": [],
    "mappings": "",
}

VENDOR_CSS = """/*!
 * Bootstrap v3.3.7 (http://getbootstrap.com)
 * Copyright 2011-2016 Twitter, Inc.
 * Licensed under MIT
 */
.container{margin:0 auto}
"""

# wasm magic + version, then a `producers` custom section naming the toolchain.
WASM = (b"\x00asm\x01\x00\x00\x00"
        b"\x00\x2a\x09producers\x02\x08language\x01\x03C++\x00"
        b"\x10processed-by\x01\x0bemscripten\x063.1.45")

CONFIG = {"api": "/api/v1", "analyticsKey": f"{CANARY}-analytics",
          "flags": {"newCheckout": True}}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "nginx/1.18.0"
    sys_version = ""

    def _send(self, body, ctype, status=200):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "Express/4.16.0")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?")[0]
        routes = {
            "/": (INDEX, "text/html; charset=utf-8"),
            "/index.html": (INDEX, "text/html; charset=utf-8"),
            "/static/app.bundle.js": (BUNDLE, "application/javascript"),
            "/static/app.bundle.js.map": (json.dumps(SOURCEMAP), "application/json"),
            "/static/vendor.css": (VENDOR_CSS, "text/css"),
            "/static/img-decode.wasm": (WASM, "application/wasm"),
            "/config.json": (json.dumps(CONFIG, indent=1), "application/json"),
            "/__inventory": (json.dumps(GROUND_TRUTH, indent=1), "application/json"),
        }
        if path in routes:
            body, ctype = routes[path]
            return self._send(body, ctype)
        self._send(json.dumps({"error": "not found", "path": path}),
                   "application/json", 404)

    def log_message(self, fmt, *args):   # one line per request, like the others
        print(f"sbomlab {self.address_string()} {fmt % args}", flush=True)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    host = os.environ.get("SBOMLAB_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    with Server((host, port), Handler) as srv:
        print(f"sbomlab on http://{host}:{port}", flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
