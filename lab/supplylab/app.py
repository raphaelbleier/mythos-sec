#!/usr/bin/env python3
"""supplylab — a target that leaks its own dependency names.

Deliberately vulnerable to dependency confusion, for the supply-chain package.
Local lab only. Every fake credential in here is the single canary string
MYTHOS_LAB_CANARY, so a run greps for exactly one token and nothing in this
file resembles a real key.

What it gets wrong, on purpose:

* `/static/app.bundle.js` keeps `node_modules/@acme-internal/...` module ids and
  a `//# sourceMappingURL`, and the map it points at keeps the whole tree.
* `/.npmrc` is served to the world, with the internal registry URL, the scope
  it serves, and a token on the line below it.
* `/package.json` declares the internal packages as ranges, not pins.
* `/package-lock.json` resolved one internal scope from registry.npmjs.org and
  the other from the internal nexus — the mixed lockfile that makes the
  confusion real rather than theoretical.
* `/requirements.txt` and `/pip.conf` do the same on the Python side, with
  `--extra-index-url https://pypi.org/simple` next to an internal index.
* `/composer.json` and `/pom.xml` carry the PHP and Maven equivalents.

It also serves `/__registry/<eco>/...`, a stand-in public registry, so the
claimability path can be exercised without sending a byte to npmjs.com:

    scripts/supplychain claimable --from extract.json --contact-registries \
      --registry-base npm=http://127.0.0.1:5025/__registry/npm

The fake registry answers 404 for every `@acme-internal/*` and every name
starting with `acme-internal` or `com.acme.internal`, and 200 with a
`squatter-lab` owner for everything else — including the typosquat neighbours of
the public packages, so `typosquat --check` has something to find.
"""
import http.server
import json
import os
import socketserver
import urllib.parse

CANARY = "MYTHOS_LAB_CANARY"
NEXUS = "https://nexus.corp.acme-internal.lab/repository/npm-private/"
PYPI_INTERNAL = "https://pypi.corp.acme-internal.lab/simple"

INDEX = """<!doctype html>
<html><head><title>Acme Internal Portal</title></head>
<body>
<h1>Acme portal</h1>
<script src="/static/app.bundle.js"></script>
<script src="/static/vendor.chunk.js"></script>
<script src="https://cdn.jsdelivr.net/npm/acme-ui-kit@2.1.0/dist/ui.min.js"></script>
</body></html>
"""

BUNDLE = """/*! acme portal bundle */
(self.webpackChunk_acme_portal=self.webpackChunk_acme_portal||[]).push([[179],{
 "./node_modules/@acme-internal/telemetry/dist/index.js":
   function(e,t,n){"use strict";t.track=function(){}},
 "./node_modules/@acme-internal/auth-sdk/dist/index.js":
   function(e,t,n){"use strict";t.login=function(){}},
 "./node_modules/react/index.js": function(e,t,n){},
 "./src/app.js": function(e,t,n){
    var flags=require("@acme-internal/feature-flags");
    var ui=require("acme-ui-kit");
    var _=require("lodash");
 }
}]);
//# sourceMappingURL=/static/app.bundle.js.map
"""

VENDOR = """/*! vendor chunk */
import u from "@acme-internal/ui-tokens";
import l from "lodash";
export default {u:u,l:l};
"""

SOURCEMAP = json.dumps({
    "version": 3,
    "file": "app.bundle.js",
    "sources": [
        "webpack:///./node_modules/@acme-internal/telemetry/src/index.ts",
        "webpack:///./node_modules/@acme-internal/billing-client/src/index.ts",
        "webpack:///./node_modules/react/index.js",
        "webpack:///./src/app.js",
    ],
    "sourcesContent": ["// internal telemetry", "// internal billing", "", ""],
    "names": [], "mappings": "",
})

NPMRC = f"""registry=https://registry.npmjs.org/
@acme-internal:registry={NEXUS}
//nexus.corp.acme-internal.lab/repository/npm-private/:_authToken={CANARY}
always-auth=false
"""

YARNRC = f"""npmRegistryServer: "https://registry.npmjs.org"
npmScopes:
  acme-internal:
    npmRegistryServer: "{NEXUS}"
    npmAuthToken: "{CANARY}"
"""

PACKAGE_JSON = json.dumps({
    "name": "acme-portal",
    "version": "3.4.1",
    "dependencies": {
        "@acme-internal/telemetry": "^1.2.0",
        "@acme-internal/auth-sdk": "~0.4.1",
        "@acme-internal/feature-flags": ">=2.0.0",
        "@acme-internal/ui-tokens": "*",
        "acme-ui-kit": "2.1.0",
        "react": "18.2.0",
        "lodash": "^4.17.21",
    },
    "devDependencies": {"@acme-internal/build-tools": "^5.0.0", "jest": "^29.7.0"},
}, indent=2)

PACKAGE_LOCK = json.dumps({
    "name": "acme-portal",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "acme-portal", "version": "3.4.1"},
        # The mixed lockfile: a private scope resolved from the public registry.
        "node_modules/@acme-internal/telemetry": {
            "version": "1.2.0",
            "resolved": "https://registry.npmjs.org/@acme-internal/telemetry/-/telemetry-1.2.0.tgz",
            "integrity": "sha512-" + CANARY,
        },
        "node_modules/@acme-internal/auth-sdk": {
            "version": "0.4.1",
            "resolved": NEXUS + "@acme-internal/auth-sdk/-/auth-sdk-0.4.1.tgz",
        },
        "node_modules/@acme-internal/feature-flags": {
            "version": "2.0.3",
            "resolved": NEXUS + "@acme-internal/feature-flags/-/feature-flags-2.0.3.tgz",
        },
        "node_modules/react": {
            "version": "18.2.0",
            "resolved": "https://registry.npmjs.org/react/-/react-18.2.0.tgz",
        },
        "node_modules/lodash": {
            "version": "4.17.21",
            "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        },
    },
}, indent=2)

REQUIREMENTS = f"""--index-url {PYPI_INTERNAL}
--extra-index-url https://pypi.org/simple
acme-internal-utils>=1.0
acme-internal-reporting==0.9.2
requests==2.31.0
flask>=2.0
"""

PIP_CONF = f"""[global]
index-url = {PYPI_INTERNAL}
extra-index-url = https://pypi.org/simple
trusted-host = pypi.corp.acme-internal.lab

[install]
password = {CANARY}
"""

COMPOSER_JSON = json.dumps({
    "name": "acme/portal",
    "require": {
        "php": ">=8.1",
        "acme-internal/logging": "^3.0",
        "monolog/monolog": "^3.5",
    },
    "repositories": [
        {"type": "composer", "url": "https://packagist.org"},
        {"type": "composer", "url": "https://composer.corp.acme-internal.lab"},
    ],
}, indent=2)

POM_XML = """<project>
  <groupId>com.acme.portal</groupId>
  <artifactId>portal</artifactId>
  <version>3.4.1</version>
  <repositories>
    <repository><id>central</id><url>https://repo1.maven.org/maven2</url></repository>
    <repository><id>corp</id>
      <url>https://nexus.corp.acme-internal.lab/repository/maven-private</url></repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.acme.internal</groupId>
      <artifactId>telemetry-java</artifactId>
      <version>1.2.0</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.17.0</version>
    </dependency>
  </dependencies>
</project>
"""

ROUTES = {
    "/": ("text/html", INDEX),
    "/static/app.bundle.js": ("application/javascript", BUNDLE),
    "/static/app.bundle.js.map": ("application/json", SOURCEMAP),
    "/static/vendor.chunk.js": ("application/javascript", VENDOR),
    "/.npmrc": ("text/plain", NPMRC),
    "/.yarnrc.yml": ("text/plain", YARNRC),
    "/package.json": ("application/json", PACKAGE_JSON),
    "/package-lock.json": ("application/json", PACKAGE_LOCK),
    "/requirements.txt": ("text/plain", REQUIREMENTS),
    "/pip.conf": ("text/plain", PIP_CONF),
    "/composer.json": ("application/json", COMPOSER_JSON),
    "/pom.xml": ("application/xml", POM_XML),
}

# The stand-in public registry. A name that looks like Acme's own is absent
# here, exactly as it would be absent from npmjs.com — that gap is the bug.
PRIVATE_PREFIXES = ("@acme-internal/", "acme-internal", "com.acme.internal")


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "supplylab/1.0"

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path.startswith("/__registry/"):
            return self.registry(path)
        ct, body = ROUTES.get(path, (None, None))
        if body is None:
            return self.send(404, "text/plain", "not found\n")
        self.send(200, ct, body)

    def registry(self, path):
        rest = path[len("/__registry/"):]
        eco, _, tail = rest.partition("/")
        name = urllib.parse.unquote(tail)
        if eco == "maven":
            # Maven Central is a solr query, not a path: the coordinates are in
            # ?q=g:"group" AND a:"artifact".
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("q", [""])[0]
            g = (q.split('g:"')[1].split('"')[0] if 'g:"' in q else "")
            art = (q.split('a:"')[1].split('"')[0] if 'a:"' in q else "")
            if any(g.startswith(pre) for pre in PRIVATE_PREFIXES):
                return self.send(200, "application/json",
                                 json.dumps({"response": {"numFound": 0, "docs": []}}))
            return self.send(200, "application/json", json.dumps({"response": {
                "numFound": 1, "docs": [{"g": g, "a": art, "latestVersion": "9.9.9"}]}}))
        for strip in ("pypi/", "api/v1/gems/", "api/v1/crates/",
                      "v3/registration5-semver1/"):
            if name.startswith(strip):
                name = name[len(strip):]
        name = name.split("/json")[0].split("/index.json")[0]
        name = name[:-5] if name.endswith(".json") else name
        if any(name.startswith(p) for p in PRIVATE_PREFIXES):
            return self.send(404, "application/json",
                             json.dumps({"error": "Not found"}))
        if eco == "pypi":
            return self.send(200, "application/json", json.dumps(
                {"info": {"name": name, "version": "9.9.9", "author": "squatter-lab"}}))
        return self.send(200, "application/json", json.dumps(
            {"name": name, "dist-tags": {"latest": "9.9.9"},
             "maintainers": [{"name": "squatter-lab"}],
             "versions": {"9.9.9": {"name": name, "version": "9.9.9"}}}))

    def send(self, status, ct, body):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} {fmt % args}", flush=True)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    # Loopback by default, so running this file by hand cannot expose it. The
    # image sets BIND=0.0.0.0 because compose publishes it on 127.0.0.1 itself,
    # and a container listening on its own loopback answers nobody.
    port = int(os.environ.get("PORT", "5000"))
    bind = os.environ.get("BIND", "127.0.0.1")
    with Server((bind, port), Handler) as srv:
        print(f"supplylab on {bind}:{port}", flush=True)
        srv.serve_forever()
