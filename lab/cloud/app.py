"""SSRF sinks in front of the metadata emulator — cloud-metadata fixture.

  GET /fetch?url=           visible SSRF: the response body comes back
  GET /avatar?url=          blind SSRF: 202 and nothing else, fetched async
  GET /proxy?url=&method=&header=  SSRF that controls method and headers,
                            which is the only shape IMDSv2 falls to
  GET /__fetchlog           JSONL of every fetch this app made (lab oracle
                            for the blind variant, like the oast catcher)

No allow-list, no scheme check, no redirect limit: that is the point. The
metadata emulators are reachable from here by name and from nowhere else.
Local lab only. Do not deploy it.
"""

from __future__ import annotations

import json
import os
import threading
import time

import requests
from flask import Flask, Response, request

app = Flask(__name__)
LOG = "/tmp/fetchlog.jsonl"
_lock = threading.Lock()


def _record(entry: dict) -> None:
    entry["ts"] = time.time()
    with _lock, open(LOG, "a") as fh:
        fh.write(json.dumps(entry) + "\n")


def _fetch(url: str, method: str = "GET", headers: dict | None = None) -> dict:
    out = {"url": url, "method": method, "headers": headers or {}}
    try:
        r = requests.request(method, url, headers=headers, timeout=3,
                             allow_redirects=True)
        out["status"] = r.status_code
        out["body"] = r.text[:4096]
    except Exception as e:  # noqa: BLE001 - the error is the signal here
        out["error"] = str(e)
    _record(out)
    return out


@app.route("/")
def index():
    return """<html><head><title>Mythos CloudApp</title></head><body>
    <h1>CloudApp</h1>
    <a href="/fetch?url=http://cloud-metadata/">fetch</a>
    <a href="/avatar?url=http://cloud-metadata/">avatar (blind)</a>
    <a href="/proxy?url=http://cloud-metadata/&amp;method=GET">proxy</a>
    <a href="/__fetchlog">fetch log</a>
    </body></html>"""


@app.route("/fetch")
def fetch():
    # VULN: visible SSRF — the fetched body is returned to the caller.
    url = request.args.get("url", "")
    if not url:
        return Response("no url", status=400)
    out = _fetch(url)
    if "error" in out:
        return Response(f"fetch error: {out['error']}", status=502)
    return Response(out["body"], status=out["status"], mimetype="text/plain")


@app.route("/avatar")
def avatar():
    # VULN: blind SSRF — the fetch happens off-request; the caller learns
    # nothing from the response. Confirm it out of band (/__fetchlog, or an
    # in-lab catcher).
    url = request.args.get("url", "")
    if not url:
        return Response("no url", status=400)
    threading.Thread(target=_fetch, args=(url,), daemon=True).start()
    return Response("accepted", status=202)


@app.route("/proxy")
def proxy():
    # VULN: SSRF with attacker-controlled method and headers — a "webhook
    # tester" shape. This is the only sink that reaches an IMDSv2-only
    # instance, because it can PUT for a token and send it back.
    url = request.args.get("url", "")
    if not url:
        return Response("no url", status=400)
    headers = {}
    for h in request.args.getlist("header"):
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    out = _fetch(url, request.args.get("method", "GET").upper(), headers)
    if "error" in out:
        return Response(f"fetch error: {out['error']}", status=502)
    return Response(out["body"], status=out["status"], mimetype="text/plain")


@app.route("/__beacon")
def beacon():
    # An in-lab sink for the ai target's exfiltration leg: whatever reaches
    # here lands in the same log, so the proof is out of band rather than a
    # reflection in the app's own answer.
    _record({"kind": "beacon", "url": request.url,
             "args": request.args.to_dict(flat=False)})
    return Response("", status=204)


@app.route("/__fetchlog")
def fetchlog():
    try:
        with open(LOG) as fh:
            return Response(fh.read(), mimetype="application/x-ndjson")
    except OSError:
        return Response("", mimetype="application/x-ndjson")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")),
            threaded=True, use_reloader=False)
