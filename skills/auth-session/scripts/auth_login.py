#!/usr/bin/env python3
"""Log in once as one role and persist the session for every toolbox tool.

Modes:
  json     POST a JSON body to a login API (token from the JSON response and/or Set-Cookie)
  form     GET the login page (keeps hidden CSRF inputs), POST the HTML form
  browser  Playwright: fill the first password form on the page (SPA / JS logins)
  token    no login; store a token/cookie obtained elsewhere (OAuth PKCE, SSO, TOTP by hand)

Writes into --out (e.g. engagements/<dir>/sessions/):
  <role>.state.json            Playwright storage_state (cookies + localStorage)
  <role>.headers               one "Name: value" per line (Cookie, Authorization)
  <role>.nuclei-secrets.yaml   nuclei -sf file (static header secret scoped to the host)
  <role>.login.json            the argv of this login with credential values redacted, replayed by
                               session_check.py (supply the secrets again when replaying)
  <role>.session_storage.json  browser mode only: sessionStorage dump (Playwright cannot persist it)

Stdlib only, except --mode browser (playwright). Run inside the toolbox:
  scripts/mythos python3 skills/auth-session/scripts/auth_login.py --role userA ...
"""
import argparse, http.cookiejar, json, re, sys, urllib.error, urllib.parse, urllib.request
from html.parser import HTMLParser
from pathlib import Path

TOKEN_KEYS = ("access_token", "accessToken", "token", "jwt", "id_token", "auth_token", "authToken")
JWT_RE = re.compile(r"^eyJ[\w-]+\.[\w-]+\.[\w-]*$")


def find_token(obj, path=None):
    """Token from a JSON response: explicit dotted path, else the first well-known key, else any JWT."""
    if path:
        for part in path.split("."):
            obj = obj[int(part)] if isinstance(obj, list) else obj[part]
        return str(obj)
    stack = [obj]
    while stack:
        o = stack.pop()
        if isinstance(o, dict):
            for k in TOKEN_KEYS:
                if isinstance(o.get(k), str) and o[k]:
                    return o[k]
            stack.extend(o.values())
        elif isinstance(o, list):
            stack.extend(o)
        elif isinstance(o, str) and JWT_RE.match(o):
            return o
    return None


class FormParser(HTMLParser):
    """Collects the first <form> containing a password input: action, method, all named inputs."""
    def __init__(self):
        super().__init__()
        self.forms, self.cur = [], None

    def handle_starttag(self, tag, a):
        a = dict(a)
        if tag == "form":
            self.cur = {"action": a.get("action", ""), "method": a.get("method", "post").lower(),
                        "inputs": {}, "password": None, "user": None}
        elif tag == "input" and self.cur is not None and a.get("name"):
            t = (a.get("type") or "text").lower()
            if t == "password" and not self.cur["password"]:
                self.cur["password"] = a["name"]
            elif t in ("text", "email") and not self.cur["user"]:
                self.cur["user"] = a["name"]
            self.cur["inputs"][a["name"]] = a.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form" and self.cur is not None:
            self.forms.append(self.cur); self.cur = None


SECRET_FLAGS = ("--password", "--pass", "--token", "--secret", "--api-key", "--cookie")


def redact(argv):
    """argv with the value of every credential-style flag replaced, so no secret reaches disk."""
    out, hide = [], False
    for x in argv:
        if hide:
            out.append("REDACTED"); hide = False
        elif x in SECRET_FLAGS:
            out.append(x); hide = True
        elif x.split("=", 1)[0] in SECRET_FLAGS and "=" in x:
            out.append(x.split("=", 1)[0] + "=REDACTED")
        else:
            out.append(x)
    return out


def check_login_status(status, a):
    """A failed login still answers with a pre-login session cookie, which would be saved as valid."""
    if not 200 <= status < 300 and status not in a.allow_login_status:
        sys.exit(f"auth_login: login answered HTTP {status}, treating it as failed (wrong creds?). "
                 "If this target legitimately returns that status on success (e.g. a 302 redirect), "
                 f"re-run with --allow-login-status {status}")


def opener(jar):
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def login_json(a, jar):
    body = {a.user_field: a.user, a.pass_field: a.password, **json.loads(a.extra or "{}")}
    req = urllib.request.Request(urllib.parse.urljoin(a.base, a.login_url), json.dumps(body).encode(),
                                 {"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with opener(jar).open(req, timeout=20) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    check_login_status(status, a)
    try:
        return find_token(json.loads(raw), a.token_path)
    except ValueError:
        return None


def login_form(a, jar):
    page = urllib.parse.urljoin(a.base, a.login_url)
    op = opener(jar)
    with op.open(page, timeout=20) as r:
        p = FormParser(); p.feed(r.read().decode(errors="replace"))
    form = next((f for f in p.forms if f["password"]), None)
    if not form:
        sys.exit("auth_login: no form with a password field at " + page)
    fields = dict(form["inputs"])  # keeps hidden CSRF tokens
    # default field names -> use the names the form actually has; explicit --user-field/--pass-field win
    fields[form["user"] if a.user_field == "username" and form["user"] else a.user_field] = a.user
    fields[form["password"] if a.pass_field == "password" else a.pass_field] = a.password
    fields.update(json.loads(a.extra or "{}"))
    data = urllib.parse.urlencode(fields).encode()
    try:
        with op.open(urllib.request.Request(urllib.parse.urljoin(page, form["action"] or page), data),
                     timeout=20) as r:
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
    check_login_status(status, a)
    return None


def login_browser(a, out):
    from playwright.sync_api import sync_playwright
    import os
    with sync_playwright() as p:
        exe = os.environ.get("CHROME_BIN")
        b = p.chromium.launch(executable_path=exe, args=["--no-sandbox"]) if exe else p.chromium.launch()
        ctx = b.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        page.goto(urllib.parse.urljoin(a.base, a.login_url), wait_until="networkidle", timeout=30000)
        page.fill(a.user_selector, a.user)
        page.fill(a.pass_selector, a.password)
        btn = page.locator(a.submit_selector)
        if btn.count():
            btn.first.click()
        else:
            page.press(a.pass_selector, "Enter")
        page.wait_for_load_state("networkidle", timeout=30000)
        page.wait_for_timeout(1500)
        state = ctx.storage_state()
        ss = page.evaluate("() => JSON.stringify(sessionStorage)")
        b.close()
    (out / f"{a.role}.session_storage.json").write_text(ss)
    token = None
    for origin in state.get("origins", []):
        for item in origin.get("localStorage", []):
            if item["name"] in TOKEN_KEYS or JWT_RE.match(item["value"] or ""):
                token = item["value"]; break
    for k, v in json.loads(ss or "{}").items():
        if not token and (k in TOKEN_KEYS or JWT_RE.match(v or "")):
            token = v
    return token, state


def jar_state(jar):
    """http.cookiejar -> Playwright storage_state, so the browser skills can reuse a non-browser login."""
    return {"cookies": [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path or "/",
                         "expires": c.expires or -1, "httpOnly": bool(c.has_nonstandard_attr("HttpOnly")),
                         "secure": bool(c.secure), "sameSite": "Lax"} for c in jar], "origins": []}


def write_outputs(a, out, token, state):
    host = urllib.parse.urlparse(a.base).hostname
    cookies = "; ".join(f"{c['name']}={c['value']}" for c in state["cookies"]
                        if host and (host == c["domain"].lstrip(".") or host.endswith(c["domain"]))) \
        or "; ".join(f"{c['name']}={c['value']}" for c in state["cookies"])
    headers = []
    if cookies:
        headers.append(("Cookie", cookies))
    if token:
        headers.append((a.token_header, a.token_prefix + token))
    if not headers:
        sys.exit("auth_login: login produced neither a cookie nor a token (wrong creds or wrong mode?)")
    (out / f"{a.role}.state.json").write_text(json.dumps(state, indent=1))
    (out / f"{a.role}.headers").write_text("".join(f"{k}: {v}\n" for k, v in headers))
    sec = ["static:", "  - type: header", "    domains:", f"      - {host}", "    headers:"]
    for k, v in headers:
        sec += [f"      - key: {json.dumps(k)}", f"        value: {json.dumps(v)}"]
    (out / f"{a.role}.nuclei-secrets.yaml").write_text("\n".join(sec) + "\n")
    print(json.dumps({"role": a.role, "cookie": bool(cookies), "token": bool(token),
                      "headers": str(out / f"{a.role}.headers")}))


def parse(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--role", required=True, help="userA, userB, admin, ...")
    ap.add_argument("--base", required=True, help="target origin, e.g. http://vampi:5000")
    ap.add_argument("--mode", choices=("json", "form", "browser", "token"), default="json")
    ap.add_argument("--login-url", default="/login", help="path of the login API / page")
    ap.add_argument("--user", default="")
    ap.add_argument("--password", default="")
    ap.add_argument("--user-field", default="username")
    ap.add_argument("--pass-field", default="password")
    ap.add_argument("--extra", help='extra login fields as JSON, e.g. \'{"otp":"123456"}\'')
    ap.add_argument("--token-path", help="dotted path to the token in the JSON response, e.g. data.auth_token")
    ap.add_argument("--token", help="--mode token: the bearer token")
    ap.add_argument("--cookie", help='--mode token: raw cookie string "a=1; b=2"')
    ap.add_argument("--token-header", default="Authorization")
    ap.add_argument("--token-prefix", default="Bearer ")
    ap.add_argument("--user-selector", default="input[type=email], input[name*=user i], input[type=text]")
    ap.add_argument("--pass-selector", default="input[type=password]")
    ap.add_argument("--submit-selector", default="button[type=submit], input[type=submit], form button")
    ap.add_argument("--allow-login-status", type=int, action="append", default=[],
                    help="HTTP status of the login response to accept as success besides 2xx, repeatable")
    ap.add_argument("--out", required=True, help="sessions dir, e.g. engagements/<dir>/sessions")
    return ap.parse_args(argv)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    a = parse(argv)
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    jar, token, state = http.cookiejar.CookieJar(), None, None
    if a.mode == "json":
        token = login_json(a, jar)
    elif a.mode == "form":
        token = login_form(a, jar)
    elif a.mode == "browser":
        token, state = login_browser(a, out)
    else:
        token = a.token
        host = urllib.parse.urlparse(a.base).hostname
        state = {"cookies": [{"name": k.strip(), "value": v.strip(), "domain": host, "path": "/", "expires": -1,
                              "httpOnly": False, "secure": a.base.startswith("https"), "sameSite": "Lax"}
                             for k, _, v in (p.partition("=") for p in (a.cookie or "").split(";") if "=" in p)],
                 "origins": []}
    write_outputs(a, out, token, state or jar_state(jar))
    (out / f"{a.role}.login.json").write_text(json.dumps(redact(argv)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
