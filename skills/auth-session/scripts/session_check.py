#!/usr/bin/env python3
"""Check that saved role sessions are still valid; re-log-in (replaying auth_login.py) if not.

A session is dead when the baseline GET (--check-url, e.g. /api/me) returns 401/403, a redirect
to a login page, or a body matching --dead-regex. Run before every tool batch:

  scripts/mythos python3 skills/auth-session/scripts/session_check.py \
      --sessions engagements/<dir>/sessions --check-url http://vampi:5000/me userA userB

Exit 0 = every role valid (possibly after re-login), 1 = at least one role still dead.
"""
import argparse, json, re, sys, urllib.error, urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import auth_login  # noqa: E402


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def load_headers(path):
    return dict(l.split(": ", 1) for l in Path(path).read_text().splitlines() if ": " in l)


def alive(url, headers, dead_re):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=15) as r:
            body = r.read(20000).decode(errors="replace")
            code = r.status
    except urllib.error.HTTPError as e:
        code, body = e.code, e.read(20000).decode(errors="replace")
        if 300 <= code < 400:
            loc = e.headers.get("Location", "")
            return not re.search(r"log-?in|sign-?in|auth", loc, re.I), f"{code} -> {loc}"
    if code in (401, 403) or (dead_re and re.search(dead_re, body, re.I)):
        return False, str(code)
    return 200 <= code < 300, str(code)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("roles", nargs="+")
    ap.add_argument("--sessions", required=True)
    ap.add_argument("--check-url", required=True, help="authenticated baseline GET")
    ap.add_argument("--dead-regex", help='body pattern meaning "logged out", e.g. "please log in"')
    a = ap.parse_args()
    d, bad = Path(a.sessions), 0
    for role in a.roles:
        ok, why = alive(a.check_url, load_headers(d / f"{role}.headers"), a.dead_regex)
        if not ok:
            recipe = d / f"{role}.login.json"
            if recipe.exists():
                auth_login.main(json.loads(recipe.read_text()))
                ok, why = alive(a.check_url, load_headers(d / f"{role}.headers"), a.dead_regex)
            print(json.dumps({"role": role, "relogin": True, "valid": ok, "status": why}))
        else:
            print(json.dumps({"role": role, "relogin": False, "valid": True, "status": why}))
        bad += not ok
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
