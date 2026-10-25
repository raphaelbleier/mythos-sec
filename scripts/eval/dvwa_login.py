#!/usr/bin/env python3
"""Lab helper: authenticate to DVWA, initialise its database, set security low,
and print the resulting cookies for authenticated scanning.

    python scripts/eval/dvwa_login.py http://mythos-dvwa

Prints two lines usable as mythos --cookie args:
    PHPSESSID=<...>
    security=low

For the local DVWA lab target only.
"""

from __future__ import annotations

import re
import sys

import requests

TOKEN = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-f]+)['\"]", re.I)


def token(html: str) -> str:
    m = TOKEN.search(html)
    return m.group(1) if m else ""


def main(base: str) -> int:
    base = base.rstrip("/")
    s = requests.Session()
    # 1) login
    r = s.get(f"{base}/login.php", timeout=15)
    s.post(f"{base}/login.php", timeout=15, data={
        "username": "admin", "password": "password",
        "Login": "Login", "user_token": token(r.text)})
    # 2) initialise the database
    r = s.get(f"{base}/setup.php", timeout=15)
    s.post(f"{base}/setup.php", timeout=15, data={
        "create_db": "Create / Reset Database", "user_token": token(r.text)})
    # 3) re-login (DB reset invalidates the session) and set security low
    r = s.get(f"{base}/login.php", timeout=15)
    s.post(f"{base}/login.php", timeout=15, data={
        "username": "admin", "password": "password",
        "Login": "Login", "user_token": token(r.text)})
    r = s.get(f"{base}/security.php", timeout=15)
    s.post(f"{base}/security.php", timeout=15, data={
        "security": "low", "seclev_submit": "Submit", "user_token": token(r.text)})
    phpsessid = s.cookies.get("PHPSESSID", "")
    if not phpsessid:
        print("ERROR: no PHPSESSID (DVWA not reachable / not set up)", file=sys.stderr)
        return 1
    # verify we can reach an authed page
    chk = s.get(f"{base}/vulnerabilities/sqli/?id=1&Submit=Submit", timeout=15)
    ok = "login.php" not in chk.url
    print(f"PHPSESSID={phpsessid}")
    print("security=low")
    print(f"# authenticated={ok}", file=sys.stderr)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "http://mythos-dvwa"))
