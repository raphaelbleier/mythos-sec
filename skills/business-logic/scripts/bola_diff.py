#!/usr/bin/env python3
"""BOLA/IDOR triage: replay each id-bearing endpoint as owner A, as other user B and anonymously.

--endpoints file: one per line, "URL" or "METHOD URL" or "METHOD URL BODY" (BODY = JSON, sent as-is).
URLs must carry ids of objects that belong to A (harvested as A from list endpoints).

Classification of B (and anon) against A's baseline, Auth Analyzer style:
  SAME      same status, same body hash
  SIMILAR   same status, body length within +-5 %
  DIFFERENT anything else
Verdict:
  candidate  B/anon got 2xx SAME/SIMILAR and (an A-only --marker is in the body, or no markers given)
  enforced   B/anon got 401/403/404 (or another non-2xx status with an empty body)
  review     everything else (e.g. 200 with B's own data = silent enforcement, or a 2xx with an
             empty body such as a 204 write = access granted, check the state by hand)
This is triage only (status + length, no semantics). A candidate becomes a finding only via the
exploit skill's proof pair. Read-only by default: non-GET/HEAD lines are skipped unless --allow-write,
which you may set only when every write line targets a resource the agent itself created.

  scripts/mythos python3 skills/business-logic/scripts/bola_diff.py --endpoints ids.txt \
    --a engagements/<dir>/sessions/userA.headers --b engagements/<dir>/sessions/userB.headers \
    --marker mythos-a@lab --rps 5 --out engagements/<dir>/scan/bola.jsonl
"""
import argparse, hashlib, json, sys, time, urllib.error, urllib.request
from pathlib import Path

SAFE = ("GET", "HEAD", "OPTIONS")


def load_headers(path):
    return dict(l.split(": ", 1) for l in Path(path).read_text().splitlines() if ": " in l) if path else {}


def send(method, url, headers, body):
    h = dict(headers)
    if body is not None:
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, body.encode() if body is not None else None, h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except OSError as e:
        return 0, str(e).encode()


def compare(base, other):
    (s1, b1), (s2, b2) = base, other
    if s1 != s2:
        return "DIFFERENT"
    if hashlib.sha256(b1).digest() == hashlib.sha256(b2).digest():
        return "SAME"
    return "SIMILAR" if abs(len(b1) - len(b2)) <= 0.05 * max(len(b1), 1) else "DIFFERENT"


def verdict(base, other, markers):
    s, b = other
    if s in (401, 403, 404):
        return "enforced"
    if 200 <= s < 300:
        # An empty body is no sign of enforcement: a 204 write by B means access was granted.
        if not b.strip():
            return "review"
        if compare(base, other) in ("SAME", "SIMILAR"):
            text = b.decode(errors="replace")
            if not markers or any(m in text for m in markers):
                return "candidate"
        return "review"
    return "enforced" if not b.strip() else "review"


def ev(resp):
    s, b = resp
    return {"status": s, "len": len(b), "sha256": hashlib.sha256(b).hexdigest()[:16],
            "excerpt": b[:300].decode(errors="replace")}


def parse_line(line):
    parts = line.split(None, 2)
    if len(parts) == 1:
        return "GET", parts[0], None
    return parts[0].upper(), parts[1], parts[2] if len(parts) == 3 else None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--endpoints", required=True)
    ap.add_argument("--a", required=True, help="owner's header file")
    ap.add_argument("--b", required=True, help="other user's header file")
    ap.add_argument("--marker", action="append", default=[], help="string only A's data contains (repeatable)")
    ap.add_argument("--no-anon", action="store_true")
    ap.add_argument("--allow-write", action="store_true", help="also replay non-GET lines (self-created resources only)")
    ap.add_argument("--rps", type=float, default=5)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    roles = {"A": load_headers(a.a), "B": load_headers(a.b)}
    if not a.no_anon:
        roles["anon"] = {}
    out, counts = open(a.out, "a"), {}
    for line in Path(a.endpoints).read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        method, url, body = parse_line(line.strip())
        if method not in SAFE and not a.allow_write:
            print(f"skip (write verb, no --allow-write): {method} {url}", file=sys.stderr)
            continue
        resp = {}
        for r, h in roles.items():
            resp[r] = send(method, url, h, body)
            if a.rps > 0:
                time.sleep(1 / a.rps)
        rec = {"method": method, "url": url, "A": ev(resp["A"])}
        if not 200 <= resp["A"][0] < 300:
            rec["note"] = "A baseline not 2xx; fix the session or the id before judging"
        for r in roles:
            if r != "A":
                rec[r] = {**ev(resp[r]), "class": compare(resp["A"], resp[r]),
                          "verdict": verdict(resp["A"], resp[r], a.marker)}
                counts[rec[r]["verdict"]] = counts.get(rec[r]["verdict"], 0) + 1
        out.write(json.dumps(rec) + "\n")
        flag = [r for r in roles if r != "A" and rec[r]["verdict"] == "candidate"]
        print(f"{method} {url}  A={resp['A'][0]}  " + "  ".join(
            f"{r}={rec[r]['status']}/{rec[r]['class']}/{rec[r]['verdict']}" for r in roles if r != "A")
            + ("  <-- CANDIDATE" if flag else ""))
    print(json.dumps({"summary": counts}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
