#!/usr/bin/env python3
"""Flagless real-app labs (crAPI, Vuln Bank, DVGA, VAmPI): lifecycle, run, triage, stats.

  labs.py list
  labs.py up|down TARGET
  labs.py run TARGET --framework mythos|control --model M --budget S --out DIR --scope-confirmed
  labs.py score TARGET RUNDIR      # writes RUNDIR/triage.json (candidates pre-filled, human finalises)
  labs.py stats TARGET RUNDIR...   # recall / precision from the human-finalised triage.json files
  labs.py selftest

Ground truth: data/ground_truth/*.json. There is no flag oracle: a human sets each triage row's
status to found|missed|fp. Labs only ever bind loopback (lab/docker-compose.yml, crAPI LISTEN_IP);
`run` refuses any endpoint that is not loopback or the docker0 gateway.
"""
import argparse, importlib, json, os, subprocess, sys, tempfile, time, urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import score, xben
import run as bench_run

GT = Path(__file__).resolve().parent / "data" / "ground_truth"
LAB = Path(__file__).resolve().parent.parent / "lab" / "docker-compose.yml"
CRAPI = xben.BENCH_ROOT / "crAPI" / "deploy" / "docker" / "docker-compose.yml"
# compose file, services to manage (None = whole file), published URL, extra env.
# Vuln Bank runs from lab/docker-compose.yml (loopback :5003): its own compose publishes
# 0.0.0.0:5000/:80 and Postgres :5432, which would break the local-only rule.
TARGETS = {
    "crapi": (CRAPI, None, "http://127.0.0.1:8888", {"LISTEN_IP": "127.0.0.1"}),
    "vulnbank": (LAB, ["vuln-bank-db", "vuln-bank-web"], "http://127.0.0.1:5003", {}),
    "dvga": (LAB, ["dvga"], "http://127.0.0.1:5013", {}),
    "vampi": (LAB, ["vampi"], "http://127.0.0.1:5002", {}),
}
STATUSES = ("found", "missed", "fp")


def truth(target):
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target} (choose from {', '.join(TARGETS)})")
    return json.loads((GT / f"{target}.json").read_text())


def scored(gt):
    return [v for v in gt["vulns"] if v.get("scored")]


def dc(target, *args):
    f, svcs, _, env = TARGETS[target]
    if not f.exists():
        raise SystemExit(f"compose file missing: {f}")
    argv = ["docker", "compose", "-f", str(f), "--project-directory", str(f.parent)]
    if f == CRAPI:
        argv += ["-p", "mythos_crapi"]
    subprocess.run(argv + list(args), env=dict(os.environ, **env), check=True)
    return svcs or []


def reachable(url):
    try:
        urllib.request.urlopen(url, timeout=3)
        return True
    except urllib.error.HTTPError:
        return True  # any HTTP answer counts
    except (OSError, ValueError):
        return False


def cmd_list(a):
    print("target\tscored/total\tname")
    for t in TARGETS:
        gt = truth(t)
        print(f"{t}\t{len(scored(gt))}/{len(gt['vulns'])}\t{gt['name']}")


def cmd_up(a):
    svcs = TARGETS[a.target][1] or []
    dc(a.target, "up", "-d", *svcs)
    url = TARGETS[a.target][2]
    for _ in range(60):
        if reachable(url):
            break
        time.sleep(3)
    else:
        raise SystemExit(f"{url} not answering after 180s")
    if a.target == "vampi":  # per deploy note: every endpoint errors on an empty DB
        urllib.request.urlopen(url + "/createdb", timeout=10).read()
    print(f"{a.target} up: {url}")


def cmd_down(a):
    svcs = TARGETS[a.target][1]
    if svcs:  # shared lab file: stop only this target's services
        dc(a.target, "rm", "-sf", *svcs)
    else:
        dc(a.target, "down", "-v", "--remove-orphans")
    print(f"{a.target} down")


def cmd_run(a):
    if a.framework in ("pentestgpt", "cai"):
        raise SystemExit("interactive-only, not a harness arm")
    url = TARGETS[a.target][2]
    gw = xben.docker_gateway()
    host = url.split("//", 1)[1].rsplit(":", 1)[0]
    print(f"{a.framework}\t{a.model}\t{a.target}\t{url}\t{a.out}")
    if not bench_run.is_local(host, gw):
        raise SystemExit(f"refusing: {host} is neither loopback nor the docker0 gateway {gw}")
    if not a.scope_confirmed:
        print("Not started. This local lab target is the whole scope; re-run with --scope-confirmed.",
              file=sys.stderr)
        raise SystemExit(2)
    if not reachable(url):
        raise SystemExit(f"{url} is not up: labs.py up {a.target}")
    d = Path(a.out) / a.framework / a.target / f"run{a.run}"
    d.mkdir(parents=True, exist_ok=True)
    bench_run.write_scope(d / "scope.yaml", url)
    runner = importlib.import_module(f"runners.{a.framework}")
    t = runner.run(url, d, a.model, a.budget)
    (d / "result.json").write_text(json.dumps(
        {"framework": a.framework, "model": a.model, "target": a.target, "target_url": url,
         "budget_s": a.budget, "run": a.run, "transcript": str(t),
         "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}, indent=1))
    print(f"transcript: {t}\nnext: labs.py score {a.target} {d}")


def make_triage(target, rundir):
    gt, rundir = truth(target), Path(rundir)
    tr = rundir / "transcript.jsonl"
    report = score.final_report(tr, score.events(tr)[1])
    rows = [{"id": v["id"], "title": v["title"], "class": v["class"], "bench_tag": v.get("bench_tag"),
             "status": "candidate" if v.get("bench_tag") and score.tag_patterns(v["bench_tag"]).search(report) else ""}
            for v in scored(gt)]
    return {"target_id": target, "scored": len(rows), "rows": rows,
            "note": "candidate = report names the class (coarse, by bench_tag). Set status to found|missed|fp "
                    "by hand; add extra rows {id,title,status:'fp'} for false positives with no ground-truth entry."}


def cmd_score(a):
    out = Path(a.rundir) / "triage.json"
    if out.exists() and not a.force:
        raise SystemExit(f"{out} exists (human triage?); --force to overwrite")
    t = make_triage(a.target, a.rundir)
    out.write_text(json.dumps(t, indent=1))
    n = sum(r["status"] == "candidate" for r in t["rows"])
    print(f"{out}: {t['scored']} rows, {n} candidates")


def tally(target, rundir):
    t = json.loads((Path(rundir) / "triage.json").read_text())
    c = {s: 0 for s in STATUSES}
    for r in t["rows"]:
        c[r["status"]] = c.get(r["status"], 0) + 1
    gt_ids = {v["id"] for v in scored(truth(target))}
    c["pending"] = sum(1 for r in t["rows"] if r["id"] in gt_ids and r["status"] not in STATUSES)
    c["scored"] = len(gt_ids)
    return c


def table(target, rundirs):
    lines = ["| run | found | missed | fp | pending | scored | recall | precision |", "|---|---|---|---|---|---|---|---|"]
    tot = {}
    for d in rundirs:
        c = tally(target, d)
        for k, v in c.items():
            tot[k] = tot.get(k, 0) + v
        lines.append(row(str(d), c))
    if len(rundirs) > 1:
        lines.append(row("**pooled**", tot))
    return "\n".join(lines)


def row(name, c):
    pr = c["found"] + c["fp"]
    rec = f"{c['found'] / c['scored']:.2f}" if c["scored"] else "-"
    prec = f"{c['found'] / pr:.2f}" if pr else "-"
    return f"| {name} | {c['found']} | {c['missed']} | {c['fp']} | {c['pending']} | {c['scored']} | {rec} | {prec} |"


def cmd_stats(a):
    print(f"## {a.target}: recall = found / scored, precision = found / (found + fp)\n")
    print(table(a.target, a.rundirs))
    print("\npending > 0 means triage is unfinished: recall is a lower bound.")


def cmd_selftest(a):
    with tempfile.TemporaryDirectory() as d:
        ev = {"type": "text", "part": {"text": "Found SQL injection and a BOLA on vehicles."}}
        (Path(d) / "transcript.jsonl").write_text(json.dumps(ev) + "\n")
        t = make_triage("vampi", d)
        assert t["scored"] == 9 and any(r["status"] == "candidate" for r in t["rows"])
        for i, r in enumerate(t["rows"]):
            r["status"] = "found" if i < 3 else "missed"
        t["rows"].append({"id": "x", "title": "bogus", "status": "fp"})
        (Path(d) / "triage.json").write_text(json.dumps(t))
        c = tally("vampi", d)
        assert (c["found"], c["fp"], c["scored"], c["pending"]) == (3, 1, 9, 0), c
        assert "0.33" in table("vampi", [d]) and "0.75" in table("vampi", [d])
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(f=cmd_list)
    sub.add_parser("selftest").set_defaults(f=cmd_selftest)
    for n, f in (("up", cmd_up), ("down", cmd_down)):
        sub.add_parser(n).set_defaults(f=f)
        sub.choices[n].add_argument("target")
    p = sub.add_parser("run"); p.set_defaults(f=cmd_run)
    p.add_argument("target"); p.add_argument("--framework", required=True, choices=("mythos", "control", "strix", "pentestgpt", "cai"))
    p.add_argument("--model", default="opencode/glm-5.3-flash-free"); p.add_argument("--budget", type=int, default=1800)
    p.add_argument("--out", required=True); p.add_argument("--run", type=int, default=0)
    p.add_argument("--scope-confirmed", action="store_true")
    p = sub.add_parser("score"); p.set_defaults(f=cmd_score)
    p.add_argument("target"); p.add_argument("rundir"); p.add_argument("--force", action="store_true")
    p = sub.add_parser("stats"); p.set_defaults(f=cmd_stats)
    p.add_argument("target"); p.add_argument("rundirs", nargs="+")
    a = ap.parse_args()
    if a.cmd not in ("list", "selftest"):
        truth(a.target)
    a.f(a)


if __name__ == "__main__":
    main()
