#!/usr/bin/env python3
"""Flagless real-app labs (crAPI, Vuln Bank, DVGA, VAmPI): lifecycle, run, triage, stats.

  labs.py list
  labs.py up|down TARGET
  labs.py run TARGET --framework claude_mythos|claude_control|mythos|control --model M \
                     --budget S --out DIR --scope-confirmed [--coverage-gate on|off|auto]
  labs.py seal OUT                             # blinded copies for the rater + sealed map
  labs.py score TARGET RUNDIR [--rater NAME]   # writes RUNDIR/triage-<rater>.json
  labs.py stats TARGET RUNDIR...               # recall / precision / inter-rater agreement
  labs.py rubric                               # print the rating rule
  labs.py selftest

Ground truth: data/ground_truth/*.json, the list each target is scored against. No arm is given
a root from which it is reachable (`labs.py run` refuses otherwise); the rule and its limits are
in METHODOLOGY.md. There is no flag oracle, so a human rates every run against
`data/triage-rubric.md`: each ground-truth entry found or missed, and each finding the arm
reported tp, fp or duplicate. Labs only ever bind loopback (lab/docker-compose.yml, crAPI
LISTEN_IP); `run` refuses any endpoint that is not loopback or the docker0 gateway.
"""
import argparse, fcntl, hashlib, importlib, json, os, re, subprocess, sys, tempfile, threading, time
import urllib.error, urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import score, xben
import run as bench_run
from runners import base as runners_base

GT = xben.GROUND_TRUTH
RUBRIC = Path(__file__).resolve().parent / "data" / "triage-rubric.md"
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
TRUTH_STATUSES = ("found", "missed")
REPORTED_STATUSES = ("tp", "fp", "duplicate")
# Report structure, not findings. Matched against the whole heading, so "Findings" is dropped
# while "Finding 3: SQLi in /login" is kept.
BOILERPLATE = re.compile(r"(executive summary|summary|scope|methodology|method|introduction|"
                         r"overview|findings|results?|conclusions?|recommendations?|"
                         r"remediation|appendix|references|table of contents|next steps|"
                         r"tested and not proven|classes tested|out of scope|disclaimer)"
                         r"\s*:?\s*", re.I)
# Tokens that name the arm. Removed from what a blinded rater reads. Partial by nature: the
# report's own wording can still reveal which arm wrote it.
ARM_TOKENS = re.compile(r"mythos[-_a-z]*|claude[ _-]?code|opencode|/cybersecurity|cybersecurity|"
                        r"sub-?agent|toolbox|scope guard|scope-guard|coverage gate|coverage-gate|"
                        r"engagements?/", re.I)


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


def cmd_rubric(a):
    print(RUBRIC.read_text())


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


def watchdog(target, url, log, stop):
    """Restart the target when it stops answering HTTP.

    These apps can be hung by ordinary testing: DVGA deadlocks when `importPaste` fetches the
    app's own address, and a hung process still accepts TCP, so a docker healthcheck on the port
    does not see it. Without this the cell measures a dead target instead of the agent.
    """
    down = 0
    while not stop.wait(30):
        if reachable(url):
            down = 0
            continue
        down += 1
        if down < 3:
            continue
        down = 0
        with log.open("a") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} down 90s, restarting\n")
        try:
            dc(target, "restart", *(TARGETS[target][1] or []))
        except SystemExit:
            pass


def cmd_run(a):
    if a.framework in ("pentestgpt", "cai"):
        raise SystemExit("interactive-only, not a harness arm")
    url = TARGETS[a.target][2]
    gw = xben.docker_gateway()
    host = url.split("//", 1)[1].rsplit(":", 1)[0]
    print(f"{a.framework}\t{a.model}\t{a.target}\t{url}\t{a.out}")
    if not bench_run.is_local(host, gw):
        raise SystemExit(f"refusing: {host} is neither loopback nor the docker0 gateway {gw}")
    # The flagless targets are scored against data/ground_truth/<target>.json. An arm that can
    # read it is scored against its own input, which is what made every recall number published
    # before 13 November 2026 indefensible.
    bench_run.check_grants([a.framework], a)
    grants = bench_run.arm_grants(a.framework, Path(a.out) / a.framework / a.target / f"run{a.run}",
                                  a.model)
    if not a.scope_confirmed:
        print("Not started. This local lab target is the whole scope; re-run with --scope-confirmed.",
              file=sys.stderr)
        raise SystemExit(2)
    if not reachable(url):
        raise SystemExit(f"{url} is not up: labs.py up {a.target}")
    lock = open(Path(tempfile.gettempdir()) / f"mythos-lab-{a.target}.lock", "w")
    try:  # one arm at a time: a lab target is a single shared instance, and two arms on it
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)  # see each other's writes and outages
    except OSError:
        raise SystemExit(f"another run holds {a.target}: labs targets are not parallel-safe")
    d = Path(a.out) / a.framework / a.target / f"run{a.run}"
    d.mkdir(parents=True, exist_ok=True)
    bench_run.write_scope(d / "scope.yaml", url)
    # flagless target: ask for coverage with evidence, not a flag
    os.environ["BENCH_OBJECTIVE"] = "survey"
    runner = importlib.import_module(f"runners.{a.framework}")
    stop = threading.Event()
    wd = threading.Thread(target=watchdog, args=(a.target, url, d / "target-restarts.log", stop),
                          daemon=True)
    wd.start()
    try:
        t = runner.run(url, d, a.model, a.budget)
    finally:
        stop.set()
    restarts = (d / "target-restarts.log")
    m, final = score.events(t)
    row = {"framework": a.framework, "model": a.model, "target": a.target, "target_url": url,
           "budget_s": a.budget, "run": a.run, "transcript": str(t), "objective": "survey",
           # the condition, recorded instead of implied by the output directory's name
           "treatment": grants["treatment"], "readable_roots": grants["roots"],
           "per_agent_models": grants.get("per_agent_models"),
           "per_agent_models_source": grants.get("per_agent_models_source"),
           "coverage_gate": bool(grants["treatment"].get("coverage_gate")),
           "repo_commit": runners_base.repo_commit(),
           "host_versions": {h: runners_base.host_version(h) for h in ("opencode", "claude", "docker")},
           "toolbox_image": bench_run.toolbox_image_id(),
           "scope_sha256": bench_run.sha256_file(d / "scope.yaml"),
           "ground_truth_sha256": bench_run.sha256_file(GT / f"{a.target}.json"),
           "resolved_models": m["resolved_models"], "tool_calls": m["tool_calls"],
           "steps": m["steps"], "usd": round(m["usd"], 4), "agent_s": m["agent_s"],
           "safety_stops": m["safety_stops"], "last_stop_after_tool": m["last_stop_after_tool"],
           "provider_http": m["provider_http"], "host_error": m["host_error"],
           "report_file": str(score.report_file(d) or ""),
           "target_restarts": len(restarts.read_text().splitlines()) if restarts.exists() else 0,
           "scope_warnings": score.scope_warnings(t, d / "scope.yaml"),
           "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    proc = d / "proc.json"
    row.update(json.loads(proc.read_text()) if proc.exists() else {})
    stderr = d / "stderr.log"
    err = stderr.read_text(errors="replace") if stderr.exists() else ""
    row["stderr_provider_down"] = bool(score.PROVIDER_DOWN.search(err))
    row["stderr_rate_limit"] = bool(score.RATE_LIMIT.search(err))
    if not reachable(url):
        row["status"] = "target_failed"
    row["status"], row["status_reason"] = score.classify(row)
    row["excluded"] = row["status"] in score.EXCLUDED
    (d / "result.json").write_text(json.dumps(row, indent=1))
    print(f"transcript: {t}")
    if row["excluded"]:
        raise SystemExit(f"{row['status']}: {row['status_reason']} -- unscored, not a failed run")
    print(f"next: labs.py score {a.target} {d}")


# --------------------------------------------------------------------------- blinding

def redact(text):
    return ARM_TOKENS.sub("[ARM]", text)


def run_id(rundir, salt):
    return hashlib.sha256((salt + "|" + str(rundir)).encode()).hexdigest()[:8]


def cmd_seal(a):
    """Blinded copies of every run under OUT, plus the sealed mapping one level up.

    Flagless recall is set row by row by a human. While the run's path carried the arm's name,
    the rater knew which arm they were grading. `blind/<id>/report.txt` holds the deliverable
    with arm-identifying tokens removed; `sealed-map.json` sits outside `blind/` and is read by
    `stats`, after the rating. Procedural blinding only: the mapping is on the same disk, and the
    report's own wording can still reveal the arm.
    """
    out = Path(a.out)
    blind = out / "blind"
    blind.mkdir(parents=True, exist_ok=True)
    mapping = out / "sealed-map.json"
    m = json.loads(mapping.read_text()) if mapping.exists() else {"salt": os.urandom(16).hex(), "runs": {}}
    runs = sorted(p.parent for p in out.glob("*/*/run*/result.json"))
    for d in runs:
        r = json.loads((d / "result.json").read_text())
        rid = run_id(d.relative_to(out), m["salt"])
        dest = blind / rid
        dest.mkdir(exist_ok=True)
        tr = d / "transcript.jsonl"
        text = score.final_report(tr, score.events(tr)[1], d) if tr.exists() else ""
        (dest / "report.txt").write_text(redact(text))
        (dest / "meta.json").write_text(json.dumps(
            {"id": rid, "target": r.get("target"), "blinded": True,
             "report_sha256": hashlib.sha256(text.encode()).hexdigest()}, indent=1))
        m["runs"][rid] = {"rundir": str(d.relative_to(out)), "framework": r.get("framework"),
                          "target": r.get("target"), "run": r.get("run"),
                          "coverage_gate": r.get("coverage_gate"),
                          "treatment": r.get("treatment")}
        print(f"{rid}\t{r.get('target')}\t{dest}")
    mapping.write_text(json.dumps(m, indent=1))
    print(f"\n{len(runs)} runs -> {blind}\nsealed mapping: {mapping} (do not open it while rating)")


def unseal(rundir):
    """(label, record) for a rundir, resolving a blinded id through the sealed map."""
    d = Path(rundir)
    mapping = d.parent.parent / "sealed-map.json"
    if d.parent.name == "blind" and mapping.exists():
        rec = json.loads(mapping.read_text())["runs"].get(d.name)
        if rec:
            return f"{rec['framework']}/{rec['target']}/run{rec['run']}" + \
                   (" +gate" if rec.get("coverage_gate") else ""), rec
    return str(d), {}


# --------------------------------------------------------------------------- triage

def findings(report):
    """The findings the arm reported, as headings. A prefill: the split is the rater's call."""
    heads = [h.strip() for h in re.findall(r"^#{2,6}\s+(.+?)\s*$", report, re.M)]
    heads = [h for h in heads if not BOILERPLATE.fullmatch(re.sub(r"^[\d.\s)]+", "", h))]
    if len(heads) < 2:
        heads = [h.strip() for h in re.findall(r"^\s*(?:\d+[.)]|[-*])\s+\*\*(.+?)\*\*", report, re.M)]
    seen, out = set(), []
    for h in heads:
        key = re.sub(r"\W+", "", h.lower())
        if key and key not in seen:
            seen.add(key)
            out.append(h)
    return out


def make_triage(target, rundir, report_file=None, rater="r1"):
    """The skeleton a rater fills in: every ground-truth entry, and every reported finding.

    Both lists are required. The version before 13 November 2026 had only the ground-truth list,
    so a false positive the arm reported had nowhere to go and precision could only ever be 1.00.
    """
    gt, rundir = truth(target), Path(rundir)
    tr = rundir / "transcript.jsonl"
    txt = rundir / "report.txt"                      # a blinded, redacted deliverable
    if report_file:
        report = Path(report_file).read_text(errors="replace")
    elif txt.exists():
        report = txt.read_text(errors="replace")
    else:
        # With the scaffolding loaded the deliverable is engagements/<dir>/report.md and the final
        # message is only a summary, so score.final_report prefers the report file.
        report = score.final_report(tr, score.events(tr)[1], rundir)
    rows = [{"id": v["id"], "title": v["title"], "class": v["class"], "bench_tag": v.get("bench_tag"),
             "status": "", "evidence": "", "note": "",
             "hint": "class named in the report" if v.get("bench_tag")
                     and score.tag_patterns(v["bench_tag"]).search(report) else ""}
            for v in scored(gt)]
    reported = [{"n": i + 1, "heading": h, "status": "", "maps_to": "", "note": ""}
                for i, h in enumerate(findings(report))]
    return {"target_id": target, "rater": rater, "rubric": str(RUBRIC.relative_to(RUBRIC.parents[2])),
            "rubric_sha256": bench_run.sha256_file(RUBRIC),
            "report_sha256": hashlib.sha256(report.encode()).hexdigest(),
            "blinded": txt.exists() and not report_file,
            "scored": len(rows), "truth": rows, "reported": reported,
            "note": "Rate against data/triage-rubric.md. truth[].status: found|missed, with the "
                    "proof in evidence. reported[].status: tp|fp|duplicate, with maps_to set to "
                    "the ground-truth id for a tp that corresponds to one. `hint` is a coarse "
                    "keyword match, not a finding. Both lists must be complete or no precision "
                    "is computed."}


def cmd_score(a):
    res = Path(a.rundir) / "result.json"
    if res.exists():
        r = json.loads(res.read_text())
        if r.get("excluded") and not a.force:
            raise SystemExit(f"{a.rundir} is {r.get('status')}: {r.get('status_reason')} -- "
                             "unscored, nothing to triage (--force to triage it anyway)")
    out = Path(a.rundir) / f"triage-{a.rater}.json"
    if out.exists() and not a.force:
        raise SystemExit(f"{out} exists (human triage?); --force to overwrite")
    t = make_triage(a.target, a.rundir, a.report, a.rater)
    out.write_text(json.dumps(t, indent=1))
    print(f"{out}: {t['scored']} ground-truth rows, {len(t['reported'])} reported findings, "
          f"blinded={t['blinded']}\nrubric: {RUBRIC}")


def triage_files(rundir):
    return sorted(Path(rundir).glob("triage*.json"))


def tally(target, rundir, rater=None):
    """Counts for one run and one rater, plus why precision is or is not computable."""
    files = triage_files(rundir)
    if rater:
        files = [f for f in files if f.name in (f"triage-{rater}.json",)]
    if not files:
        raise SystemExit(f"no triage file in {rundir} (labs.py score {target} {rundir})")
    t = json.loads(files[0].read_text())
    gt_ids = {v["id"] for v in scored(truth(target))}
    c = {s: 0 for s in TRUTH_STATUSES + REPORTED_STATUSES}
    c.update(pending=0, scored=0, reported=0, rater="?", precision_refused="")
    if "truth" not in t:
        # Pre-13-November schema: one list, statuses found/missed/fp, no accounting of what the
        # arm reported. Recall is readable; precision is not, and was never measured.
        for r in t.get("rows", []):
            if r.get("status") in TRUTH_STATUSES:
                c[r["status"]] += 1
        c["pending"] = sum(1 for r in t.get("rows", [])
                           if r.get("id") in gt_ids and r.get("status") not in TRUTH_STATUSES)
        c["scored"] = len(gt_ids)
        c["reported"] = 0
        c["precision_refused"] = "legacy triage schema: no accounting of reported findings"
        c["rater"] = t.get("rater", "?")
        return c
    for r in t["truth"]:
        if r.get("status") in TRUTH_STATUSES:
            c[r["status"]] += 1
    for r in t["reported"]:
        if r.get("status") in REPORTED_STATUSES:
            c[r["status"]] += 1
    c["pending"] = sum(1 for r in t["truth"] if r["id"] in gt_ids and r.get("status") not in TRUTH_STATUSES)
    c["scored"] = len(gt_ids)
    c["reported"] = len(t["reported"])
    c["rater"] = t.get("rater", "?")
    unset = sum(1 for r in t["reported"] if r.get("status") not in REPORTED_STATUSES)
    found_ids = {r["id"] for r in t["truth"] if r.get("status") == "found"}
    mapped = {r.get("maps_to") for r in t["reported"] if r.get("status") == "tp" and r.get("maps_to")}
    c["precision_refused"] = (
        f"{unset} reported finding(s) unclassified" if unset else
        "no reported findings recorded" if not t["reported"] else
        f"tp rows map to {sorted(mapped - found_ids)}, which are not marked found"
        if mapped - found_ids else
        f"found entries {sorted(found_ids - mapped)} have no tp row mapping to them"
        if found_ids - mapped else "")
    return c


def row(name, c):
    rec = f"{c['found'] / c['scored']:.2f}" if c["scored"] else "-"
    if c["pending"]:
        rec += "+"                                  # lower bound: triage unfinished
    pr = c["tp"] + c["fp"]
    prec = "-" if c.get("precision_refused") or not pr else f"{c['tp'] / pr:.2f}"
    return (f"| {name} | {c.get('rater', '?')} | {c['found']} | {c['missed']} | {c['pending']} | "
            f"{c['scored']} | {rec} | {c['tp']} | {c['fp']} | {c['duplicate']} | {prec} |")


def table(target, rundirs, rater=None):
    lines = ["| run | rater | found | missed | pending | scored | recall | tp | fp | dup | precision |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    tot = {k: 0 for k in TRUTH_STATUSES + REPORTED_STATUSES + ("pending", "scored", "reported")}
    tot.update(rater="pooled", precision_refused="")
    refused = []
    for d in rundirs:
        c = tally(target, d, rater)
        for k in tot:
            if isinstance(tot[k], int):
                tot[k] += c.get(k, 0) or 0
        label, _ = unseal(d)
        lines.append(row(label, c))
        if c.get("precision_refused"):
            refused.append(f"{label}: {c['precision_refused']}")
    if len(rundirs) > 1:
        tot["rater"] = rater or "pooled"
        tot["precision_refused"] = "; ".join(refused)
        lines.append(row("**pooled**", tot))
    return "\n".join(lines), refused


def agreement(target, rundir):
    """Simple agreement and Cohen's kappa between two raters over the ground-truth rows."""
    files = [f for f in triage_files(rundir) if "truth" in json.loads(f.read_text())]
    if len(files) < 2:
        return None
    a, b = (json.loads(f.read_text()) for f in files[:2])
    pa = {r["id"]: r.get("status") for r in a["truth"]}
    pb = {r["id"]: r.get("status") for r in b["truth"]}
    ids = [i for i in pa if pa[i] in TRUTH_STATUSES and pb.get(i) in TRUTH_STATUSES]
    if not ids:
        return None
    n = len(ids)
    obs = sum(pa[i] == pb[i] for i in ids) / n
    exp = sum((sum(pa[i] == s for i in ids) / n) * (sum(pb[i] == s for i in ids) / n)
              for s in TRUTH_STATUSES)
    kappa = (obs - exp) / (1 - exp) if exp < 1 else 1.0
    return {"raters": [a.get("rater"), b.get("rater")], "rows": n,
            "agreement": round(obs, 3), "cohens_kappa": round(kappa, 3)}


def cmd_stats(a):
    print(f"## {a.target}: recall = found / scored, precision = tp / (tp + fp)\n")
    t, refused = table(a.target, a.rundirs, a.rater)
    print(t)
    print("\n`recall` with a `+` is a lower bound: triage unfinished.")
    if refused:
        print("\nPrecision not computed:")
        for r in refused:
            print(f"- {r}")
        print("\nAn incomplete triage gets no precision number. The schema used before "
              "13 November 2026 could not record a false positive at all, so the precision of "
              "1.00 it reported was a property of the schema.")
    for d in a.rundirs:
        ag = agreement(a.target, d)
        if ag:
            print(f"\nInter-rater, {unseal(d)[0]}: {ag['raters']}, {ag['rows']} rows, "
                  f"agreement {ag['agreement']}, Cohen's kappa {ag['cohens_kappa']}")


def cmd_selftest(a):
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        # No arm may be handed a root from which the ground truth or the scoring code is readable.
        assert xben.sealed_violations([str(xben.GROUND_TRUTH)])
        assert xben.sealed_violations([str(Path(__file__).resolve().parent.parent)]), \
            "the repo root must be refused: it contains bench/data/ground_truth"
        assert xben.sealed_violations([str(xben.GROUND_TRUTH.parent)])
        assert not xben.sealed_violations([str(d), str(xben.ASSET_ROOT / "x")])
        for fw in ("mythos", "control", "claude_mythos", "claude_control"):
            g = importlib.import_module(f"runners.{fw}").grants(d)
            assert not xben.sealed_violations(g["roots"]), (fw, g["roots"])
            assert "scaffolding" in g["treatment"] and "coverage_gate" in g["treatment"], fw

        # Both arms must run the same model everywhere. `--model` only moves the orchestrator,
        # so the mythos arm pins all seven agents through OPENCODE_CONFIG_CONTENT.
        from runners import mythos as _mythos
        g = _mythos.grants(d, "zai/glm-5.3")
        cfg = g["per_agent_models"]
        assert cfg["model"] == "zai/glm-5.3"
        assert cfg["agent"] and all(v["model"] == "zai/glm-5.3" for v in cfg["agent"].values()), cfg
        assert "configured" in g["per_agent_models_source"]
        try:
            _mythos.grants(d, "sonnet")          # unqualified: read as a profile name, not a model
            raise AssertionError("an unqualified model id must be refused, not guessed")
        except RuntimeError:
            pass

        # triage skeleton: both lists, pre-filled from the report
        rep = ("## Finding 1: SQL injection in /login\nproof\n## Finding 2: BOLA on /users/1\n"
               "proof\n## Methodology\nnot a finding\n")
        (d / "report.txt").write_text(rep)
        t = make_triage("vampi", d)
        assert t["scored"] == 9 and t["blinded"] and t["rubric_sha256"]
        assert [r["heading"] for r in t["reported"]] == ["Finding 1: SQL injection in /login",
                                                         "Finding 2: BOLA on /users/1"], t["reported"]
        assert any(r["hint"] for r in t["truth"])

        # an unfinished reported list gets no precision, however complete the truth list is
        for i, r in enumerate(t["truth"]):
            r["status"] = "found" if i < 3 else "missed"
        (d / "triage-r1.json").write_text(json.dumps(t))
        c = tally("vampi", d)
        assert (c["found"], c["missed"], c["scored"], c["pending"]) == (3, 6, 9, 0), c
        assert c["precision_refused"] and "-" in row("x", c).split("|")[-2]

        # a complete, consistent triage: precision counts the false positive
        ids = [r["id"] for r in t["truth"] if r["status"] == "found"]
        t["reported"] = [{"n": 1, "heading": "a", "status": "tp", "maps_to": ids[0]},
                         {"n": 2, "heading": "b", "status": "tp", "maps_to": ids[1]},
                         {"n": 3, "heading": "c", "status": "tp", "maps_to": ids[2]},
                         {"n": 4, "heading": "d", "status": "fp", "maps_to": ""},
                         {"n": 5, "heading": "d again", "status": "duplicate", "maps_to": "4"}]
        (d / "triage-r1.json").write_text(json.dumps(t))
        c = tally("vampi", d)
        assert not c["precision_refused"], c["precision_refused"]
        assert (c["tp"], c["fp"], c["duplicate"]) == (3, 1, 1), c
        tbl, refused = table("vampi", [d])
        assert "0.33" in tbl and "0.75" in tbl and not refused, tbl

        # a found entry no reported row accounts for is an inconsistency, not a precision of 1.00
        t2 = json.loads(json.dumps(t))
        t2["reported"] = t2["reported"][:1]
        (d / "triage-r1.json").write_text(json.dumps(t2))
        assert "have no tp row" in tally("vampi", d)["precision_refused"]
        (d / "triage-r1.json").write_text(json.dumps(t))

        # a second rater gives an agreement figure
        t2 = json.loads(json.dumps(t))
        t2["rater"] = "r2"
        t2["truth"][0]["status"] = "missed"
        (d / "triage-r2.json").write_text(json.dumps(t2))
        ag = agreement("vampi", d)
        assert ag and ag["rows"] == 9 and ag["agreement"] < 1.0, ag

        # the legacy one-list schema is readable for recall and refuses precision
        (d / "legacy").mkdir()
        (d / "legacy" / "triage.json").write_text(json.dumps(
            {"target_id": "vampi", "scored": 9,
             "rows": [{"id": v["id"], "status": "found" if i < 8 else "missed"}
                      for i, v in enumerate(scored(truth("vampi")))]}))
        c = tally("vampi", d / "legacy")
        assert c["found"] == 8 and "legacy" in c["precision_refused"], c

        # blinding removes the arm's name from what the rater reads
        assert "mythos" not in redact("The mythos orchestrator used /cybersecurity and a sub-agent.")
        assert run_id("a/b", "s1") != run_id("a/b", "s2")
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(f=cmd_list)
    sub.add_parser("selftest").set_defaults(f=cmd_selftest)
    sub.add_parser("rubric").set_defaults(f=cmd_rubric)
    for n, f in (("up", cmd_up), ("down", cmd_down)):
        sub.add_parser(n).set_defaults(f=f)
        sub.choices[n].add_argument("target")
    p = sub.add_parser("run"); p.set_defaults(f=cmd_run)
    p.add_argument("target"); p.add_argument("--framework", required=True, choices=("mythos", "control", "claude_mythos", "claude_control", "strix",
                                     "pentestgpt", "cai"))
    p.add_argument("--model", default="opencode/glm-5.3-flash-free"); p.add_argument("--budget", type=int, default=1800)
    p.add_argument("--out", required=True); p.add_argument("--run", type=int, default=0)
    p.add_argument("--coverage-gate", choices=("on", "off", "auto"), default="auto",
                   help="the condition you intend to run; checked against hooks/hooks.json")
    p.add_argument("--scope-confirmed", action="store_true")
    p = sub.add_parser("seal"); p.set_defaults(f=cmd_seal)
    p.add_argument("out", help="sweep output dir holding <fw>/<target>/run<N>/")
    p = sub.add_parser("score"); p.set_defaults(f=cmd_score)
    p.add_argument("target"); p.add_argument("rundir"); p.add_argument("--force", action="store_true")
    p.add_argument("--rater", default="r1", help="writes triage-<rater>.json")
    p.add_argument("--report", help="report file to triage instead of the run's own deliverable")
    p = sub.add_parser("stats"); p.set_defaults(f=cmd_stats)
    p.add_argument("target"); p.add_argument("rundirs", nargs="+")
    p.add_argument("--rater", help="only this rater's triage files")
    a = ap.parse_args()
    if a.cmd not in ("list", "selftest", "rubric", "seal"):
        truth(a.target)
    a.f(a)


if __name__ == "__main__":
    main()
