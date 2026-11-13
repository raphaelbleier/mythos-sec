#!/usr/bin/env python3
"""Run (framework x challenge x run) cells against XBOW, score by the harness.

  python3 bench/run.py --frameworks mythos,control --model opencode/glm-5.3-flash-free \
      --sample 30 --seed 1 --runs 3 --parallel 3 --dry-run          # plan only, no Docker
  python3 bench/run.py ... --scope-confirmed                        # actually attack

Without --scope-confirmed the planned targets are printed and the run exits 2. Targets are always
local: every published port is rebound to the docker0 gateway (or loopback), and a cell whose
endpoint is not local is refused. Each cell gets a fresh compose project bench_<fw>_<chal>_<run>,
a random FLAG baked in at build time, a scope.yaml restricted to its one host:port, a fixed wall
clock and a clean agent HOME. Scoring: see score.py. Existing result.json cells are skipped, so a
sweep can be resumed. Frameworks are adapters in bench/runners/: mythos and control run on the OpenCode host,
claude_mythos and claude_control on the Claude Code host, plus strix (
pentestgpt and cai are interactive-only and refused).
"""
import argparse, hashlib, importlib, ipaddress, json, os, secrets, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import score, xben

FRAMEWORKS = ("mythos", "control", "claude_mythos", "claude_control", "strix",
              "pentestgpt", "cai")


def is_local(host, gateway):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or host == gateway


def write_scope(path, url):
    host, port = url.split("//", 1)[1].rsplit(":", 1)
    path.write_text(f"""# written by bench/run.py: one local XBEN lab target, nothing else
target: {url}
in_scope:
  - {host}
out_of_scope: []
ports: [{port}]  # only this port of {host} is authorized
rules:
  rate_limit_rps: 20
  max_requests: 20000
  allow_active: true
  allow_exploit: true
identities: []
notes: "Isolated local CTF benchmark target. Only {host}:{port} is in scope."
""")


def tree_sha256(run_dir):
    h = hashlib.sha256()
    for p in sorted(run_dir.rglob("*")):
        rel = p.relative_to(run_dir)
        if p.is_file() and not p.is_symlink() and p.name != "result.json" and "home" not in rel.parts:
            h.update(str(rel).encode() + b"\0" + p.read_bytes())
    return h.hexdigest()


def model_for(fw, a):
    return (a.strix_model or os.environ.get("STRIX_LLM", "")) if fw == "strix" else a.model


def sha256_file(path):
    p = Path(path)
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None


def arm_grants(fw, workdir, model=None):
    """`grants()` of one runner, or a placeholder for an arm that does not implement it."""
    mod = importlib.import_module(f"runners.{fw}")
    return mod.grants(workdir, model) if hasattr(mod, "grants") else {"roots": [], "treatment": {}}


def check_grants(fws, a):
    """Refuse the sweep if any arm is handed a root from which it could read the scoring key.

    Until 13 November 2026 the mythos arm ran with `--plugin-dir <repo> --add-dir <repo>`, which
    contains `bench/data/ground_truth/*.json`, while the control arm got an empty directory.
    Nothing checked it and nothing would have detected it. This is that check.
    """
    bad, declared = [], {}
    with __import__("tempfile").TemporaryDirectory() as probe:
        for fw in fws:
            g = arm_grants(fw, probe)
            declared[fw] = g
            bad += [f"{fw}: {v}" for v in xben.sealed_violations(g["roots"])]
    if bad:
        raise SystemExit("refusing: an arm could read what it is scored against\n  " + "\n  ".join(bad))
    if a.coverage_gate != "auto":
        want = a.coverage_gate == "on"
        for fw, g in declared.items():
            if "coverage_gate" in g["treatment"] and bool(g["treatment"]["coverage_gate"]) != want \
                    and g["treatment"].get("scaffolding") is True:
                raise SystemExit(f"refusing: --coverage-gate {a.coverage_gate} but the gate is "
                                 f"{'wired' if not want else 'not wired'} in {fw}'s assets "
                                 "(hooks/hooks.json). Fix one of the two; the condition must be "
                                 "recorded, not implied by the output directory name.")
    return declared


def run_cell(fw, chal, run_idx, a):
    run_dir = Path(a.out) / fw / chal["id"] / f"run{run_idx}"
    res_path = run_dir / "result.json"
    if res_path.exists():
        return json.loads(res_path.read_text())
    run_dir.mkdir(parents=True, exist_ok=True)
    project = f"bench_{fw}_{chal['id']}_{run_idx}".lower().replace("-", "_")
    flag = "FLAG{" + secrets.token_hex(32) + "}"  # same shape as upstream sha256 flags, not derivable
    grants = arm_grants(fw, run_dir, model_for(fw, a))
    res = {"framework": fw, "model": model_for(fw, a), "challenge": chal["id"], "level": chal["level"],
           "tags": chal["tags"], "run": run_idx, "project": project, "apt_fix": not a.no_apt_fix,
           "budget_s": a.timeout, "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           # everything needed to place this cell in a condition without reading the directory name
           "treatment": grants["treatment"], "readable_roots": grants["roots"],
           # the model of every agent, not just the orchestrator's alias
           "per_agent_models": grants.get("per_agent_models"),
           "per_agent_models_source": grants.get("per_agent_models_source"),
           "coverage_gate": bool(grants["treatment"].get("coverage_gate")),
           "repo_commit": a.repo_commit, "host_versions": a.host_versions,
           "toolbox_image": a.toolbox_image, "objective": os.environ.get("BENCH_OBJECTIVE", "flag"),
           "status": "ok"}
    tdir = Path(a.out) / ".targets" / project  # compose.json/target.log: outside the agent's workdir
    tdir.mkdir(parents=True, exist_ok=True)
    target = xben.Target(chal, project, flag, tdir, a.bind_ip, apt_fix=not a.no_apt_fix)
    try:
        try:
            endpoints = target.up()
        except (subprocess.SubprocessError, OSError, KeyError) as e:
            res.update(status="target_failed", error=repr(e)[:500], solved=False)
            return res
        res["endpoints"] = endpoints
        if not endpoints:
            res.update(status="target_failed", error="no published port", solved=False)
            return res
        url = f"http://{endpoints[0]}"
        if not all(is_local(e.rsplit(":", 1)[0], a.gateway) for e in endpoints):
            res.update(status="scope_refused", error=f"non-local endpoint in {endpoints}", solved=False)
            return res
        res["target_url"] = url
        write_scope(run_dir / "scope.yaml", url)
        res["scope_sha256"] = sha256_file(run_dir / "scope.yaml")
        res["compose_sha256"] = sha256_file(tdir / "compose.json")  # pins the resolved build inputs
        runner = importlib.import_module(f"runners.{fw}")
        try:
            transcript = runner.run(url, run_dir, res["model"], a.timeout)
        except (NotImplementedError, RuntimeError, OSError) as e:
            res.update(status="runner_failed", error=str(e)[:500], solved=False)
            return res
        # Canaries are read here and never stored: the result row carries only the hit count.
        res.update(score.score(flag, transcript, chal["tags"], run_dir, xben.canaries(chal), url))
        res["status"], res["status_reason"] = score.classify(res)
        res["excluded"] = res["status"] in score.EXCLUDED
    finally:
        target.down()
        if res["status"] != "target_failed" or a.keep_failed:
            res["flag"] = flag
            res["trace_sha256"] = tree_sha256(run_dir)
            res_path.write_text(json.dumps(res, indent=1))
        print(f"{fw:8} {chal['id']} run{run_idx} {res['status']:13} solved={res.get('solved')} "
              f"detected={res.get('detected')} {res.get('wall_s', '-')}s", flush=True)
    return res


def toolbox_image_id():
    """The toolbox image the mythos arms will drive, so a sweep pins its tool versions."""
    for ref in ("mythos-toolbox:local", "ghcr.io/raphaelbleier/mythos-toolbox:latest"):
        try:
            r = subprocess.run(["docker", "image", "inspect", ref, "-f", "{{.Id}}"],
                               capture_output=True, text=True, check=True)
            return {"ref": ref, "id": r.stdout.strip()}
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    return None


def print_plan(cells, a, bind):
    print(f"# {len(cells)} cells -> {a.out}")
    print(f"# every target: http://{bind}:<ephemeral port>  (local only; scope.yaml = that one host:port)")
    for fw, c, r in cells:
        project = f"bench_{fw}_{c['id']}_{r}".lower().replace("-", "_")
        print(f"{fw}\t{model_for(fw, a) or '-'}\t{c['id']}\tL{c['level']}\trun{r}\t{project}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--frameworks", default="mythos,control", help=",".join(FRAMEWORKS))
    ap.add_argument("--model", default="opencode/glm-5.3-flash-free", help="provider/model for opencode arms")
    ap.add_argument("--strix-model", help="LiteLLM model id for strix (default: $STRIX_LLM)")
    ap.add_argument("--challenges", help="comma-separated XBEN ids")
    ap.add_argument("--sample", type=int, help="stratified sample of buildable challenges")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--build-tsv", default=str(xben.BUILD_TSV), help="pre-flight build list (ok rows are used)")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--timeout", "--budget", type=int, default=1800, help="wall clock per cell in seconds")
    ap.add_argument("--parallel", type=int, default=3, help="concurrent cells (free models: 2-3)")
    ap.add_argument("--bind-ip", help="host IP targets publish on (default: docker0 gateway; must be local)")
    ap.add_argument("--no-apt-fix", action="store_true", help="build upstream Dockerfiles unpatched")
    ap.add_argument("--keep-failed", action="store_true", help="write result.json for target failures too")
    ap.add_argument("--dry-run", action="store_true", help="print the plan, touch no Docker")
    ap.add_argument("--scope-confirmed", action="store_true",
                    help="required to run: confirms the planned local targets are authorized")
    ap.add_argument("--coverage-gate", choices=("on", "off", "auto"), default="auto",
                    help="the condition you intend to run; checked against hooks/hooks.json and "
                         "recorded per cell (default: record whatever is wired)")
    ap.add_argument("--out", default=str(xben.RESULTS_ROOT / datetime.now().strftime("%Y%m%d-%H%M")),
                    help="outside the repo, so the control arm cannot pick up AGENTS.md from a parent dir")
    a = ap.parse_args()

    fws = a.frameworks.split(",")
    for fw in fws:
        if fw not in FRAMEWORKS:
            raise SystemExit(f"unknown framework {fw} (choose from {', '.join(FRAMEWORKS)})")
    grants = check_grants([f for f in fws if f not in ("pentestgpt", "cai")], a)
    for fw in fws:
        if fw in ("pentestgpt", "cai"):
            try:
                importlib.import_module(f"runners.{fw}").run(None, None, None, None)
            except NotImplementedError as e:
                raise SystemExit(str(e))

    chals = xben.load_challenges()
    if a.challenges:
        want = set(a.challenges.split(","))
        chals = [c for c in chals if c["id"] in want]
    else:
        built = xben.load_build_status(a.build_tsv)
        chals = [c for c in chals if built.get(c["id"])]
        if a.sample:
            chals = xben.stratified_subset(chals, a.sample, a.seed)
    if not chals:
        raise SystemExit("no challenges selected (build TSV empty? pass --challenges or --build-tsv)")
    # run-major order: every challenge gets run 0 before any gets run 1, so a cut sweep stays paired
    cells = [(fw, c, r) for r in range(a.runs) for c in chals for fw in fws]

    if a.dry_run:
        return print_plan(cells, a, a.bind_ip or "<docker0 gateway>")
    a.gateway = xben.docker_gateway()
    a.bind_ip = a.bind_ip or a.gateway
    print_plan(cells, a, a.bind_ip)
    if not is_local(a.bind_ip, a.gateway):
        raise SystemExit(f"refusing: bind IP {a.bind_ip} is neither loopback nor the docker0 gateway {a.gateway}")
    if not a.scope_confirmed:
        print("\nNot started. These local lab targets are the whole scope; re-run with --scope-confirmed.",
              file=sys.stderr)
        raise SystemExit(2)

    Path(a.out).mkdir(parents=True, exist_ok=True)
    from runners import base as runners_base
    a.repo_commit = runners_base.repo_commit()
    a.host_versions = {h: runners_base.host_version(h) for h in ("opencode", "claude", "docker", "uv")}
    a.toolbox_image = toolbox_image_id()
    (Path(a.out) / "sweep.json").write_text(json.dumps(
        {**{k: v for k, v in vars(a).items() if k != "grants"},
         "challenges": [c["id"] for c in chals],
         "arms": {fw: grants[fw] for fw in fws},
         "ground_truth_dir": str(xben.GROUND_TRUTH),
         "xben_dir": str(xben.XBEN_DIR),
         "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}, indent=1))
    with ThreadPoolExecutor(a.parallel) as pool:
        list(pool.map(lambda cell: run_cell(*cell, a), cells))
    rows = score.write_jsonl(a.out)
    print(f"{len(rows)} cells -> {Path(a.out) / 'results.jsonl'}")


if __name__ == "__main__":
    main()
