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


def run_cell(fw, chal, run_idx, a):
    run_dir = Path(a.out) / fw / chal["id"] / f"run{run_idx}"
    res_path = run_dir / "result.json"
    if res_path.exists():
        return json.loads(res_path.read_text())
    run_dir.mkdir(parents=True, exist_ok=True)
    project = f"bench_{fw}_{chal['id']}_{run_idx}".lower().replace("-", "_")
    flag = "FLAG{" + secrets.token_hex(32) + "}"  # same shape as upstream sha256 flags, not derivable
    res = {"framework": fw, "model": model_for(fw, a), "challenge": chal["id"], "level": chal["level"],
           "tags": chal["tags"], "run": run_idx, "project": project, "apt_fix": not a.no_apt_fix,
           "budget_s": a.timeout, "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
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
        runner = importlib.import_module(f"runners.{fw}")
        try:
            transcript = runner.run(url, run_dir, res["model"], a.timeout)
        except (NotImplementedError, RuntimeError, OSError) as e:
            res.update(status="runner_failed", error=str(e)[:500], solved=False)
            return res
        res.update(score.score(flag, transcript, chal["tags"], run_dir))
        if res["suspect"]:
            res["status"] = "suspect"  # review the trace before counting it
    finally:
        target.down()
        if res["status"] != "target_failed" or a.keep_failed:
            res["flag"] = flag
            res["trace_sha256"] = tree_sha256(run_dir)
            res_path.write_text(json.dumps(res, indent=1))
        print(f"{fw:8} {chal['id']} run{run_idx} {res['status']:13} solved={res.get('solved')} "
              f"detected={res.get('detected')} {res.get('wall_s', '-')}s", flush=True)
    return res


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
    ap.add_argument("--out", default=str(xben.BENCH_ROOT / "results" / datetime.now().strftime("%Y%m%d-%H%M")),
                    help="outside the repo, so the control arm cannot pick up AGENTS.md from a parent dir")
    a = ap.parse_args()

    fws = a.frameworks.split(",")
    for fw in fws:
        if fw not in FRAMEWORKS:
            raise SystemExit(f"unknown framework {fw} (choose from {', '.join(FRAMEWORKS)})")
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
    oc = subprocess.run(["opencode", "--version"], capture_output=True, text=True).stdout.strip()
    (Path(a.out) / "sweep.json").write_text(json.dumps(
        {**vars(a), "opencode_version": oc, "challenges": [c["id"] for c in chals]}, indent=1))
    with ThreadPoolExecutor(a.parallel) as pool:
        list(pool.map(lambda cell: run_cell(*cell, a), cells))
    rows = score.write_jsonl(a.out)
    print(f"{len(rows)} cells -> {Path(a.out) / 'results.jsonl'}")


if __name__ == "__main__":
    main()
