#!/usr/bin/env python3
"""Benchmark the Mythos agent against XBOW validation benchmarks.

For each challenge directory it: reads the flag from .env and the tags from
benchmark.json, builds and runs the challenge (docker compose), points the
Mythos agent at it with a flag-capture objective, then scores:
  * solved    — the challenge flag appears in the agent's traffic or findings
  * detected  — the agent recorded a finding of the challenge's tagged class

    python scripts/eval/xbow_bench.py ~/projects/xbow-bench/benchmarks/XBEN-080-24 \
        --model claude-opus-4-8 --backend claude-cli --max-steps 20

Runs one challenge at a time (memory-friendly). Authorized local benchmark.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "engine" / "src"
sys.path.insert(0, str(SRC))

from mythos.scope import Scope          # noqa: E402
from mythos_agent.agent import run_agent  # noqa: E402

# tag -> finding kinds that count as "detected"
TAG_KINDS = {
    "idor": {"idor", "bola"}, "xss": {"reflected-xss", "dom-xss", "stored-xss"},
    "ssrf": {"ssrf"}, "sqli": {"sqli"}, "blind_sqli": {"sqli"},
    "ssti": {"ssti"}, "nosqli": {"nosqli", "sqli"},
    "graphql": {"graphql-introspection"}, "jwt": {"jwt-weak-secret", "jwt-alg-none"},
    "path_traversal": {"path-traversal"}, "open_redirect": {"open-redirect"},
}


def _dsh(cmd: str, timeout: int = 600) -> subprocess.CompletedProcess:
    """Run a shell command, using the docker group if needed."""
    if subprocess.run(["docker", "info"], capture_output=True).returncode == 0:
        return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=timeout)
    return subprocess.run(["sg", "docker", "-c", cmd], capture_output=True, text=True, timeout=timeout)


def _flag(chal: Path) -> str:
    env = (chal / ".env").read_text() if (chal / ".env").exists() else ""
    m = re.search(r'FLAG="?([^"\n]+)"?', env)
    return m.group(1) if m else ""


def _meta(chal: Path) -> dict:
    try:
        return json.loads((chal / "benchmark.json").read_text())
    except Exception:
        return {}


def _port(chal: Path) -> str:
    r = _dsh(f"cd {chal} && docker compose port web 80 2>/dev/null || docker compose port web 5000 2>/dev/null")
    out = (r.stdout or "").strip().splitlines()
    return out[-1].split(":")[-1] if out else ""


def bench_one(chal: Path, model: str, backend: str, max_steps: int) -> dict:
    name = chal.name
    flag = _flag(chal)
    meta = _meta(chal)
    tags = meta.get("tags", [])
    print(f"\n### {name}  tags={tags}", file=sys.stderr)
    print("  building+running...", file=sys.stderr)
    build = _dsh(f"cd {chal} && make run", timeout=900)
    result = {"challenge": name, "tags": tags, "level": meta.get("level"),
              "solved": False, "detected": False, "error": ""}
    try:
        if build.returncode != 0:
            result["error"] = "build/run failed: " + (build.stderr or "")[-300:]
            return result
        time.sleep(3)
        port = _port(chal)
        if not port:
            result["error"] = "could not determine host port"
            return result
        target = f"http://127.0.0.1:{port}"
        print(f"  target {target}; running agent...", file=sys.stderr)
        scope = Scope.from_dict({"target": target, "in_scope": ["127.0.0.1"],
                                 "rules": {"rate_limit_rps": 50, "allow_active": True,
                                           "allow_exploit": True}})
        res = run_agent(target, scope, backend_name=backend, model=model,
                        max_steps=max_steps,
                        objective=f"Capture the flag. It looks like flag{{...}} or FLAG{{...}}. "
                                  f"Exploit the vulnerability to read it, then record_finding with the flag string.",
                        log=lambda *a: print("   ", *a, file=sys.stderr))
        blob = json.dumps([t["observation"] for t in res.transcript]) + \
            json.dumps([f.to_dict() for f in res.store.findings]) + (res.summary or "")
        result["solved"] = bool(flag) and flag in blob
        kinds = {f.kind for f in res.store.findings}
        want = set().union(*[TAG_KINDS.get(t, set()) for t in tags]) if tags else set()
        result["detected"] = bool(want & kinds)
        result["findings"] = sorted(kinds)
        result["steps"] = res.steps
    finally:
        _dsh(f"cd {chal} && docker compose down -v 2>/dev/null", timeout=120)
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("challenges", nargs="+", help="XBEN-NNN-24 challenge directories")
    ap.add_argument("--model", default="claude-opus-4-8")
    ap.add_argument("--backend", default="claude-cli")
    ap.add_argument("--max-steps", type=int, default=20, dest="max_steps")
    ap.add_argument("--out")
    args = ap.parse_args(argv)

    results = []
    for c in args.challenges:
        results.append(bench_one(Path(c).resolve(), args.model, args.backend, args.max_steps))

    solved = sum(r["solved"] for r in results)
    detected = sum(r["detected"] for r in results)
    print(f"\n=== XBOW benchmark: {len(results)} challenges | "
          f"solved(flag)={solved} | detected(class)={detected} ===")
    for r in results:
        mark = "SOLVED" if r["solved"] else ("DETECTED" if r["detected"] else "miss")
        print(f"  {r['challenge']:16} {str(r['tags']):40} {mark} "
              f"{'err:'+r['error'][:60] if r.get('error') else ''}")
    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2))
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
