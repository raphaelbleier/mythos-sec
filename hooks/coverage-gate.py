#!/usr/bin/env python3
"""Mythos coverage gate — Stop hook.

The benchmark's clearest failure is not a wrong answer, it is stopping early: on Vuln Bank
both arms reported 13-15 findings after a few minutes of a 3600s budget and never sent one
request to the target's GraphQL, merchant, bill-payment or card endpoints. A prompt rule did
not prevent that, so this is the code-level version: when the agent tries to finish while
mapped paths are still unaccounted for, the hook hands the open list back and the turn
continues.

Fires at most MAX_NUDGES times per engagement, counted in `.coverage-gate`, so a surface the
agent genuinely cannot reach cannot trap it in a loop. Needs a surface map to do anything
(`scripts/probe <target> --json > engagements/<dir>/surface.json`); with no map it stays silent.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_NUDGES = 3
REPO = Path(__file__).resolve().parent.parent


def engagement():
    """The newest engagement directory.

    The agent may write under the working directory or under the repo, so check both.
    Newest wins even when it carries no surface map: an older engagement that does carry
    one would otherwise hijack the gate, which then checks the wrong report. `ensure_map`
    maps the current engagement when the agent skipped recon.
    """
    roots = ([Path(os.environ["MYTHOS_ENGAGEMENTS"])] if os.environ.get("MYTHOS_ENGAGEMENTS")
             else [Path.cwd() / "engagements", REPO / "engagements"])
    dirs = [d for r in roots for d in r.glob("*") if d.is_dir()]
    if dirs:
        return max(dirs, key=lambda d: d.stat().st_mtime)
    f = os.environ.get("MYTHOS_SCOPE")      # no engagement dir: the run's own workspace
    return Path(f).parent if f and Path(f).exists() else None


def scope_target():
    """The engagement's target, from the active scope file."""
    f = os.environ.get("MYTHOS_SCOPE")
    if not f or not Path(f).exists():
        return None
    for line in Path(f).read_text(errors="replace").splitlines():
        if line.startswith("target:"):
            return line.split(":", 1)[1].strip().strip('"\'')
    return None


def ensure_map(d):
    """Map the surface here if the engagement has not.

    The gate cannot depend on the agent having run the recon step: in the benchmark runs it
    skipped `scripts/probe` and went straight to curl, which left the gate with nothing to
    check. One probe at stop time costs under a minute and is cached.
    """
    f = d / "surface.json"
    if f.exists():
        return True
    target = scope_target()
    if not target:
        return False
    p = subprocess.run([sys.executable, str(REPO / "scripts" / "probe"), target,
                        "--depth", "2", "--json"], capture_output=True, text=True, timeout=300)
    if p.returncode != 0 or not p.stdout.strip():
        return False
    f.write_text(p.stdout)
    return True


def assistant_text(transcript):
    """What the agent actually said. An engagement may report in the conversation and never
    write report.md, and then a file-only check sees no coverage at all."""
    out = []
    try:
        lines = Path(transcript).read_text(errors="replace").splitlines()
    except Exception:
        return None
    for line in lines:
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        msg = ev.get("message") or {}
        for block in (msg.get("content") or []):
            if isinstance(block, dict) and block.get("type") == "text" and block.get("text"):
                out.append(block["text"])
    if not out:
        return None
    f = Path(tempfile.gettempdir()) / "mythos-coverage-said.txt"
    f.write_text("\n\n".join(out))
    return str(f)


def main():
    said = None
    try:
        event = json.load(sys.stdin)
        if event.get("transcript_path"):
            said = assistant_text(event["transcript_path"])
    except Exception:
        pass
    d = engagement()
    if d is None or not ensure_map(d):
        return 0
    counter = d / ".coverage-gate"
    try:
        fired = int(counter.read_text().strip() or 0) if counter.exists() else 0
    except (ValueError, OSError):
        fired = 0                        # a corrupt counter must not crash the Stop hook
    if fired >= MAX_NUDGES:
        return 0
    argv = [sys.executable, str(REPO / "scripts" / "coverage"), str(d), "--list", "15"]
    if said:
        argv += ["--text", said]
    p = subprocess.run(argv, capture_output=True, text=True)
    if p.returncode != 1:
        return 0
    counter.write_text(str(fired + 1))
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "Stop",
        "additionalContext":
            "MYTHOS COVERAGE GATE: mapped paths are still unaccounted for in "
            f"{d}/report.md. Test each one or write down explicitly that it was tested and "
            "not vulnerable, with the request and response. Stay inside the scope file and "
            f"keep the non-destructive rules.\n\n{p.stdout.strip()}\n\n"
            f"(nudge {fired + 1} of {MAX_NUDGES}; after that you may finish with the gaps named "
            "in the report.)"}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
