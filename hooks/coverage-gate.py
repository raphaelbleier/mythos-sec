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
from pathlib import Path

MAX_NUDGES = 3
REPO = Path(__file__).resolve().parent.parent


def engagement():
    """The newest engagement directory that has a surface map.

    The agent may write under the working directory or under the repo, so check both.
    """
    roots = ([Path(os.environ["MYTHOS_ENGAGEMENTS"])] if os.environ.get("MYTHOS_ENGAGEMENTS")
             else [Path.cwd() / "engagements", REPO / "engagements"])
    dirs = [d for r in roots for d in r.glob("*") if (d / "surface.json").exists()]
    return max(dirs, key=lambda d: d.stat().st_mtime) if dirs else None


def main():
    try:
        json.load(sys.stdin)
    except Exception:
        pass
    d = engagement()
    if d is None:
        return 0
    counter = d / ".coverage-gate"
    fired = int(counter.read_text().strip() or 0) if counter.exists() else 0
    if fired >= MAX_NUDGES:
        return 0
    p = subprocess.run([sys.executable, str(REPO / "scripts" / "coverage"), str(d), "--list", "15"],
                       capture_output=True, text=True)
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
