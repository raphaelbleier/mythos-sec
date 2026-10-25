"""mythos-agent CLI: run the autonomous LLM pentest agent.

    mythos-agent <target> --scope scope.yaml --model claude-opus-4-8 \
                 --backend claude-cli --workdir engagements/x --max-steps 25
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mythos.scope import Scope

from .agent import run_agent


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="mythos-agent",
                                 description="Autonomous LLM pentest agent (authorized use only)")
    ap.add_argument("target")
    ap.add_argument("--scope", help="scope.yaml (else single-host from target)")
    ap.add_argument("--model", default="claude-opus-4-8")
    ap.add_argument("--backend", default="claude-cli",
                    choices=["claude-cli", "litellm", "anthropic", "auto"],
                    help="claude-cli = no API key (Claude Code auth); litellm = any "
                         "provider via its key or local Ollama")
    ap.add_argument("--max-steps", type=int, default=25, dest="max_steps")
    ap.add_argument("--proxy", help="route all agent HTTP via an upstream proxy "
                    "(Burp/Caido/ZAP), e.g. http://127.0.0.1:8080")
    ap.add_argument("--objective", default="",
                    help="explicit goal, e.g. 'capture the flag (flag{...})' for CTF/benchmark")
    ap.add_argument("--workdir")
    args = ap.parse_args(argv)

    if args.scope:
        scope = Scope.load(args.scope)
    else:
        from urllib.parse import urlparse
        host = urlparse(args.target).hostname or args.target
        scope = Scope.from_dict({"target": args.target, "in_scope": [host]})

    res = run_agent(args.target, scope, backend_name=args.backend, model=args.model,
                    max_steps=args.max_steps, proxy=args.proxy, objective=args.objective,
                    workdir=Path(args.workdir) if args.workdir else None,
                    log=lambda *a: print(*a, file=sys.stderr))
    c = res.store.counts()
    print(f"\n=== Mythos agent done: {res.steps} steps, "
          f"{len(res.store)} findings "
          f"(crit={c['critical']} high={c['high']} med={c['medium']} low={c['low']}) ===")
    print(res.summary[:800])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
