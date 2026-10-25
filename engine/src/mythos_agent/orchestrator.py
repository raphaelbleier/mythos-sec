"""Multi-agent orchestration.

A root coordinator that does not touch the target itself; it spawns several
focused sub-agents in parallel (threads), each its own ReAct loop with a role,
then merges their findings — in the spirit of CAI's run_parallel_specialists
and Strix's agent graph. Parallelism is I/O-bound (each sub-agent blocks on its
LLM backend + HTTP), so threads give real wall-clock speedup.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from mythos.findings import FindingStore
from mythos.report import render_markdown
from mythos.scope import Scope

from .agent import run_agent

ROLES = {
    "recon": "You are the RECON specialist. Map the full attack surface only: "
             "fingerprint, crawl (SPA/JS), import any OpenAPI spec, discover "
             "sensitive paths, list endpoints. Record exposures (sensitive files, "
             "headers, cookies). Do NOT run heavy injection — hand that to others.",
    "injection": "You are the INJECTION specialist. Crawl briefly, then call "
                 "scan_all once and follow up with targeted `check`/`run_tool` for "
                 "SQLi, XSS, SSTI, command injection, path traversal, open redirect "
                 "on every parameterized endpoint. Record confirmed findings.",
    "api_auth": "You are the API/AUTH specialist. Focus on API and authorization: "
                "OpenAPI endpoints, JWT weaknesses, CORS, API excessive-data-exposure, "
                "and BOLA (two-account if scope.identities is set). Record findings.",
}


@dataclass
class SwarmResult:
    target: str
    store: FindingStore
    per_role: dict = field(default_factory=dict)


def run_orchestrated(target: str, scope: Scope, *, roles: list[str] | None = None,
                     backend_name: str = "claude-cli", model: str = "claude-opus-4-8",
                     max_steps: int = 14, proxy: str | None = None,
                     workdir: Path | None = None, log=print) -> SwarmResult:
    roles = roles or list(ROLES)
    log(f"[swarm] spawning {len(roles)} parallel sub-agents: {roles}")
    merged = FindingStore()
    per_role: dict = {}

    def _one(role: str):
        res = run_agent(target, scope, backend_name=backend_name, model=model,
                        max_steps=max_steps, proxy=proxy,
                        objective=ROLES.get(role, role),
                        log=lambda *a: log(f"[{role}]", *a))
        return role, res

    with ThreadPoolExecutor(max_workers=min(len(roles), 4)) as ex:
        futs = [ex.submit(_one, r) for r in roles]
        for fut in as_completed(futs):
            try:
                role, res = fut.result()
            except Exception as e:
                log(f"[swarm] a sub-agent failed: {e}")
                continue
            n = 0
            for f in res.store.findings:
                if merged.add(f):
                    n += 1
            per_role[role] = {"steps": res.steps, "findings": len(res.store),
                              "merged_new": n, "summary": res.summary[:300]}
            log(f"[swarm] {role} done: {len(res.store)} findings (+{n} new)")

    if workdir:
        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        (workdir / "swarm.json").write_text(json.dumps(
            {"target": target, "per_role": per_role,
             "findings": [f.to_dict() for f in merged.findings]}, indent=2), encoding="utf-8")
        (workdir / "report.md").write_text(render_markdown(target, merged), encoding="utf-8")
    return SwarmResult(target=target, store=merged, per_role=per_role)
