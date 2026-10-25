"""The Mythos agent ReAct loop.

Drives an LLM through: observe -> decide (one JSON action) -> execute tool ->
observe -> ... -> finish. The LLM chooses tools from the registry; the loop
executes them against the scope-aware engine and feeds observations back.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from mythos.http_client import HttpClient
from mythos.report import render_markdown
from mythos.scope import Scope

from .llm import get_backend
from .prompts import SYSTEM, render_prompt
from .tools import AgentState, registry

_JSON = re.compile(r"\{.*\}", re.S)


def _parse_action(text: str) -> dict | None:
    # take the last balanced-looking JSON object in the reply
    candidates = _JSON.findall(text.strip())
    for cand in ([text.strip()] + candidates[::-1]):
        try:
            obj = json.loads(cand)
            if isinstance(obj, dict) and ("tool" in obj or "finish" in obj):
                return obj
        except json.JSONDecodeError:
            continue
    # last resort: first {...} to last }
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    return None


@dataclass
class AgentResult:
    target: str
    steps: int
    summary: str
    transcript: list[dict] = field(default_factory=list)
    store: object = None


def run_agent(target: str, scope: Scope, *, backend_name: str = "claude-cli",
              model: str = "claude-opus-4-8", max_steps: int = 25,
              proxy: str | None = None, objective: str = "",
              workdir: Path | None = None, log=print) -> AgentResult:
    client = HttpClient(scope=scope, proxy=proxy)
    state = AgentState(target=target, client=client)
    tools = registry()
    backend = get_backend(backend_name, model)
    log(f"[agent] backend={backend.name} model={model} target={target}")

    scope_desc = (f"in_scope={scope.in_scope} exploit_allowed={scope.rules.allow_exploit} "
                  f"rate={scope.rules.rate_limit_rps}rps")
    transcript: list[dict] = []
    summary = ""
    step = 0
    while step < max_steps:
        step += 1
        prompt = render_prompt(target, scope_desc, tools, transcript, step, max_steps,
                               objective=objective)
        try:
            reply = backend.complete(SYSTEM, prompt)
        except Exception as e:
            log(f"[agent] LLM error: {e}")
            break
        action = _parse_action(reply)
        if not action:
            transcript.append({"action": "(unparseable reply)",
                               "observation": "Your reply was not valid JSON. "
                               "Output exactly one JSON action object."})
            log(f"[agent] step {step}: unparseable reply")
            continue
        if action.get("finish"):
            summary = action.get("summary", "")
            log(f"[agent] step {step}: finish")
            break
        tool_name = action.get("tool", "")
        args = action.get("args") or {}
        thought = (action.get("thought") or "")[:160]
        log(f"[agent] step {step}: {tool_name} {json.dumps(args)[:120]}  // {thought}")
        tool = tools.get(tool_name)
        if not tool:
            obs = f"unknown tool {tool_name!r}. Valid: {', '.join(tools)}"
        else:
            try:
                obs = tool.run(state, args)
            except Exception as e:
                obs = f"tool raised: {e}"
        transcript.append({"action": json.dumps({"tool": tool_name, "args": args}),
                           "observation": obs})

    if workdir:
        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        data = {"target": target, "summary": summary, "steps": step,
                "findings": [f.to_dict() for f in state.store.findings],
                "transcript": transcript}
        (workdir / "agent.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
        (workdir / "report.md").write_text(
            render_markdown(target, state.store), encoding="utf-8")
    return AgentResult(target=target, steps=step, summary=summary,
                       transcript=transcript, store=state.store)
