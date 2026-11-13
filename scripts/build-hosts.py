#!/usr/bin/env python3
"""Render the Claude Code host files from the canonical OpenCode sources.

OpenCode-first: `.opencode/agent/*.md` and `.opencode/command/*.md` are the one
source of truth. This script generates the Claude Code plugin files from them:

  .opencode/agent/<name>.md   (mode: subagent)  ->  agents/<name>.md
  .opencode/command/<cmd>.md  (+ its agent body) ->  commands/<cmd>.md

Claude frontmatter: `model: inherit`, `tools:` derived from the OpenCode
`permission:` map (bash -> Bash, edit -> Write, webfetch -> WebFetch; Read,
Grep, Glob always). A command's Claude body is the command template followed
by the prompt of the agent it names (the orchestrator).

  python3 scripts/build-hosts.py          # write the generated files
  python3 scripts/build-hosts.py --check  # exit 1 if any generated file drifted

Stdlib only. The frontmatter parser understands the YAML subset these files
use: `key: value` lines and nested maps by indentation.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OC = ROOT / ".opencode"
NOTE = ("<!-- generated from {src} by scripts/build-hosts.py; "
        "edit the source, not this file -->\n")


def parse(path: Path) -> tuple[dict, str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return {}, text
    head, body = text[4:].split("\n---\n", 1)
    root: dict = {}
    stack = [(-1, root)]  # (indent, map)
    for line in head.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        key, _, value = line.strip().partition(":")
        key, value = key.strip().strip("'\""), value.strip().strip("'\"")
        while stack[-1][0] >= indent:
            stack.pop()
        if value:
            stack[-1][1][key] = value
        else:
            stack[-1][1][key] = child = {}
            stack.append((indent, child))
    return root, body


def allowed(perm: dict, key: str) -> bool:
    v = perm.get(key, "allow")
    if isinstance(v, dict):  # pattern map: allowed unless everything is denied
        return any(x != "deny" for x in v.values())
    return v != "deny"


def claude_tools(perm: dict) -> str:
    tools = ["Read"]
    if allowed(perm, "bash"):
        tools.append("Bash")
    tools += ["Grep", "Glob"]
    if allowed(perm, "edit"):
        tools.append("Write")
    if allowed(perm, "webfetch"):
        tools.append("WebFetch")
    return ", ".join(tools)


def need(fm: dict, key: str, src: Path):
    if key not in fm:
        sys.exit(f"build-hosts: {src.relative_to(ROOT)}: missing frontmatter key '{key}'")
    return fm[key]


def render() -> dict[Path, str]:
    out: dict[Path, str] = {}
    for src in sorted((OC / "agent").glob("*.md")):
        fm, body = parse(src)
        if fm.get("mode") != "subagent":
            continue
        out[ROOT / "agents" / src.name] = (
            "---\n"
            f"name: {src.stem}\n"
            f"description: {need(fm, 'description', src)}\n"
            "model: inherit\n"
            f"tools: {claude_tools(fm.get('permission', {}))}\n"
            "---\n"
            + NOTE.format(src=src.relative_to(ROOT)) + body)
    for src in sorted((OC / "command").glob("*.md")):
        fm, body = parse(src)
        agent_src = OC / "agent" / f"{need(fm, 'agent', src)}.md"
        _, agent_body = parse(agent_src)
        head = f"---\ndescription: {need(fm, 'description', src)}\n"
        if "argument-hint" in fm:
            head += f"argument-hint: {fm['argument-hint']}\n"
        out[ROOT / "commands" / src.name] = (
            head + "---\n"
            + NOTE.format(src=f"{src.relative_to(ROOT)} + "
                              f"{agent_src.relative_to(ROOT)}")
            + body.rstrip("\n") + "\n" + agent_body)
    return out


def main() -> int:
    check = "--check" in sys.argv[1:]
    drift = []
    for path, text in render().items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == text:
            continue
        drift.append(path.relative_to(ROOT))
        if not check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    if check and drift:
        print("out of date (run scripts/build-hosts.py):",
              *map(str, drift), sep="\n  ")
        return 1
    for p in drift:
        print(f"wrote {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
