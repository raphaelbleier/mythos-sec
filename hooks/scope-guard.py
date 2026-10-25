#!/usr/bin/env python3
"""Mythos scope guard — PreToolUse hook (warn-only by default).

Reads the Claude Code hook event on stdin. For Bash/tool calls it extracts the
hosts and URLs the command targets and checks them against the active
engagement scope. If a target is out of scope it prints a prominent warning
but does NOT block (the user chose warn-only). Set MYTHOS_SCOPE_ENFORCE=block
to turn it into a hard block instead.

Finding the active scope, in order:
  1. $MYTHOS_SCOPE                       (explicit path)
  2. the newest engagements/*/scope.yaml under the project
  3. no scope -> stay silent (nothing to check against)

This is a safety net, not the primary control: the engine's HttpClient enforces
scope itself, independently of this hook.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

# hosts we never warn about (local testing, the toolbox, loopback)
SAFE_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1",
              "mythos-toolbox", "host.docker.internal"}

URL_RE = re.compile(r"https?://([a-zA-Z0-9.\-]+)")
# bare host/IP after a flag commonly used by pentest tools
FLAG_RE = re.compile(r"(?:-u|-h|-d|-t|--url|--host|--target|--domain)\s+"
                     r"(?:https?://)?([a-zA-Z0-9.\-]+)")
HOSTLIKE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[a-z0-9.\-]+\.[a-z]{2,}$", re.I)


def load_scope():
    try:
        import yaml  # type: ignore
    except Exception:
        yaml = None
    path = os.environ.get("MYTHOS_SCOPE")
    scope_file = Path(path) if path else _newest_scope()
    if not scope_file or not scope_file.exists():
        return None
    text = scope_file.read_text(encoding="utf-8", errors="replace")
    if yaml:
        try:
            data = yaml.safe_load(text) or {}
            return (scope_file, data.get("in_scope") or [],
                    data.get("out_of_scope") or [])
        except Exception:
            pass
    # minimal fallback parse without yaml
    return (scope_file, _crude_list(text, "in_scope"),
            _crude_list(text, "out_of_scope"))


def _newest_scope():
    root = Path(os.environ.get("CLAUDE_PROJECT_DIR", "."))
    candidates = list(root.glob("engagements/*/scope.yaml"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _crude_list(text: str, key: str):
    out, grab = [], False
    for line in text.splitlines():
        if line.strip().startswith(key + ":"):
            grab = True
            continue
        if grab:
            m = re.match(r"\s*-\s*['\"]?([^'\"]+)['\"]?\s*$", line)
            if m:
                out.append(m.group(1).strip())
            elif line.strip() and not line.startswith((" ", "\t", "-")):
                break
    return out


def _match(host: str, pattern: str) -> bool:
    import fnmatch
    import ipaddress
    host, pattern = host.lower().strip(), pattern.lower().strip()
    try:
        net = ipaddress.ip_network(pattern, strict=False)
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    except ValueError:
        pass
    return fnmatch.fnmatch(host, pattern) or host == pattern


def in_scope(host: str, in_list, out_list) -> bool:
    if any(_match(host, p) for p in out_list):
        return False
    return any(_match(host, p) for p in in_list)


def extract_hosts(command: str) -> set[str]:
    hosts = set(URL_RE.findall(command))
    hosts |= set(FLAG_RE.findall(command))
    return {h for h in hosts if h and h not in SAFE_HOSTS and HOSTLIKE.match(h)}


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except Exception:
        return 0
    tool = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}
    command = tool_input.get("command") or tool_input.get("url") or ""
    if not command:
        return 0

    loaded = load_scope()
    if not loaded:
        return 0  # no active engagement scope; nothing to check
    scope_file, in_list, out_list = loaded
    if not in_list:
        return 0

    hosts = extract_hosts(str(command))
    offenders = [h for h in hosts if not in_scope(h, in_list, out_list)]
    if not offenders:
        return 0

    msg = ("⚠️  MYTHOS SCOPE GUARD: this command targets host(s) that are "
           f"OUT OF SCOPE: {', '.join(sorted(offenders))}\n"
           f"    Active scope: {scope_file}\n"
           f"    In-scope: {', '.join(in_list)}\n"
           "    Only test what the engagement authorizes.")

    if os.environ.get("MYTHOS_SCOPE_ENFORCE") == "block":
        # exit code 2 blocks the tool call and feeds stderr back to Claude
        print(msg, file=sys.stderr)
        return 2
    # warn-only: surface the warning without blocking
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": msg,
        }
    }))
    print(msg, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
