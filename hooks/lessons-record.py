#!/usr/bin/env python3
"""Mythos lessons recorder — Stop hook.

An engagement throws away everything it learned. The next run against a
similar stack starts from the same uniform prior: it will spend the same
minutes on the class that never once confirmed, and reach the class that
confirms four times in five just as late.

This hook closes that loop with the smallest thing that works: at the end of
an engagement it reads the findings the agent wrote and appends one record per
finding to a ledger. `scripts/lessons` reads the ledger back and tells recon
which classes to try first on this fingerprint, and which playbooks have never
confirmed anything and are therefore suspect.

It is a frequency table, not a model. That is deliberate: the output has to be
auditable, and a count of confirmations per class on a given stack is a claim
anyone can check.

What is recorded, and nothing else:

  stack       the fingerprint tokens from recon (framework, server, language)
  class       the vulnerability class, from the finding's front matter
  state       the closure state (validated / unconfirmed / rejected)
  playbook    which knowledge/ note was used, when the finding names one
  target      a salted hash of the host, never the host itself

No URLs, no payloads, no evidence, no hostnames. The ledger outlives the
engagement directory, so it must not carry anything a later reader should not
see. The salt lives beside the ledger and never leaves the operator's machine,
so the hash cannot be reversed to a hostname by someone holding the file.

Default location ~/.mythos/lessons.jsonl, overridable with $MYTHOS_LESSONS.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

FRONT = re.compile(r"^---\s*$")
FIELD = re.compile(r"^([a-z_]+)\s*:\s*(.+?)\s*$")
STATES = {"validated", "reproduced", "candidate", "unconfirmed", "rejected"}

# A finding's `class` is written by the agent, and the agent read the target's
# responses to write it. Storing that string verbatim in a file that steers
# later engagements is a memory-poisoning path, and poisoning an agent's
# retrieved memory is a published attack with measured success rates. So the
# class is only ever recorded when it names a playbook that exists in this
# repository; anything else is recorded as "other" and the raw string is
# discarded rather than kept "just in case".
def known_classes() -> set:
    root = Path(__file__).resolve().parent.parent
    names = {f.stem for f in (root / "knowledge" / "web").glob("*.md")}
    names |= {f.stem for f in (root / "knowledge" / "techniques").glob("*.md")}
    # Aliases the skills use for the same playbook.
    names |= {"idor", "bola", "bfla", "bopla", "sqli", "rce", "lfi", "ssrf",
              "xss", "csrf", "ssti", "xxe", "prompt-injection", "open-redirect",
              "race-condition", "information-disclosure", "secrets-exposure"}
    return {n.lower() for n in names if n and n != "README"}


def ledger_path() -> Path:
    env = os.environ.get("MYTHOS_LESSONS")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".mythos" / "lessons.jsonl"


def _salt(ledger: Path) -> str:
    """A per-operator salt, so a hostname cannot be recovered from the hash."""
    f = ledger.parent / ".salt"
    try:
        if f.exists():
            return f.read_text().strip()
        ledger.parent.mkdir(parents=True, exist_ok=True)
        value = secrets.token_hex(16)
        f.write_text(value)
        try:
            f.chmod(0o600)
        except OSError:
            pass
        return value
    except OSError:
        return ""


def engagement() -> Path | None:
    scope = os.environ.get("MYTHOS_SCOPE")
    if scope and Path(scope).exists():
        return Path(scope).parent
    roots = [Path.cwd() / "engagements",
             Path(os.environ.get("CLAUDE_PROJECT_DIR", ".")) / "engagements"]
    dirs = [d for r in roots for d in r.glob("*") if d.is_dir()]
    return max(dirs, key=lambda d: d.stat().st_mtime) if dirs else None


def front_matter(text: str) -> dict:
    lines = text.splitlines()
    if not lines or not FRONT.match(lines[0]):
        return {}
    out = {}
    for line in lines[1:]:
        if FRONT.match(line):
            break
        m = FIELD.match(line)
        if m:
            out[m.group(1)] = m.group(2).strip().strip("'\"")
    return out


def stack(d: Path) -> list[str]:
    """Fingerprint tokens recon wrote, if it wrote any."""
    for name in ("surface.json", "recon/surface.json", "recon/fingerprint.json"):
        f = d / name
        if not f.exists():
            continue
        try:
            data = json.loads(f.read_text())
        except Exception:
            continue
        tokens = set()
        for key in ("stack", "technologies", "fingerprint", "tech"):
            value = data.get(key)
            if isinstance(value, str):
                tokens.add(value)
            elif isinstance(value, list):
                tokens.update(str(v) for v in value)
            elif isinstance(value, dict):
                tokens.update(f"{k}:{v}" for k, v in value.items())
        if tokens:
            return sorted(t.lower()[:40] for t in tokens if t)[:20]
    return []


def target_hash(d: Path, salt: str) -> str:
    """A stable, non-reversible id for this target, for same-target recall."""
    host = ""
    scope = d / "scope.yaml"
    if scope.exists():
        for line in scope.read_text(errors="replace").splitlines():
            if line.startswith("target:"):
                host = line.split(":", 1)[1].strip().strip("'\"")
                break
    host = host or d.name
    return hashlib.sha256((salt + host).encode()).hexdigest()[:16]


def records(d: Path, salt: str) -> list[dict]:
    findings = sorted((d / "findings").glob("*.md")) if (d / "findings").is_dir() else []
    if not findings:
        return []
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    tokens, thash = stack(d), target_hash(d, salt)
    allowed = known_classes()
    out = []
    for f in findings:
        try:
            fm = front_matter(f.read_text(errors="replace"))
        except OSError:
            continue
        klass = (fm.get("class") or fm.get("vuln_class") or fm.get("category") or "")
        state = (fm.get("state") or fm.get("status") or "").lower()
        if not klass:
            continue
        klass = klass.strip().lower()
        if klass not in allowed:
            klass = "other"
        out.append({
            "ts": now,
            "target": thash,
            "stack": tokens,
            "class": klass[:60],
            "state": (state.split("(")[0].strip()
                      if state.split("(")[0].strip() in STATES else "unknown"),
            "playbook": (fm.get("playbook") or fm.get("knowledge") or "")[:80],
        })
    return out


def main() -> int:
    try:
        d = engagement()
        if d is None:
            return 0
        ledger = ledger_path()
        salt = _salt(ledger)
        rows = records(d, salt)
        if not rows:
            return 0
        # One line per finding, append-only: a corrupted tail costs one
        # engagement's records, never the history.
        ledger.parent.mkdir(parents=True, exist_ok=True)
        marker = d / ".lessons-recorded"
        already = set()
        if marker.exists():
            already = set(marker.read_text().split())
        new = [r for r in rows if f"{r['class']}:{r['state']}" not in already]
        if not new:
            return 0
        with ledger.open("a", encoding="utf-8") as fh:
            for r in new:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
        marker.write_text(" ".join(sorted(
            already | {f"{r['class']}:{r['state']}" for r in new})))
    except Exception:
        # A Stop hook must never break the host. Losing a lesson is cheap.
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
