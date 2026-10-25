# Mythos architecture

Mythos is a Claude Code plugin, not a standalone agent runtime and not a Python
engine. **Claude Code is the agent loop.** Mythos supplies the methodology
(skills), the orchestration (one command, six sub-agents), a real Kali tool belt
(Docker), the scope safety net (a hook), and a knowledge base. There is no
external API key and no second LLM.

```
  /cybersecurity <target>
        │
        ▼
  ┌─────────────┐   reads scope.yaml (authorization boundary)
  │ orchestrator│   never touches the target itself
  └─────┬───────┘
        │ follows the engagement-setup skill, then delegates phase by phase
        ▼
  planner ─▶ recon ─▶ scanner ─▶ (browser) ─▶ exploiter ─▶ reporter
     │         │          │           │            │            │
     │         │          │           │            │            └─ report skill → report.md / docx handoff
     │         │          │           │            └─ exploit skill: minimal PoC (if allow_exploit)
     │         │          │           └─ Playwright MCP: DOM XSS, auth flows, client-side
     │         │          └─ web-scan skill: nuclei, dalfox, sqlmap, manual checks, passive
     │         └─ recon skill: whatweb/httpx, subfinder, katana, arjun, ffuf
     └─ maps phases to skills + reads knowledge/
        │
        ▼ every tool runs through
  scripts/mythos  ──docker exec──▶  mythos-toolbox (Kali) ──scope-gated──▶ target
        │
        └─ scope-guard hook watches every Bash/WebFetch for out-of-scope hosts
```

## Components

- **Command** (`commands/cybersecurity.md`): the single entry point. Parses the
  target, sets up the scoped engagement, states the scope, runs the phases.
- **Skills** (`skills/*/SKILL.md`): the playbooks Claude follows.
  - `engagement-setup` — workspace + `scope.yaml` (authorization boundary).
  - `recon` — attack-surface mapping with real tools.
  - `web-scan` — vulnerability scanning + triage.
  - `exploit` — minimal, non-destructive proof of concept.
  - `report` — bug-bounty-format deliverable.
  - `toolbox` — how to run tools in the Kali container.
- **Agents** (`agents/*.md`): planner, recon, scanner, browser, exploiter,
  reporter. Each uses `model: inherit`, so the session model
  (`claude-opus-4-6`, `claude-mythos-5-1`, `claude-opus-4-8`) drives them. They
  follow the phase skills.
- **Toolbox** (`toolbox/Dockerfile`): a Kali image with the web/API tool belt
  (nuclei, sqlmap, dalfox, ffuf, katana, subfinder, httpx, nikto, commix,
  interactsh-client, jwt_tool, …) plus headless Chromium. Claude runs tools
  inside it via `scripts/mythos` (`docker exec`).
- **Shim** (`scripts/mythos`): thin driver — `up` / `down` / `tools` /
  `run <tool>` / `sh '<cmd>'` / `<tool> …`. Mounts the repo at `/repo` so output
  lands under `engagements/`; maps `host.docker.internal` for local lab targets.
- **Hook** (`hooks/scope-guard.py`): warn-only `PreToolUse` guard that flags
  Bash/WebFetch commands targeting out-of-scope hosts
  (`MYTHOS_SCOPE_ENFORCE=block` to hard-block).
- **Knowledge** (`knowledge/`): per-bug-class notes the agents read at runtime.
- **Lab** (`lab/`): the ground-truth vuln app plus Juice Shop / DVWA / VAmPI.
- **Engagements** (`engagements/`): per-target workspaces, git-ignored.

## Scope enforcement

Scope is the authorization boundary, and with the Python engine gone it rests on
two things working together:

1. **The agent's discipline** — every skill tells Claude to target only in-scope
   hosts, stay under the rate limit, and exploit only when `allow_exploit` is true.
2. **The hook** — `scope-guard.py` inspects every Bash/WebFetch command and warns
   (or blocks) when it targets a host outside `scope.yaml`. This is the automated
   safety net; it is warn-only by default and block-capable.

## Why skill-driven (vs. a Python engine or a second LLM runtime)

- **No API key, no extra runtime.** The agent is Claude Code itself. Nothing to
  provision; anyone with Claude Code and Docker can run it.
- **Real tools, real output.** Findings come from the same tools a human
  pentester uses (nuclei/sqlmap/dalfox/commix/interactsh), not a reimplementation.
- **Transparent and extensible.** A new technique is a few lines in a skill, not
  a code change — the model reads the playbook and adapts to the target.
- **The model is the reasoning.** Filter evasion, chaining, and triage are the
  agent's job; the skills point it at the right tool and the right payload shape.
