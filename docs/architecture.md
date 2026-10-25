# Mythos architecture

Mythos is a Claude Code plugin, not a standalone agent runtime. Claude Code is
the agent loop; Mythos supplies the orchestration (one command, five+ agents),
the scope-aware engine, the Kali toolbox, and the knowledge base.

```
  /cybersecurity <target>
        │
        ▼
  ┌─────────────┐   reads scope.yaml (authorization boundary)
  │ orchestrator│   never touches the target itself
  └─────┬───────┘
        │ delegates, phase by phase, to subagents (model: inherit)
        ▼
  planner ─▶ recon ─▶ scanner ─▶ (browser) ─▶ exploiter ─▶ reporter
        │        │         │          │            │           │
        │        │         │          │            │           └─ report.md (bounty format) / docx handoff
        │        │         │          │            └─ validates candidates with minimal PoC (if allow_exploit)
        │        │         │          └─ Playwright: DOM XSS, auth flows, client-side
        │        │         └─ nuclei, dalfox, sqlmap, native checks, passive checks
        │        └─ fingerprint, subfinder, katana/native crawl, ffuf/native discovery
        └─ phase plan + task tree + reads knowledge/
        │
        ▼ all tool execution flows through
  scripts/mythos ─▶ Kali toolbox container (docker exec) ─▶ tools + engine
        │
        └─ fallback: pure-Python engine on the host (no Docker, no binaries)
```

## Components

- **Command** (`commands/cybersecurity.md`): the single entry point. Parses the
  target, sets up the engagement, states the scope, then runs the phases.
- **Agents** (`agents/*.md`): planner, recon, scanner, browser, exploiter,
  reporter. Each uses `model: inherit`, so the session model
  (`claude-opus-4-6`, `claude-mythos-5-1`, `claude-opus-4-8`) drives them.
- **Engine** (`engine/src/mythos/`): a scope-aware HTTP engine. Modules:
  `scope` (authorization), `http_client` (scope + rate-limit + budget + evidence),
  `recon/` (fingerprint, crawl, discover), `scan/` (quick + advanced + headers +
  idor), `external` (OSS-tool orchestration), `selection` (tool-priority table),
  `state` (coverage matrix + task tree), `oast` (out-of-band listener),
  `findings`, `report`, `orchestrator`, `cli`.
- **Toolbox** (`toolbox/Dockerfile`): Kali image with the web tool belt and the
  engine. Agents run tools inside it via `scripts/mythos` / `docker exec`.
- **Hook** (`hooks/scope-guard.py`): warn-only PreToolUse guard that flags
  commands targeting out-of-scope hosts (block mode via `MYTHOS_SCOPE_ENFORCE`).
- **Knowledge** (`knowledge/`): per-bug-class notes the agents read at runtime.
- **Lab** (`lab/`): the ground-truth vuln app plus Juice Shop / DVWA for testing.
- **Engagements** (`engagements/`): per-target workspaces, git-ignored.

## Two enforcement layers for scope

1. **Engine** — `HttpClient` raises `ScopeViolation` before any request leaves
   the scope, and enforces a request budget and rate limit. Hard, in code.
2. **Hook** — the scope guard inspects Bash/WebFetch commands and warns on
   out-of-scope targets. Warn-only by default (the chosen policy), block-capable.

## Design states ported from prior art

- **Finding closure** (`findings.Finding.status`): candidate → confirmed /
  ruled_out / open_proof_gap. A `certain` finding with evidence auto-confirms.
- **Coverage matrix** (`state.CoverageMatrix`): endpoint × bug-class × status,
  persisted as `coverage.json` so no surface is silently skipped.
- **Task tree** (`state.TaskTree`): typed, revisioned, append-only tasks the
  planner owns.
- **Resilience** (`external._run`): TTL result cache for recon, retry/backoff and
  tool-fallback for transient failures.

## Scan modes

- **quick** — headline classes only (XSS, SQLi, redirect, traversal) + passive.
- **standard** (default) — adds SSTI, CRLF, IDOR, SSRF, GraphQL, JWT.
- **deep** — adds the time-based oracles (command injection, blind SQLi).
