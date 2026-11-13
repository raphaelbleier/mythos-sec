# Mythos architecture

Mythos is a skill-driven framework, not a standalone agent runtime and not a
Python engine. **The agent host is the agent loop**: OpenCode first (1.x >=
1.18.29 and 2.x), Claude Code second. Mythos supplies the methodology
(skills), the orchestration (one orchestrator, six sub-agents), a Kali tool belt
(Docker), a scope guard, and a knowledge base. There is no external API key of
its own and no second LLM; the host's configured model is the model. On
OpenCode, `models.json` may give each agent a different model from that host, so
that cheap phases run cheaply and the validator pass can run on a model that did
not write the finding.

One canonical source feeds both hosts. `AGENTS.md`, `.opencode/agent/`,
`.opencode/command/` and `skills/` are edited by hand; `scripts/build-hosts.py`
generates `CLAUDE.md`, `agents/` and `commands/` for Claude Code
(`--check` exits 1 on drift).

```
  /cybersecurity <target> [--scope scope.yaml]
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
        └─ scope guard watches every Bash/WebFetch for out-of-scope hosts
```

## Components

- **Orchestrator** (`.opencode/agent/mythos.md`, `.opencode/command/cybersecurity.md`;
  generated for Claude Code as `commands/cybersecurity.md`): parses the target,
  sets up the scoped engagement, states the scope, runs the phases.
- **Skills** (`skills/*/SKILL.md`): the playbooks the model follows. OpenCode
  reads them via `opencode.json` (`skills.paths`), Claude Code via the plugin.
  - `engagement-setup`: workspace + `scope.yaml` (authorization boundary).
  - `recon`: attack-surface mapping.
  - `web-scan`: vulnerability scanning and triage.
  - `auth-session`, `business-logic`, `stored-xss-oast`, `deep-server`:
    capability skills for multi-account auth, BOLA / mass assignment / races,
    stored XSS with an out-of-band catcher, and server-side classes. Their
    measured effect is not yet established (see
    [`docs/plan/ROADMAP.md`](plan/ROADMAP.md), phases 3 and 5).
  - `exploit`: minimal, non-destructive proof of concept, with closure states.
  - `report`: bug-bounty-format deliverable; findings carry a closure state.
  - `continuous`: acts on a `scripts/watch` work list for an already-tested
    target: new endpoints and CVEs, replay of stored proofs, fix verification.
  - `toolbox`: how to run tools in the Kali container.
  - `research-ingest`, `cve-deep-dive`: knowledge-base maintenance.
- **Sub-agents** (`.opencode/agent/mythos-*.md`; generated as `agents/*.md`):
  planner, recon, scanner, browser, exploiter, reporter. They follow the phase
  skills and use the session model.
- **Toolbox** (`toolbox/Dockerfile`): two-stage image. Stage 1 compiles pinned Go
  tools, stage 2 is Kali with apt tools plus headless Chromium. Published
  multi-arch (amd64, arm64) as `ghcr.io/raphaelbleier/mythos-toolbox` by
  `.github/workflows/toolbox.yml`; `scripts/mythos up` pulls it, or builds
  locally with `MYTHOS_BUILD=1`.
- **Shim** (`scripts/mythos`): stdlib-only Python driver: `up`, `down`,
- **Watch** (`scripts/watch`): stdlib-only change detector for a tested target.
  Surface drift via `scripts/probe`, new CVEs via `scripts/cvefeed`, finding
  drift via `scripts/findings --diff`. State in `engagements/.watch/`. It applies
  the scope pin and the rate limit to its own requests, since cron has no hook.
  `tools`, `run <tool>`, `sh '<cmd>'`, `net <network>`, `<tool> ...`. Mounts the
  repo at `/repo`, maps `host.docker.internal`, and logs every exec to
  `engagements/audit.jsonl`.
- **Scope guard** (`hooks/scope-guard.py`; Claude Code `PreToolUse` hook, and
  the OpenCode plugin `.opencode/plugin/scope-guard.ts`, which shells out to
  `--check`): flags bash/webfetch calls to hosts outside `scope.yaml`. Warn-only
  by default; `MYTHOS_SCOPE_ENFORCE=ask` refuses and names the reason, `=block`
  refuses outright. Whether the hook also
  fires inside OpenCode sub-agents is a phase-0 verification item in the
  roadmap; it is not claimed here.
- **Knowledge** (`knowledge/`): per-bug-class confirmation playbooks
  (including cache poisoning, mass assignment, race conditions, request
  smuggling) read by the agents at runtime.
- **Lab** (`lab/`): ground-truth vuln app, Juice Shop, DVWA, VAmPI, DVGA, Vuln
  Bank, plus an OAST catcher and an admin bot (see `lab/README.md`).
- **Benchmark harness** (`bench/`): XBOW validation-benchmarks runner, a
  flagless-lab runner (`labs.py`) scoring recall against the documented
  vulnerability lists in `bench/data/ground_truth/`, and the statistics; protocol
  in `bench/README.md`.
- **Engagements** (`engagements/`): per-target workspaces, git-ignored.

## Single human gate

The only stop is the scope confirmation in step 0 of the orchestrator. With
`--scope <file>` (including non-interactive `opencode run --auto`) the file is
the confirmation. After that recon, scan, exploit and report run unattended.
Safety rests on hard rules, not pauses: non-destructive only, no denial of
service or brute force, minimal proof of concept, no data dumping. What cannot
be proven safely is reported as unconfirmed.

## Scope enforcement

Scope is the authorization boundary and rests on two things:

1. **Agent discipline**: every skill says to target only in-scope hosts, stay
   under `rules.rate_limit_rps` / `rules.max_requests`, and exploit only when
   `allow_exploit` is true.
2. **The scope guard**: warn-only by default, block-capable. It is a safety
   net, not a sandbox; a model that ignores a warning is not stopped.
   Benchmark cells additionally get a `scope.yaml` with exactly one host and
   port, and targets are bound to the docker0 gateway only.

## Why skill-driven

- No extra runtime or key of its own: anyone with an agent host and Docker can
  run it.
- Findings come from the tools a human pentester uses (nuclei, sqlmap, dalfox,
  commix, interactsh), not a reimplementation.
- A new technique is a few lines in a skill, not a code change.
- Reasoning (filter evasion, chaining, triage) is the model's job. Whether the
  skills add measurable value over the bare model is exactly what `bench/`
  tests with a bare-model control arm. The results are in: a null on flag-capture
  challenges and one separation on Vuln Bank with the coverage gate, which the
  same gate reversed on DVGA. See the Benchmarks section of `README.md`,
  [`../docs/poster/poster.md`](poster/poster.md) (German) and
  [`poster/LIMITATIONS.md`](poster/LIMITATIONS.md).
