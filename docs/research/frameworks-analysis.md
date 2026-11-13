# Prior-art analysis: CAI, Strix, HexStrike, PentestGPT

> **Working notes, not documentation.** This file belongs to the research
> trail behind Mythos. It records what was true when it was written and is not
> kept in sync with the code. For maintained documentation see `README.md`,
> `AGENTS.md` and `docs/architecture.md`.

Source analysis of four AI-driven offensive-security frameworks, read from their
repositories in October 2026. These shaped the Mythos design. Each section
states what the project does and what Mythos takes from it.

## aliasrobotics/CAI (archived, v1.1.5)

- **Architecture:** an orchestrator agent is the sole decision-maker; specialists
  (`red_teamer`, `web_pentester`, `bug_bounter`, `retester`, `reporter`,
  `thought` planner, …) run as tools and never take over the session. Tools:
  `run_specialist`, `run_parallel_specialists` (2–4 workers), `run_dual_approach_contest`.
  Handoff "swarm" patterns transfer full history. ReAct loop; bug-bounty adds a
  one-line Decision Log per step.
- **Tools:** thin — mostly a generic shell (`generic_linux_command`, optionally in
  a container) plus a few wrappers (nmap, curl, shodan, a header analyzer,
  `fetch_url`). ffuf/nuclei/sqlmap/gobuster are named in prompts, not wired in.
- **Notable:** layered prompts (global baseline → per-role micro-profile → role
  prompt); per-role output contracts; a falsification mindset in triage; a
  guardrail that treats target HTML/JSON/headers as untrusted data; an evidence
  guard that rejects fabricated artifacts.
- **Mythos takes:** the orchestrator-that-doesn't-touch-the-target pattern, the
  falsifying retester, layered prompts with output contracts, the untrusted-data
  rule, and — crucially — wiring in _real_ tools where CAI only names them.

## usestrix/strix (Apache-2.0)

- **Architecture:** a dynamic parent/child agent tree. The root agent only
  decomposes scope, spawns and aggregates. Every detected vulnerability gets its
  own validation subagent; scanner output is never trusted without a PoC. Runs in
  a Kali Docker sandbox with Caido as the proxy.
- **State:** a shared, amendable threat model; a coverage matrix with required
  evidence; a notes/todo store.
- **Closure discipline:** every candidate ends as `confirmed` (working PoC or
  source→sink trace), `ruled_out` (naming the specific control and its location),
  or `open_proof_gap`. Missing information never counts as proof of safety.
- **Reporting gates:** a finding needs PoC description + PoC script, a computed
  CVSS 3.1, valid CWE/CVE, baseline-vs-exploit request pair, and a confidence
  rationale; LLM dedup; update/withdraw operations.
- **Tools in the image:** httpx, katana, gospider, nuclei, ffuf, dirsearch,
  arjun, wafw00f, subfinder, naabu, nmap, sqlmap, wapiti, jwt_tool,
  interactsh-client, semgrep, bandit, trufflehog, gitleaks, trivy, retire. A
  headless-Chrome `agent-browser`. Per-class vulnerability skills loaded on demand.
- **Mythos takes:** per-finding validation, the three-state closure model, the
  PoC-gated report schema, the coverage matrix, scan modes (quick/standard/deep),
  on-demand per-class knowledge files, and a near-identical tool belt.

## 0x4m4/hexstrike-ai (MIT, v6.0)

- **Architecture:** a FastMCP stdio client exposing ~151 MCP tools to a Flask
  server (`:8888`) that runs the tools via subprocess. The "agents" are
  rule-based Python classes: `IntelligentDecisionEngine` scores tools 0–1 per
  target type (web/api/network/…), `BugBountyWorkflowManager` is a priority table
  (rce 10, sqli 9, ssrf 8, idor 8, …) mapping classes to tools and payloads.
- **Breadth:** ~100+ tool routes spanning recon, web, fuzzing, exploitation,
  passwords, cloud, binary/reversing, forensics, OSINT.
- **Engineering worth copying:** an LRU result cache with per-key TTL; an
  `IntelligentErrorHandler` that classifies errors and maps them to recovery
  actions (retry/backoff, reduced scope, alternative tool, adjust params,
  escalate, degrade, abort); a process manager; CVE intelligence via the NVD API;
  a parameter optimizer keyed on the detected stack.
- **Weaknesses:** static effectiveness scores, a raw `/api/command` shell, regex
  "findings" rather than validated ones, and no scope enforcement.
- **Mythos takes:** the target-type/tech → tool-priority table (transparent and
  editable), the TTL result cache, and the error-type → recovery-action retry
  logic — while adding the scope enforcement and PoC validation HexStrike lacks.

## GreyDGL/PentestGPT

- **Architecture:** the legacy design runs three LLM sessions (reasoning,
  generation, parsing) around a Pentesting Task Tree. The current design is a
  two-role loop (Supervisor picks one task; Executor performs one leased task)
  over a deterministic SQLite memory kernel.
- **State model:** typed tasks `{id, kind, target, objective, done_when,
depends_on, status}` with `kind ∈ DISCOVER/ENUMERATE/TEST/EXPLOIT/VERIFY/
RECOVER`; append-only numbered transitions; one active task at a time; per-kind
  turn budgets; EXPLOIT must cite the newest completed TEST on the same target.
- **Evidence rule:** evidence is a verbatim contiguous quote from a tool receipt;
  summaries and diagnostics are never evidence. "An anomaly is a lead, not proof."
  No speculative backlog.
- **Self-named weakness:** runs lose coverage information and revisit surfaces.
- **Mythos takes:** the typed task tree with revisioned append-only transitions,
  the task-kind boundary, the verbatim-evidence rule, strict JSON schemas with
  validation feedback, and the parser role — and fixes the coverage weakness with
  an explicit coverage matrix.

## What Mythos synthesizes

| Capability                         | CAI       | Strix      | HexStrike | PentestGPT      | Mythos |
| ---------------------------------- | --------- | ---------- | --------- | --------------- | ------ |
| Orchestrator doesn't touch target  | ✓         | ✓          | –         | ✓               | ✓      |
| Per-finding validation / PoC-gated | ✓(triage) | ✓          | –         | ✓(VERIFY)       | ✓      |
| Three-state closure                | partial   | ✓          | –         | partial         | ✓      |
| Coverage matrix                    | –         | ✓          | –         | missing (named) | ✓      |
| Task tree state                    | todo      | notes      | workflows | ✓               | ✓      |
| Target-type/tech tool selection    | –         | –          | ✓         | –               | ✓      |
| Result cache + error recovery      | –         | –          | ✓         | –               | ✓      |
| Hard scope enforcement (code+hook) | prompt    | scope tool | –         | code            | ✓      |
| Broad real tool belt               | –         | ✓          | ✓         | thin            | ✓      |
| Pure-engine fallback (no Docker)   | –         | –          | –         | –               | ✓      |
| Browser (Playwright)               | –         | ✓          | Selenium  | –               | ✓      |

Mythos is the intersection of their strengths plus two things none combine:
hard scope enforcement in both the engine and a hook, and a pure-Python engine
that still finds the headline bug classes with no external tools installed.
