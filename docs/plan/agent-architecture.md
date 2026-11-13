# Mythos Agent v2 — Architecture (SUPERSEDED)

> **Working notes, not documentation.** This file belongs to the research
> trail behind Mythos. It records what was true when it was written and is not
> kept in sync with the code. For maintained documentation see `README.md`,
> `AGENTS.md` and `docs/architecture.md`.

> **Historical.** This documents the earlier standalone Python agent runtime
> (`mythos_agent`) and the scope-aware engine, both since removed. Mythos is now
> skill-driven: Claude Code is the agent and runs real tools in the Kali toolbox.
> See `docs/architecture.md` for the current design. Kept for the research
> write-up / poster history.

How the LLM-driven agent runtime was structured and how v2 features fit in.

## Core loop (v1, unchanged)

```
mythos-agent <target> --scope scope.yaml --model <m> --backend <b>
        │
        ▼
  ┌──────────────┐   system prompt + ReAct protocol
  │  agent loop  │   each step: render transcript -> LLM -> parse ONE JSON action
  └──────┬───────┘
         │ action = {tool, args} | {finish, summary}
         ▼
  ┌──────────────┐   scope-gated execution against the engine
  │ tool registry│   fingerprint · crawl · discover · http_request · check ·
  └──────┬───────┘   scan_all · passive_checks · run_tool · record_finding
         │ observation (text) fed back into the transcript
         ▼
  findings store → agent.json + report.md
```

LLM backend is pluggable (`llm.py`): `claude` CLI (no API key, uses Claude Code
auth) or Anthropic API. The model reasons; the engine executes.

## v2 additions

### 1. Toolbox tool proxy (`external._run`)

When a Kali tool is not on the local PATH, `_run` falls back to executing it
inside the running `mythos-toolbox` container:

```
tool on PATH?  ── yes ─▶ run locally
      │ no
      ▼
docker + mythos-toolbox up?  ── yes ─▶ docker exec mythos-toolbox <tool ...>
      │ no
      ▼
return empty (engine uses native checks)
```

So the host agent gets nuclei/sqlmap/dalfox/ffuf/nikto via the container, with
no Kali tools installed on the host. Controlled by `MYTHOS_TOOLBOX` (container
name, default `mythos-toolbox`) and `MYTHOS_NO_TOOLBOX_PROXY=1` to disable.

### 2. New agent tools

- `browser_dom_xss` → headless-Chromium DOM-XSS (`scan/browser.py`).
- `bola` → two-account cross-access (`scan/bola.py`) using `scope.identities`.
- `cve_lookup` → NVD API query for a product/version (`mythos.intel.nvd`).
- proxy → `scope.proxy` / `--proxy` routes all agent HTTP via Burp/Caido/ZAP.

### 3. Shared state in the loop (`mythos_agent/state`)

A per-engagement `AgentMemory`:

- coverage matrix (`mythos.state.CoverageMatrix`) — endpoint × class × status,
- task tree (`mythos.state.TaskTree`) — typed tasks the agent opens/closes,
- notes — free-form observations.
  Exposed as tools (`note`, `coverage`, `plan_task`) and summarized into each
  prompt, so the agent reasons over durable state, not only the transcript.

### 4. Multi-agent orchestration (`mythos_agent/orchestrator`)

A root agent that never touches the target decomposes the engagement and spawns
parallel sub-agents (threads), each its own ReAct loop with a focused role:

```
          root (plan + aggregate)
         /        |          \
     recon    scan:web     scan:api      (parallel)
                  \          /
              per-finding validators      (parallel, spawned on candidates)
```

Mirrors CAI `run_parallel_specialists` and Strix's agent graph. Shared findings
store + coverage are merged under a lock.

## Safety

Every layer stays scope-gated (engine `HttpClient` + the warn-only hook). The
proxy and toolbox calls inherit the same scope checks. Exploitation tools run
only when `scope.rules.allow_exploit` is set.
