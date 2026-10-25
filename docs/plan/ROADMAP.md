# Mythos — Agent v2 Roadmap

Status of the LLM-driven agent runtime (`mythos_agent`) and the capabilities
requested for parity with / beyond CAI, Strix, HexStrike, PentestGPT.

Legend: ✅ done · 🚧 in this iteration · ⏳ planned

## Delivered in v1

- ✅ Standalone LLM agent (`mythos-agent`), ReAct loop, pluggable LLM backend
  (`claude` CLI with no API key, or Anthropic API).
- ✅ Tool registry over the engine: fingerprint, crawl, discover, http_request,
  per-class `check`, `passive_checks`, `scan_all`, `run_tool`, `record_finding`.
- ✅ Scope-gated execution; demonstrated on live ginandjuice.shop (found the
  `/login` reflected-XSS autonomously).

## This iteration (Agent v2)

- 🚧 **Toolbox tool proxy** — the agent runs Kali tools (nuclei/sqlmap/dalfox/
  ffuf/nikto) even from the host, by proxying tool calls into the running
  `mythos-toolbox` container via `docker exec`. Closes the biggest gap.
- 🚧 **Browser/DOM agent tool** — expose the headless-Chromium DOM-XSS check as
  an agent tool.
- 🚧 **Two-account BOLA agent tool** — the agent drives `scan/bola.py` with two
  identities from `scope.identities`.
- 🚧 **Persistent shared state in the loop** — wire the coverage matrix and a
  task-tree/notes store into the agent so it tracks what is tested across steps,
  not just the transcript.
- 🚧 **Multi-agent / parallelism** — an orchestrator that spawns parallel
  sub-agents (recon, per-area scanners, per-finding validators), in the spirit
  of CAI's `run_parallel_specialists` and Strix's agent graph.
- 🚧 **CVE intelligence (NVD)** — a tool that queries the NVD API for the
  detected technologies/versions (HexStrike-style).
- 🚧 **Proxy integration** — route all agent traffic through an upstream proxy
  (Burp/Caido/ZAP) via `scope`/CLI, for evidence capture and manual pivoting.

## Backlog (post-v2)

- ⏳ Deterministic PoC replay before a finding is accepted (Strix closure model).
- ⏳ Caido/ZAP request-id evidence linking.
- ⏳ Richer business-logic reasoning (mass assignment chains, race conditions).
- ⏳ GHCR-published toolbox image for one-pull setup.

## Design references

See `docs/research/frameworks-analysis.md` for the source analysis that drives
these choices, and `docs/plan/agent-architecture.md` for the v2 design.
