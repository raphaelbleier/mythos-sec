<p align="center">
  <img src="docs/assets/logo.svg" alt="Mythos" width="420">
</p>

<p align="center">
  <b>Mythos</b> — an autonomous, LLM-driven web red-team agent for authorized pentesting and bug bounty.
</p>

<p align="center">
  <i>Point it at a target you're allowed to test; an LLM reasons step by step and drives a scope-aware engine plus a Kali toolbox to find — and prove — web vulnerabilities.</i>
</p>

---

> **For authorized testing only** — bug-bounty programs in scope, systems you own,
> or lab targets. Scope is a hard boundary, enforced in the engine and by a hook.

## What it is

Mythos is in the spirit of CAI / Strix / HexStrike / PentestGPT, with two things
those don't combine: it runs **with Claude Code and no API key** (the model
backend is the local `claude` CLI), and it ships a **scope-aware engine** that
works even with zero external tools installed.

- **Autonomous agent** (`mythos-agent`): a ReAct loop where an LLM chooses tools,
  observes results, and plans — like a human pentester.
- **Pluggable model backend:** the `claude` CLI (no API key, uses Claude Code
  auth) · **LiteLLM** (any provider or local Ollama) · the Anthropic API.
- **Claude Code plugin** (`/cybersecurity`): the same capabilities driven by
  Claude Code's own agents.
- **Engine:** recon (fingerprint, SPA/JS crawl, OpenAPI import, content/param
  discovery), a broad vulnerability-check catalog, and OSS-tool orchestration.

## Architecture

![Mythos architecture](docs/assets/architecture.svg)

(Source: `docs/assets/architecture.dot` — `dot -Tsvg` renders the diagram.)

## Quick start — the agent

```bash
# no API key: uses the local `claude` CLI (Claude Code auth), model your choice
mythos-agent https://target.example --scope scope.yaml --model claude-opus-4-8

# any provider via LiteLLM (needs that provider's key, or local Ollama = no key)
mythos-agent https://target.example --backend litellm --model gpt-4o
mythos-agent https://target.example --backend litellm --model ollama/llama3

# route all traffic through Burp/Caido/ZAP
mythos-agent https://target.example --proxy http://127.0.0.1:8080
```

The agent's tools: `fingerprint`, `crawl`, `discover`, `http_request`, `check`
(per class), `scan_all` (exhaustive sweep), `passive_checks`, `run_tool`
(nuclei/sqlmap/dalfox — local **or via the toolbox container**), `browser_dom_xss`
(headless Chromium), `bola` (two-account), `cve_lookup` (NVD), `record_finding`.

## Quick start — the Claude Code plugin

```bash
/plugin marketplace add /path/to/mythos-sec
/plugin install mythos-sec
/cybersecurity https://target.example
```

Agents use `model: inherit`; pick per engagement with `/model claude-opus-4-6 | claude-mythos-5-1 | claude-opus-4-8`.

## Toolbox (Kali) and the proxy

`toolbox/Dockerfile` builds a Kali image with nuclei, dalfox, sqlmap, ffuf,
katana, subfinder, httpx, nmap, nikto, arjun, jwt_tool, interactsh and more,
plus headless Chromium and the Mythos engine. The agent can run from the **host
with no Kali tools installed** — tool calls are proxied into the running
`mythos-toolbox` container via `docker exec`.

```bash
scripts/mythos engage https://target --scope scope.yaml --workdir engagements/t
```

## Capabilities

Injection (query/form/JSON-body/path), reflected & DOM XSS, SSTI, OS command
injection (time-based), SQLi (error + blind), SSRF (out-of-band), CRLF, path
traversal, open redirect, IDOR + two-account BOLA, CORS, JWT, GraphQL, API
excessive-data-exposure, sensitive-file exposure, security headers/cookies;
authenticated scanning (cookie/bearer); OpenAPI import; CVE intelligence (NVD).

## Scope & safety

- Enforced in the engine (`ScopeViolation` before any out-of-scope request) and
  by a warn-only PreToolUse hook (`MYTHOS_SCOPE_ENFORCE=block` to hard-block).
- Per-engagement request budget and rate limit; non-destructive by default;
  exploitation only when `scope.rules.allow_exploit` is set.
- Engagement data lives under `engagements/` and is git-ignored.

## Testing & benchmarks

```bash
cd engine && pytest                                   # 44 tests
python scripts/eval/run_eval.py --target <lab> --mode deep ...   # coverage/FP on ground truth
python scripts/eval/xbow_bench.py <XBOW challenge dir> ...        # XBOW benchmark
```

- Ground-truth app: **18/18 vulnerability classes, 0 false positives** in one deep run.
- Real third-party targets: OWASP Juice Shop, DVWA (authenticated), VAmPI,
  crAPI (confirmed vehicle BOLA across two accounts), PortSwigger ginandjuice.shop.
- Benchmarked against **XBOW validation benchmarks** (see `docs/plan/` and
  `docs/poster/`).

## Layout

```
commands/  agents/  skills/  hooks/      Claude Code plugin surface
engine/src/mythos/                       scope-aware engine (+ tests)
engine/src/mythos_agent/                 autonomous LLM agent runtime
toolbox/   lab/                          Kali toolbox + vulnerable test lab
scripts/   scripts/eval/                 mythos wrapper + eval/benchmark harnesses
knowledge/ docs/                         runtime knowledge, research, plans, evidence
```

## License

MIT. See `LICENSE`. Built for Security Engineering research into AI pentest agents.
