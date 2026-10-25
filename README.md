<p align="center">
  <img src="docs/assets/logo.svg" alt="Mythos" width="420">
</p>

<p align="center">
  <b>Mythos</b> — a skill-driven web red-team framework for Claude Code, for authorized pentesting and bug bounty.
</p>

<p align="center">
  <i>Point <code>/cybersecurity</code> at a target you're allowed to test. Claude Code <b>is</b> the agent: it reasons like a pentester and drives real security tools in a Kali toolbox to find — and prove — web vulnerabilities. No external API key.</i>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#benchmark-results">Benchmarks</a> ·
  <a href="#scope--safety">Safety</a>
</p>

---

> **For authorized testing only** — bug-bounty programs in scope, systems you
> own, or lab targets. Scope is a hard boundary, stated up front and watched by a
> hook. Never point it at a host you are not permitted to test.

## What it is

Mythos is in the spirit of CAI / Strix / HexStrike / PentestGPT, but built the
way Claude Code works best: **skill-driven, no external API key, no second LLM
runtime.** Claude Code is the agent loop. Mythos supplies the methodology
(skills), the orchestration (one command, six sub-agents), a real Kali tool belt
(Docker), a per-bug-class knowledge base, and a scope safety net.

- **`/cybersecurity` command** — the orchestrator. Sets up a scoped engagement,
  then runs the phases: recon → scan → exploit → report.
- **Phase skills** — the playbooks Claude follows, each naming the exact tools
  and techniques: `engagement-setup`, `recon`, `web-scan`, `exploit`, `report`,
  `toolbox`, plus `research-ingest` and `cve-deep-dive`.
- **Sub-agents** — planner, recon, scanner, browser, exploiter, reporter. Each
  uses `model: inherit`, so your session model drives them.
- **Kali toolbox** (Docker) — Claude runs nuclei, sqlmap, dalfox, ffuf, katana,
  subfinder, httpx, nikto, commix, interactsh, jwt_tool and more inside the
  `mythos-toolbox` container via a thin shim, plus headless Chromium for the
  browser agent.
- **Knowledge base** (`knowledge/`) — per-class confirmation playbooks the
  agents read at runtime to cut false positives.

## Architecture

![Mythos architecture](docs/assets/architecture.svg)

Claude Code is the agent; skills are the playbooks; the shim runs real tools in
the Kali container against the target; the scope-guard hook watches every
command. (Source: `docs/assets/architecture.dot` — `dot -Tsvg` renders it.)
Full write-up: [`docs/architecture.md`](docs/architecture.md).

## Install

**Prerequisites**

- [Claude Code](https://docs.claude.com/en/docs/claude-code) (you are the agent;
  no API key needed).
- **Docker** — Docker Desktop with WSL integration on Windows, or the engine on
  Linux/macOS, with your user able to run `docker`.
- `git`. That's it.

**1. Get the plugin**

```bash
git clone https://github.com/raphaelbleier/mythos-sec
```

**2. Add + install it in Claude Code**

```text
/plugin marketplace add /path/to/mythos-sec
/plugin install mythos-sec
```

**3. Build + start the Kali toolbox** (first build takes a few minutes; it is
cached after that)

```bash
cd mythos-sec
scripts/mythos up          # build the image on first run, start the container
scripts/mythos tools       # sanity-check the tool belt (should list ~16 OK)
```

**4. (optional) spin up the practice lab**

```bash
docker compose -f lab/docker-compose.yml up -d        # Juice Shop, DVWA, VAmPI, DVGA, vulnapp
```

**5. Verify the whole flow** end to end:

```bash
scripts/selftest.sh        # 10/10: 7 vuln classes + a no-false-positive control + scope-guard
```

That's the full setup. No API key, no Python environment, no model config.

## Quick start

```text
/cybersecurity https://target.example
```

Mythos sets up `engagements/<target>-<date>/`, writes a `scope.yaml` you confirm,
then runs recon → scan → exploit → report, driving the toolbox throughout, and
writes a bug-bounty-format `report.md`.

Pick the model per engagement with `/model claude-opus-4-6 | claude-mythos-5-1 |
claude-opus-4-8` — every agent inherits it.

Useful sub-commands:

```text
/cybersecurity research CVE-2026-1234     # CVE deep-dive -> knowledge-base note
/cybersecurity research <topic>           # ingest a technique into knowledge/
```

## How it works

Everything runs in the `mythos-toolbox` Kali container via `scripts/mythos`:

```bash
scripts/mythos up                      # build (first run) + start the container
scripts/mythos <tool> [args]           # run one tool,  e.g. scripts/mythos nuclei -u URL
scripts/mythos sh '<pipeline>'         # run a shell pipeline in the toolbox
scripts/mythos tools                   # list the belt + versions
scripts/mythos down                    # stop + remove the container
```

The repo is mounted at `/repo`, so output lands under `engagements/`. A local
lab target on `localhost:PORT` is reached as `http://host.docker.internal:PORT`.
`toolbox/Dockerfile` builds the belt; a tool missing from a given Kali snapshot
is skipped, never fatal.

## Capabilities

Reflected & DOM XSS, SQLi (error + blind + UNION, via sqlmap), **GraphQL-resolver
SQLi**, SSTI → RCE, OS command injection (reflected + blind/OOB), **SSRF (out-of-
band via interactsh)**, path traversal / LFI + filter-evasion, open redirect,
CRLF, IDOR + two-account BOLA, CORS, **JWT forgery / privilege escalation**,
GraphQL introspection + code execution, API excessive-data-exposure,
sensitive-file exposure, verbose-debug disclosure, security headers/cookies;
authenticated flows (cookie/bearer, Playwright for SPAs); OpenAPI/GraphQL
import; CVE triage (KEV/EPSS, patch-diff); nuclei templated scanning.

## Benchmark results

Confirmed, evidence-backed findings across **six targets / five stacks**, run
through the skill-driven toolbox flow (DOM XSS via the Playwright browser agent).
Details: [`docs/poster/benchmark-skill-driven.md`](docs/poster/benchmark-skill-driven.md)
and [`docs/poster/benchmark-hard-targets.md`](docs/poster/benchmark-hard-targets.md).

| Target                  | Stack                        | Headline confirmed findings                                                                                                             |
| ----------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **Self-test** (vulnapp) | Flask                        | 7 classes + no-FP control + scope-guard — **10/10** automated                                                                           |
| **OWASP Juice Shop**    | Node SPA + REST              | UNION SQLi (Users dump), `/ftp` disclosure, poison-null-byte filter bypass, open redirect, config leak, **DOM XSS** (browser-confirmed) |
| **DVGA**                | Python GraphQL               | **unauth RCE** (introspection → SSRF → command injection), broken access control, introspection                                         |
| **VAmPI**               | Python REST                  | `_debug` plaintext-password dump; a BOLA **tested and disproven** (not over-claimed)                                                    |
| **Vuln Bank** (2026)    | Flask + PostgreSQL + GraphQL | `.env` leak → **JWT forge → admin takeover**, GraphQL-resolver SQLi, verbose-debug disclosure                                           |

Two things these show: Mythos **chains** multi-step attacks a scanner won't
(`.env` → forge → admin; introspection → SSRF → RCE), and it **does not
over-claim** — the VAmPI BOLA was disproven by impact verification and reported
as not-vulnerable.

Honest limits: full crAPI's 7-container API-logic chain does not fit a
RAM-limited (~3.7 GB) WSL host, so the heaviest multi-service logic is future
work on a larger host. "Performs on _any_ web app" is not literally provable
without authorized access to each target; the evidence above spans five stacks
and the headline hard classes.

## Scope & safety

- Scope is stated up front and watched by a warn-only `PreToolUse` hook
  (`hooks/scope-guard.py`; set `MYTHOS_SCOPE_ENFORCE=block` to hard-block
  out-of-scope hosts). The agent honors `scope.yaml` in every tool call.
- Non-destructive by default; exploitation only when `scope.rules.allow_exploit`
  is set; proofs are minimal (no data dumps, no DoS, no brute-force).
- Engagement data lives under `engagements/` and is git-ignored.

## Layout

```
commands/   /cybersecurity orchestrator
agents/     planner · recon · scanner · browser · exploiter · reporter
skills/     engagement-setup · recon · web-scan · exploit · report · toolbox
            · research-ingest · cve-deep-dive
hooks/      scope-guard PreToolUse hook (authorization safety net)
toolbox/    Kali toolbox Dockerfile (the tool belt)
lab/        deliberately vulnerable targets for local testing
scripts/    mythos (toolbox shim) · selftest.sh (regression suite)
knowledge/  per-class confirmation playbooks + CVE technique notes
docs/       architecture, research, plans, poster/benchmark evidence
```

## License

MIT. See `LICENSE`. Built by raphaelbleier for Security Engineering research
into AI pentest agents.
