<p align="center">
  <img src="docs/assets/logo.svg" alt="Mythos" width="420">
</p>

<p align="center">
  <b>Mythos</b> — a skill-driven web red-team framework for OpenCode and Claude Code, for authorized pentesting and bug bounty.
</p>

<p align="center">
  <i>Point <code>/cybersecurity</code> at a target you're allowed to test. Your agent host <b>is</b> the agent: it reasons like a pentester and drives real security tools in a Kali toolbox to find — and prove — web vulnerabilities. No API key of its own.</i>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#benchmarks">Benchmarks</a> ·
  <a href="#scope--safety">Safety</a> ·
  <a href="#responsible-use">Responsible use</a>
</p>

---

> **For authorized testing only** — bug-bounty programs in scope, systems you
> own, or lab targets. Scope is a hard boundary, stated up front and watched by a
> hook. Never point it at a host you are not permitted to test.

## What it is

Mythos is in the spirit of CAI / Strix / HexStrike / PentestGPT, but
**skill-driven, with no separate engine and no LLM runtime of its own.** The
agent host (OpenCode first, Claude Code second) is the agent loop. Mythos
supplies the methodology (skills), the orchestration (one orchestrator, six
sub-agents), a Kali tool belt (Docker), a per-bug-class knowledge base, and a
scope guard.

- **`/cybersecurity` command**: the orchestrator. Sets up a scoped engagement,
  then runs recon, scan, exploit, report.
- **Phase skills**: `engagement-setup`, `recon`, `web-scan`, `exploit`,
  `report`, `toolbox`, plus capability skills `auth-session`,
  `business-logic`, `stored-xss-oast`, `deep-server` and the maintenance skills
  `research-ingest` and `cve-deep-dive`. Findings carry a closure state
  (candidate / confirmed / ruled_out / open_proof_gap).
- **Sub-agents**: planner, recon, scanner, browser, exploiter, reporter, using
  the session model.
- **Kali toolbox** (Docker): nuclei, sqlmap, dalfox, ffuf, katana, subfinder,
  httpx, nikto, commix, interactsh, jwt_tool and more, run through
  `scripts/mythos`; headless Chromium for the browser agent.
- **Knowledge base** (`knowledge/`): per-class confirmation playbooks read at
  runtime to cut false positives.
- **One canonical source**: `AGENTS.md`, `.opencode/` and `skills/` are
  hand-edited; `python3 scripts/build-hosts.py` generates the Claude Code files
  (`CLAUDE.md`, `agents/`, `commands/`).

## Architecture

![Mythos architecture](docs/assets/architecture.svg)

The host is the agent; skills are the playbooks; the shim runs real tools in
the Kali container against the target; the scope guard watches bash/webfetch
calls. (Source: `docs/assets/architecture.dot` — `dot -Tsvg` renders it.)
Full write-up: [`docs/architecture.md`](docs/architecture.md).

## Install

**Prerequisites**

- [OpenCode](https://opencode.ai) (1.x >= 1.18.29 or 2.x), primary, or
  [Claude Code](https://docs.claude.com/en/docs/claude-code), secondary.
- A model for the host: any provider the host supports (the repo's
  `opencode.json` has an example Z.ai provider reading `LLM_API_KEY`; replace it
  with your own).
- **Docker**, with your user able to run `docker`. `git`, and Python 3 (stdlib
  only) for the shim.

**1. Get the repo**

```bash
git clone https://github.com/raphaelbleier/mythos-sec
cd mythos-sec
```

**2a. OpenCode (primary)**: nothing to install. Run `opencode` in the repo; it
reads `opencode.json` (default agent `mythos`, `AGENTS.md`, the `skills/` path)
and `.opencode/` (agents, `/cybersecurity` command, scope-guard plugin).
Non-interactive:

```bash
opencode run --agent mythos --auto "https://target.example --scope scope.yaml"
```

**2b. Claude Code (secondary)**: add and install the plugin

```text
/plugin marketplace add /path/to/mythos-sec
/plugin install mythos-sec
```

**3. Toolbox**: `scripts/mythos up` pulls the prebuilt image from GHCR and starts
it (no local build):

```bash
docker pull ghcr.io/raphaelbleier/mythos-toolbox:latest   # optional, `up` does this
scripts/mythos up          # pull (or build) the image, start the container
scripts/mythos tools       # sanity-check the tool belt
```

Pin a tag for reproducibility (`MYTHOS_IMAGE=ghcr.io/raphaelbleier/mythos-toolbox:<tag>`;
tags are `vX.Y.Z`, `X.Y`, `YYYYMMDD`, `sha-...`; the workflow publishes amd64 and
arm64). To build locally instead: `MYTHOS_BUILD=1 scripts/mythos up` (first
build takes minutes). Whether a published tag exists yet depends on the CI run;
check the repository's packages page.

**4. (optional) practice lab**: see [`lab/README.md`](lab/README.md)

```bash
docker compose -f lab/docker-compose.yml up -d
scripts/mythos net mythos-lab     # let the toolbox reach lab targets by service name
```

**5. Verify** end to end:

```bash
scripts/selftest.sh                   # 7 vuln classes + no-false-positive control + scope-guard
scripts/selftest.sh --host opencode   # same checks, scored from the mythos agent's report
```

**Platform notes**

- **Linux**: Docker engine; add your user to the `docker` group.
- **macOS**: Docker Desktop. Local lab targets are reached from the toolbox as
  `http://host.docker.internal:<port>`. Untested by the maintainer.
- **Windows**: Docker Desktop with WSL integration; run the repo and the host
  inside WSL, or use Git Bash (the shim sets `MSYS_NO_PATHCONV` so `/repo` is not
  rewritten). Only the WSL path has been exercised; native Windows is untested.

You need a model for the agent host; Mythos itself needs no extra API key.

## Quick start

```text
/cybersecurity https://target.example
```

Mythos sets up `engagements/<target>-<date>/`, writes a `scope.yaml` you confirm
(or takes yours via `--scope`),
then runs recon → scan → exploit → report, driving the toolbox throughout, and
writes a bug-bounty-format `report.md`.

The model is whatever the host is configured to use (`/model` in Claude Code,
`--model` in `opencode run`); every agent uses it.

The single human gate is the scope confirmation. With `--scope <file>` (also
with `opencode run --auto`) the file is the confirmation and nothing is asked;
after that the engagement runs unattended under hard rules (non-destructive, no
DoS or brute force, minimal PoC, no data dumping).

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
scripts/mythos net <network>           # attach the toolbox to a lab docker network
scripts/mythos down                    # stop + remove the container
```

The repo is mounted at `/repo`, so output lands under `engagements/`. A local
lab target on `localhost:PORT` is reached as `http://host.docker.internal:PORT`.
`toolbox/Dockerfile` (two-stage) builds the belt; a tool missing from a given
Kali snapshot is skipped, never fatal. Every exec is logged to
`engagements/audit.jsonl`.

## Capabilities

Reflected & DOM XSS, SQLi (error + blind + UNION, via sqlmap), **GraphQL-resolver
SQLi**, SSTI → RCE, OS command injection (reflected + blind/OOB), **SSRF (out-of-
band via interactsh)**, path traversal / LFI + filter-evasion, open redirect,
CRLF, IDOR + two-account BOLA, CORS, **JWT forgery / privilege escalation**,
GraphQL introspection + code execution, API excessive-data-exposure,
sensitive-file exposure, verbose-debug disclosure, security headers/cookies;
authenticated flows (cookie/bearer, Playwright for SPAs); OpenAPI/GraphQL
import; CVE triage (KEV/EPSS, patch-diff); nuclei templated scanning.

## Benchmarks

**Controlled evaluation (in progress).** `bench/` runs mythos and a bare-model
control on the XBOW validation-benchmarks with the same model, prompt, budget
and sandbox; per-run random flags; harness-side scoring; Wilson intervals and
paired McNemar tests. Protocol, usage and isolation rules:
[`bench/README.md`](bench/README.md). **Results are pending**; the table to fill
is in [`docs/poster/poster.md`](docs/poster/poster.md). Limits:
[`docs/poster/LIMITATIONS.md`](docs/poster/LIMITATIONS.md).

```bash
python3 bench/xben.py check --out <build_results.tsv>
python3 bench/run.py --frameworks mythos,control --model <id> --sample 30 --seed 1 --runs 3 --dry-run
python3 bench/stats.py <results>/results.jsonl --compare mythos,control
```

**Earlier manual engagements** (single runs, no control arm, from the earlier
skill-driven flow; evidence, not a measured advantage). Details:
[`docs/poster/benchmark-skill-driven.md`](docs/poster/benchmark-skill-driven.md),
[`docs/poster/benchmark-hard-targets.md`](docs/poster/benchmark-hard-targets.md).

| Target                  | Stack                        | Headline confirmed findings                                                                                                             |
| ----------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **Self-test** (vulnapp) | Flask                        | 7 classes + no-FP control + scope-guard — **10/10** automated                                                                           |
| **OWASP Juice Shop**    | Node SPA + REST              | UNION SQLi (Users dump), `/ftp` disclosure, poison-null-byte filter bypass, open redirect, config leak, **DOM XSS** (browser-confirmed) |
| **DVGA**                | Python GraphQL               | **unauth RCE** (introspection → SSRF → command injection), broken access control, introspection                                         |
| **VAmPI**               | Python REST                  | `_debug` plaintext-password dump; a BOLA **tested and disproven** (not over-claimed)                                                    |
| **Vuln Bank** (2026)    | Flask + PostgreSQL + GraphQL | `.env` leak → **JWT forge → admin takeover**, GraphQL-resolver SQLi, verbose-debug disclosure                                           |

Honest limits: full crAPI does not fit a ~3.7 GB host. "Works on any web app"
is not provable without authorized access to each target.

## Scope & safety

- Scope is stated up front and watched by a warn-only scope guard
  (`hooks/scope-guard.py` as a Claude Code `PreToolUse` hook,
  `.opencode/plugin/scope-guard.ts` for OpenCode; set
  `MYTHOS_SCOPE_ENFORCE=block` to hard-block out-of-scope hosts). It is a safety
  net, not a sandbox; coverage inside OpenCode sub-agents is not yet verified.
  The agent honors `scope.yaml` in every tool call.
- Non-destructive by default; exploitation only when `scope.rules.allow_exploit`
  is set; proofs are minimal (no data dumps, no DoS, no brute-force).
- Engagement data lives under `engagements/` and is git-ignored.

## Responsible use

Mythos is offensive security tooling. Use it only against systems you own,
bug-bounty programs within their stated scope, or lab targets, and only with
authorization. You are responsible for compliance with program rules and
applicable law. The scope guard and rate limits reduce risk but do not grant
permission. The software is provided as is, without warranty (MIT).

## Layout

```
AGENTS.md          canonical project instructions (CLAUDE.md imports it)
opencode.json      OpenCode config (default agent, skills path)
.opencode/         canonical agents, /cybersecurity command, scope-guard plugin
commands/ agents/  generated for Claude Code by scripts/build-hosts.py
skills/            engagement-setup · recon · web-scan · exploit · report · toolbox
                   · auth-session · business-logic · stored-xss-oast · deep-server
                   · research-ingest · cve-deep-dive
hooks/             scope-guard (Claude Code PreToolUse hook + shared --check logic)
toolbox/           two-stage Kali toolbox Dockerfile
.github/           toolbox image CI (GHCR, amd64 + arm64)
lab/               vulnerable targets, OAST catcher, admin bot
bench/             XBOW benchmark harness and statistics
scripts/           mythos (toolbox shim) · selftest.sh · build-hosts.py
knowledge/         per-class confirmation playbooks + CVE technique notes
docs/              architecture, research, plan, poster/benchmark evidence
```

## License

MIT. See `LICENSE`. Built by raphaelbleier for Security Engineering research
into AI pentest agents.
