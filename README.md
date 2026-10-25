<p align="center">
  <img src="docs/assets/logo.svg" alt="Mythos" width="420">
</p>

<p align="center">
  <b>Mythos</b> — a skill-driven web red-team framework for Claude Code, for authorized pentesting and bug bounty.
</p>

<p align="center">
  <i>Point <code>/cybersecurity</code> at a target you're allowed to test. Claude Code <b>is</b> the agent: it reasons like a pentester and drives real security tools in a Kali toolbox to find — and prove — web vulnerabilities.</i>
</p>

---

> **For authorized testing only** — bug-bounty programs in scope, systems you own,
> or lab targets. Scope is a hard boundary, stated up front and watched by a hook.

## What it is

Mythos is in the spirit of CAI / Strix / HexStrike / PentestGPT, but built the
way Claude Code works best: **skill-driven, no external API key, no second LLM
runtime.** Claude Code is the agent loop. Mythos supplies the methodology
(skills), the orchestration (one command, six sub-agents), a real Kali tool
belt (Docker), and a knowledge base.

- **`/cybersecurity` command** — the orchestrator. Sets up a scoped engagement,
  then runs the phases: recon → scan → exploit → report.
- **Phase skills** (`skills/`) — the playbooks Claude follows, each naming the
  exact tools and techniques: `engagement-setup`, `recon`, `web-scan`,
  `exploit`, `report`, `toolbox`.
- **Sub-agents** (`agents/`) — planner, recon, scanner, browser, exploiter,
  reporter. Each uses `model: inherit`, so your session model drives them.
- **Kali toolbox** (Docker) — Claude runs nuclei, sqlmap, dalfox, ffuf, katana,
  subfinder, httpx, nikto, commix, interactsh, jwt_tool and more inside the
  `mythos-toolbox` container via a thin shim. No API key, no Python engine.

## Architecture

![Mythos architecture](docs/assets/architecture.svg)

(Source: `docs/assets/architecture.dot` — `dot -Tsvg` renders the diagram.)

## Quick start

```bash
# install the plugin
/plugin marketplace add /path/to/mythos-sec
/plugin install mythos-sec

# build + start the Kali toolbox (first run takes a few minutes)
scripts/mythos up
scripts/mythos tools        # sanity-check the tool belt

# run an engagement against an AUTHORIZED target
/cybersecurity https://target.example
```

Agents use `model: inherit`; pick per engagement with
`/model claude-opus-4-6 | claude-mythos-5-1 | claude-opus-4-8`.

## Running tools (the toolbox)

Everything runs in the `mythos-toolbox` Kali container via `scripts/mythos`:

```bash
scripts/mythos up                      # build (first run) + start the container
scripts/mythos <tool> [args]           # run one tool,  e.g. scripts/mythos nuclei -u URL
scripts/mythos sh '<pipeline>'         # run a shell pipeline in the toolbox
scripts/mythos down                    # stop + remove the container
```

The repo is mounted at `/repo`, so output lands under `engagements/`. A local
lab target on `localhost:PORT` is reached as `http://host.docker.internal:PORT`.

`toolbox/Dockerfile` builds the Kali image: nuclei, dalfox, sqlmap, ffuf,
katana, subfinder, httpx, nmap, nikto, whatweb, wafw00f, arjun, commix,
jwt_tool, interactsh-client, gf/qsreplace/gau, plus headless Chromium for
DOM work. A tool missing from a given Kali snapshot is skipped, never fatal.

## Capabilities

Reflected & DOM XSS, SQLi (error + blind, via sqlmap), SSTI → RCE, OS command
injection (reflected + blind/OOB), SSRF (out-of-band via interactsh), path
traversal / LFI, open redirect, CRLF, IDOR + two-account BOLA, CORS, JWT
weaknesses, GraphQL introspection, API excessive-data-exposure, sensitive-file
exposure, security headers/cookies; authenticated flows (cookie/bearer, and
Playwright for SPAs); OpenAPI/GraphQL import; CVE lookups; nuclei templated
scanning.

## Scope & safety

- Scope is stated up front and watched by a warn-only `PreToolUse` hook
  (`hooks/scope-guard.py`; set `MYTHOS_SCOPE_ENFORCE=block` to hard-block
  out-of-scope hosts). The agent must honor `scope.yaml` in every tool call.
- Non-destructive by default; exploitation only when `scope.rules.allow_exploit`
  is set; proofs are minimal (no data dumps, no DoS, no brute-force).
- Engagement data lives under `engagements/` and is git-ignored.

## Testing

Repeatable regression suite — drives the toolbox against the ground-truth app
and asserts each class is found (plus a no-false-positive control and the
scope-guard hook):

```bash
scripts/selftest.sh        # 10/10: 7 classes + FP control + 2 scope-guard checks
```

Validated end-to-end against the bundled ground-truth app (`lab/vulnapp`,
`http://localhost:5001`) — every expected class confirmed with real tool output
through the toolbox:

| Class              | Check                                  | Tool        |
| ------------------ | -------------------------------------- | ----------- |
| reflected XSS      | `/search?q=` unencoded reflection      | curl/dalfox |
| SQLi               | `/user?id=` boolean-blind, SQLite      | sqlmap      |
| open redirect      | `/go?next=` → external `Location`      | curl        |
| path traversal     | `/download?file=../../etc/passwd`      | curl        |
| CORS               | `/api/data` reflects attacker `Origin` | curl        |
| sensitive exposure | `/.env` → 200                          | httpx       |
| cookie flags       | `/profile` session cookie              | passive     |

Live benchmark on a real modern app — **OWASP Juice Shop** (Angular SPA + REST):
the full flow surfaced 6 vulnerability classes, 5 confirmed unauthenticated with
tool evidence (critical UNION SQLi dumping the Users table, `/ftp` disclosure,
poison-null-byte filter bypass, open-redirect allowlist bypass, config leak),
one DOM-XSS candidate flagged for the browser agent. See
`docs/poster/benchmark-skill-driven.md`.

Hard-target benchmark (`docs/poster/benchmark-hard-targets.md`) — classes
experienced testers miss, across stacks:

- **DVGA (GraphQL)** — unauthenticated **RCE** chained from introspection →
  `importPaste` SSRF → OS command injection (read `/etc/passwd`); private-paste
  access; introspection disclosure.
- **VAmPI (REST API)** — critical `_debug` plaintext-password dump; a BOLA was
  **tested and disproven** by impact verification (reported as not-vulnerable,
  not claimed).

More vulnerable targets for practice are in `lab/docker-compose.yml`: OWASP
Juice Shop, DVWA, VAmPI, DVGA.

```bash
docker compose -f lab/docker-compose.yml up -d        # start the lab
```

## Layout

```
commands/   /cybersecurity orchestrator
agents/     planner · recon · scanner · browser · exploiter · reporter
skills/     engagement-setup · recon · web-scan · exploit · report · toolbox
hooks/      scope-guard PreToolUse hook (authorization safety net)
toolbox/    Kali toolbox Dockerfile (the tool belt)
lab/        deliberately vulnerable targets for local testing
scripts/    mythos — the toolbox shim
knowledge/  runtime technique knowledge base
docs/       architecture, research, plans, poster evidence
```

## License

MIT. See `LICENSE`. Built by raphaelbleier for Security Engineering research
into AI pentest agents.
