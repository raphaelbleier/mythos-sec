# Mythos — autonomous web red-team framework for Claude Code

Mythos (`mythos-sec`) is a Claude Code plugin for **authorized** web red-teaming
and bug-bounty work. Point `/cybersecurity` at a target you are allowed to test
and it runs recon, scanning, exploitation triage and reporting — through a
scope-aware engine and a Kali toolbox, with the agent loop provided by Claude
Code itself.

> For authorized testing only: bug-bounty programs, systems you own, or lab
> targets. Scope is a hard boundary, enforced in the engine and by a hook.

## Why it exists

A source analysis of four AI pentest frameworks (CAI, Strix, HexStrike,
PentestGPT — see `docs/research/frameworks-analysis.md`) fed a design that takes
the best of each and adds two things none combine: **hard scope enforcement**
(engine + hook) and a **pure-Python engine** that finds the headline web bug
classes with no external tools installed.

## Install (as a Claude Code plugin)

```bash
# from a local clone
/plugin marketplace add /path/to/mythos-sec
/plugin install mythos-sec
# then, in any session:
/cybersecurity https://target.example
```

Model choice: the agents use `model: inherit`. Pick per engagement with
`/model claude-opus-4-6` (fast default), `/model claude-mythos-5-1` (deepest
reasoning) or `/model claude-opus-4-8` (latest).

## How a run goes

1. **Scope** — an engagement workspace and a `scope.yaml` are created; you fill
   in exactly what the program authorizes.
2. **Plan** → **Recon** → **Scan** → **Browser** → **Exploit-triage** →
   **Report**, each a subagent. Exploitation runs only if the scope allows it.
3. **Output** — `report.md` in bug-bounty format (title, severity + CVSS, asset,
   steps, evidence, impact, remediation), plus `findings.json` and
   `coverage.json`. A German lab `.docx` is available via the `security-lab` skill.

## Scan modes

| Mode               | Adds                                                               |
| ------------------ | ------------------------------------------------------------------ |
| quick              | reflected XSS, SQLi, open redirect, path traversal, passive checks |
| standard (default) | + SSTI, CRLF, IDOR, SSRF (OOB), GraphQL, JWT                       |
| deep               | + time-based oracles (OS command injection, blind SQLi)            |

## The engine on its own

The engine runs without Claude Code, in the toolbox or on any host with Python:

```bash
scripts/mythos engage https://target.example \
    --scope engagements/target/scope.yaml --workdir engagements/target --mode deep
scripts/mythos tools            # show which OSS tools are available
scripts/mythos init-scope https://target.example --out scope.yaml
```

`scripts/mythos` runs everything inside the Kali toolbox container (built on
first use from `toolbox/Dockerfile`). Set `MYTHOS_NATIVE=1` to use the host
engine directly (pure-Python, no external tools).

## Toolbox

`toolbox/Dockerfile` builds a Kali image with nuclei, dalfox, sqlmap, ffuf,
katana, subfinder, httpx, naabu, dnsx, nmap, nikto, whatweb, wafw00f, arjun,
jwt_tool, interactsh-client, gau/waybackurls/qsreplace, semgrep, gitleaks and
the Mythos engine. Metasploit is opt-in (`--build-arg INSTALL_METASPLOIT=true`).

## Test lab

```bash
docker compose -f lab/docker-compose.yml up -d   # vulnapp, Juice Shop, DVWA
python scripts/eval/run_eval.py --target http://localhost:5001 --mode deep \
    --ground-truth lab/vulnapp/ground_truth.json,lab/vulnapp/ground_truth_hard.json
```

`lab/vulnapp/` is a labelled ground-truth app (15 planted vulns across 8 classes)
used by the test suite and the evaluation harness. On it the pure-Python engine
scores 15/15 coverage at 0% false positives (see `docs/poster/eval.json`).

## Safety model

- Scope is enforced in the engine (`ScopeViolation` before any out-of-scope
  request) and by a warn-only hook (`hooks/scope-guard.py`; set
  `MYTHOS_SCOPE_ENFORCE=block` to hard-block).
- A per-engagement request budget and requests-per-second ceiling.
- Exploitation is off unless `scope.rules.allow_exploit` is true, and is always
  minimal and non-destructive.
- Engagement data (`engagements/`) is git-ignored and never pushed.

## Layout

```
commands/        /cybersecurity entry point
agents/          planner, recon, scanner, browser, exploiter, reporter
skills/          engagement-setup, research-ingest
hooks/           scope-guard (warn-only PreToolUse)
engine/          the Mythos engine (Python package + tests)
toolbox/         Kali toolbox Dockerfile
lab/             ground-truth vuln app + Juice Shop/DVWA compose
knowledge/       per-bug-class notes the agents read at runtime
scripts/         mythos wrapper + evaluation harness
docs/            research analysis, architecture, poster
engagements/     per-target workspaces (git-ignored)
```

## Tests

```bash
cd engine && pytest            # 30 tests; -m "not slow" to skip time-based
```

## License

MIT. See `LICENSE`.
