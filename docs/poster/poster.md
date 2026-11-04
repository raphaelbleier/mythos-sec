# Mythos: Does Skill-Driven Scaffolding Improve an LLM Pentest Agent?

Security Engineering, research poster, winter semester 2026/27.

## Problem

AI pentest agents are proliferating (CAI, Strix, HexStrike, PentestGPT,
Shannon). Published scores on the XBOW validation benchmarks (e.g. Strix 100/104,
Shannon 100/104, PentestGPT 90/104) are self-reported, use different models, and
were not independently replicated. They do not show whether the scaffolding or
the model produces the result. Mythos asks a narrower question: with the model
held fixed, what does a skill-driven scaffold add over the bare model?

## Approach

- **Runtime:** the agent host is the agent loop, OpenCode first (1.x >= 1.18.29,
  2.x), Claude Code second. One canonical source (`AGENTS.md`, `.opencode/`,
  `skills/`) is used by both; `scripts/build-hosts.py` generates the Claude Code
  files. No separate engine, no key of Mythos' own.
- **Orchestration:** one orchestrator (`/cybersecurity <target> --scope file`)
  and six sub-agents (planner, recon, scanner, browser, exploiter, reporter)
  following phase skills: engagement-setup, recon, web-scan, exploit, report.
- **Capability skills:** `auth-session` (two accounts), `business-logic` (BOLA,
  mass assignment, races), `stored-xss-oast` (OAST catcher + admin bot),
  `deep-server` (server-side classes). Targets the report identifies as gaps in
  other frameworks; their effect here is to be measured, not assumed.
- **Tools:** a two-stage Kali toolbox image (`ghcr.io/raphaelbleier/mythos-toolbox`,
  amd64 + arm64) driven through a stdlib Python shim. Tools: nuclei, sqlmap,
  dalfox, ffuf, katana, subfinder, httpx, commix, interactsh, jwt_tool, others.
- **Safety:** `scope.yaml` is the authorization boundary; a scope guard (Claude
  Code hook / OpenCode plugin) warns on out-of-scope hosts (block mode
  optional); a single human gate (scope confirmation), then unattended
  non-destructive operation; findings carry closure states
  (candidate / confirmed / ruled_out / open_proof_gap) and need verbatim evidence.
- **Design inputs:** `docs/research/frameworks-analysis.md` (CAI, Strix,
  HexStrike, PentestGPT).

## Evaluation protocol

Harness: `bench/` (stdlib Python), XBOW validation-benchmarks. Full detail in
`bench/README.md`.

- **Arms:** `mythos` (`opencode run --agent mythos --auto`) vs `control`
  (`opencode run --pure --agent build`, empty dir, bash/read only: the bare-model
  control). Strix as a third arm needs its own LLM key (not yet run).
- **Fairness:** the same model id for every arm, recorded with the date; the
  same prompt, wall-clock budget, sandbox and machine. Challenge tags, level and
  description never reach the prompt. Clean HOME and config per cell (no global
  skills, MCP servers or `CLAUDE.md`).
- **Targets:** a seeded random subset of challenges that build. Many upstream
  Dockerfiles need an apt fix (Debian releases moved to `archive.debian.org`);
  the fix is injected without touching the checkout, recorded as `apt_fix`, and
  the build-success list is published.
- **Flag:** a random `FLAG{<64 hex>}` per cell, baked in at build time (the
  upstream default is precomputable). Scoring is harness-side only: `solved` =
  flag in transcript and not `suspect`; `detected` = report names a challenge tag.
- **Isolation:** one compose project per cell, ports rebound to the docker0
  gateway on random host ports, one-host `scope.yaml`, teardown after every cell.
- **Statistics:** Wilson 95% intervals for solve rates, pass@k over repeats,
  paired McNemar test between arms (repeats run-major so a cut sweep stays
  paired). Raw transcripts are hashed (`trace_sha256`).

## Results

**Placeholder: not yet run. Fill from the output of**
`python3 bench/stats.py <results>/results.jsonl --compare mythos,control`
**Do not edit numbers by hand; record the model id, date and sample parameters.**

Run parameters: model = `TBD`, date = `TBD`, challenges = `TBD` (seed `TBD`),
runs per cell = `TBD`, budget = `TBD` s, apt_fix = `TBD`.

| Arm | n cells | solved | solve rate | Wilson 95% CI | pass@k |
|---|---|---|---|---|---|
| control (bare model) | TBD | TBD | TBD | TBD | TBD |
| mythos | TBD | TBD | TBD | TBD | TBD |
| strix (if run) | TBD | TBD | TBD | TBD | TBD |

Paired comparison mythos vs control: discordant pairs b = TBD, c = TBD,
McNemar p = TBD.

Per-class breakdown (stored XSS, auth/BOLA, mass assignment, race, SSTI,
smuggling, deserialization): TBD. Ablation, evidence gating on/off: TBD.

## Earlier, uncontrolled evidence

Single manual engagements through the toolbox flow, no repeats, no control arm.
They show the flow works on real targets, not a measured advantage:
`benchmark-skill-driven.md` (Juice Shop), `benchmark-hard-targets.md` (DVGA
GraphQL chain, VAmPI, Vuln Bank), `benchmark-xbow.md`. A regression self-test
(`scripts/selftest.sh`, 15 checks: the deterministic surface probe, 7 vulnerability classes, a no-false-positive
control, scope-guard) runs on both hosts.

## Contribution

A reproducible, same-model evaluation of scaffolding value, with a bare-model
control, interval estimates and paired tests; an OpenCode-first, single-source
framework usable on both hosts; and explicit coverage of multi-account,
business-logic and stored-XSS/OAST work. Whether the scaffolding helps is the
open result above.

## Limitations

See `LIMITATIONS.md`. Architecture: `docs/architecture.md`.
