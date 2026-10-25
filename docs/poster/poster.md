# Mythos: An Autonomous Web Red-Team Framework for Claude Code

Security Engineering — research poster, winter semester 2026/27.

## Problem

AI pentest agents are proliferating (CAI, Strix, HexStrike, PentestGPT), but
each reinvents an agent runtime, and most lack two things that matter for
_authorized_ bug-bounty work: hard scope enforcement and proof-gated findings.
Mythos asks: can a thin orchestration layer over Claude Code plus mature OSS
tools match their detection while adding safety and reproducibility?

## Approach

- **Runtime:** Claude Code is the agent loop. Mythos adds one command
  (`/cybersecurity <target>`) and six subagents (planner → recon → scanner →
  browser → exploiter → reporter), each inheriting the session model.
- **Engine:** a scope-aware Python engine does recon (fingerprint, crawl,
  discovery) and a catalog of active checks, and orchestrates OSS tools (nuclei,
  dalfox, sqlmap, ffuf, katana, …) in a Kali toolbox container. It falls back to
  a pure-Python path when no tools are installed.
- **Safety:** every request is scope-checked in the engine and by a warn-only
  hook; a request budget and rate limit are enforced; findings carry a closure
  state (candidate / confirmed / ruled_out / open_proof_gap).
- **Design inputs:** ported from a source analysis of the four frameworks (see
  `docs/research/frameworks-analysis.md`): orchestrator-that-doesn't-touch-target
  and layered prompts (CAI), per-finding validation + coverage matrix + three-state
  closure (Strix), tool-priority table + cache + error recovery (HexStrike),
  typed task tree + verbatim-evidence rule (PentestGPT).

## Evaluation

Detection measured against a labelled ground-truth app with 15 planted
vulnerabilities across 8 classes (`lab/vulnapp/`), scored by the harness in
`scripts/eval/run_eval.py`. Metrics: coverage (detected classes / expected) and
false-positive rate (findings contradicting the `must_not_flag` labels).

**Pure-Python engine, deep mode, no external tools:**

| Metric                         | Value              |
| ------------------------------ | ------------------ |
| Expected vulnerability classes | 15                 |
| Detected (coverage)            | 15 / 15 = 100%     |
| False-positive rate            | 0%                 |
| Precision / Recall / F1        | 1.00 / 1.00 / 1.00 |
| Requests to complete           | 369                |

The false-positive guard matters: the engine does **not** flag `/safe`, which
reflects input but HTML-encodes it. Classes covered: reflected XSS, error-based
and blind (time-based) SQLi, open redirect, path traversal, CORS, sensitive-file
exposure, insecure cookies, SSTI, OS command injection, CRLF, SSRF (out-of-band),
GraphQL introspection, JWT weak-secret, IDOR. With the Kali toolbox enabled,
nuclei/dalfox/sqlmap add breadth on real targets (Juice Shop, DVWA).

_Caveat: 100% on a self-authored ground-truth app validates the pipeline, not
real-world recall. The contribution is the method and the safety model; the
next run measures recall on Juice Shop / DVWA / crAPI._

## Contribution

Mythos is the intersection of the four frameworks' strengths plus two things
none combine: scope enforcement in both the engine and a hook, and a
pure-Python engine that finds the headline web bug classes with zero external
tools installed. 30 automated tests; MIT; a Claude Code plugin.

## Architecture

See `docs/architecture.md` for the full diagram. One command, six agents, a
scope-aware engine, a Kali toolbox, a coverage matrix, and a bug-bounty report.
