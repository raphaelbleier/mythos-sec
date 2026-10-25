# Mythos — Roadmap

Status of the **skill-driven** Mythos framework: Claude Code is the agent, phase
skills are the playbooks, and real security tools run in the Kali toolbox. No
Python engine, no external API key, no second LLM runtime.

Legend: ✅ done · 🚧 in progress · ⏳ planned

## Architecture pivot (current)

Mythos was rebuilt from a deterministic Python engine + standalone LLM agent into
a pure skill-driven plugin, in the spirit of how CAI/Strix/HexStrike let the
model drive — but native to Claude Code and keyless.

- ✅ **`/cybersecurity` orchestrator** drives the engagement through phase skills.
- ✅ **Phase skills**: `engagement-setup`, `recon`, `web-scan`, `exploit`,
  `report`, `toolbox` — each naming the exact tools + techniques.
- ✅ **Sub-agents** (planner/recon/scanner/browser/exploiter/reporter) follow the
  skills, `model: inherit`.
- ✅ **Toolbox shim** (`scripts/mythos`): thin `docker exec` driver over the Kali
  container. `up` / `down` / `tools` / `run` / `sh` / `<tool>`.
- ✅ **Kali toolbox** image: full web/API tool belt (nuclei, sqlmap, dalfox,
  ffuf, katana, subfinder, httpx, nikto, commix, interactsh-client, jwt_tool,
  gf/qsreplace/gau) + headless Chromium.
- ✅ **Scope-guard hook** retained as the authorization safety net (warn/block).
- ✅ **Removed**: `engine/` (Python engine + standalone `mythos_agent` runtime)
  and `scripts/eval/` — superseded by the skill-driven model.

## Validated

- ✅ **Regression self-test** (`scripts/selftest.sh`): 10/10 — 7 ground-truth
  classes + a no-false-positive control + 2 scope-guard checks, all through the
  toolbox. Repeatable automated suite for the skill-driven architecture.
- ✅ **Live benchmark — OWASP Juice Shop** (Angular SPA + REST): 6 classes
  surfaced, 5 confirmed unauthenticated with tool evidence (critical UNION SQLi
  → Users dump, `/ftp` disclosure, poison-null-byte filter bypass, open-redirect
  allowlist bypass, config leak), 1 DOM-XSS candidate flagged for the browser
  agent. See `docs/poster/benchmark-skill-driven.md`.

## Backlog

- ⏳ A `knowledge/`-backed per-class cheat-sheet the scanner reads inline.
- ⏳ Authenticated-SPA recipe in the `recon`/`browser` skills (Playwright login +
  cookie reuse for authenticated scanning).
- ⏳ OOB exfil recipe hardening in `exploit` (interactsh templates for blind
  SQLi/RCE/SSRF/XXE, filter-evasion payload library).
- ⏳ GHCR-published toolbox image for one-pull setup (no local build).
- ⏳ Extend the live benchmark set beyond Juice Shop (DVWA authenticated, VAmPI
  API/BOLA) and record each in `docs/poster/`.

## Design references

`docs/research/frameworks-analysis.md` — the CAI/Strix/HexStrike/PentestGPT
analysis that drives these choices. `docs/architecture.md` — the current design.
