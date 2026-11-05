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

Drei Sweeps, alle vom 4. November 2026, Rohdaten unter
`/mnt/linux-data/mythos-bench/results/`. Jede Zelle bekommt eine frisch
gebaute Challenge mit zufälligem Flag, ein eigenes Compose-Projekt im eigenen
Netz, eine `scope.yaml` auf genau diesen Host und Port, dieselbe Wall-Clock und
ein sauberes HOME. Gewertet wird nur, was die Harness selbst nachweist; Zellen,
in denen der Anbieter die Quote verweigerte, stehen gelassen hat oder der
Runner scheiterte, zählen nicht.

**Sweep A, Claude Code, Modell `sonnet`, 40 Challenges (seed 7), ein Lauf je
Zelle, Budget 1800 s, apt_fix an.**

| Arm | gewertete Zellen | gelöst | Lösungsrate | Wilson 95 % CI | Median s |
|---|---|---|---|---|---|
| control (nacktes Modell mit Shell) | 39 | 27 | 0,69 | 0,54 bis 0,81 | 23 |
| mythos | 40 | 28 | 0,70 | 0,55 bis 0,82 | 28 |

Gepaart über 39 Challenges: 23 lösen beide, 5 nur mythos, 4 nur die Kontrolle,
7 keiner. McNemar exakt, p = 1,0.

**Sweep B, OpenCode, Modell `zai/glm-5.3`, 12 Challenges (seed 1), Budget
5400 s.** Strix lief im selben Sweep auf `openai/glm-5.3` über seine eigene
CLI und Sandbox.

| Arm | gewertete Zellen | gelöst | Lösungsrate | Wilson 95 % CI | Median s |
|---|---|---|---|---|---|
| control | 10 | 10 | 1,00 | 0,72 bis 1,00 | 177 |
| mythos | 10 | 10 | 1,00 | 0,72 bis 1,00 | 135 |
| strix | 2 | 2 | 1,00 | 0,34 bis 1,00 | 438 |

Gepaart über 10 Challenges: alle zehn lösen beide, keine abweichenden Paare.
Von Strix' zwölf Zellen blieben nur zwei verwertbar, acht endeten im
Stillstand des Anbieters und zwei im Runner-Fehler.

**Sweep C, Claude Code, Modell `sonnet`, Nachlauf auf den sieben Challenges,
an denen in Sweep A beide Arme gescheitert waren.** Zwischen A und C bekam der
Orchestrator die Regeln gegen vorzeitiges Aufgeben und gegen Festbeißen.

| Arm | gewertete Zellen | gelöst | Lösungsrate | Wilson 95 % CI | Median s |
|---|---|---|---|---|---|
| control | 7 | 2 | 0,29 | 0,08 bis 0,64 | 166 |
| mythos | 7 | 2 | 0,29 | 0,08 bis 0,64 | 57 |

Beide Arme lösen jetzt zwei der sieben, die zuvor keiner löste. Weil die
Kontrolle keine Regeln bekam und ebenso zulegt, ist das Lauf-zu-Lauf-Varianz
und kein belegter Effekt der Änderung.

Auf Flag-Capture-Challenges mit einer Schwachstelle pro Ziel ist
der Beitrag des Gerüsts null, soweit diese Stichproben das auflösen. Die
Intervalle überlappen in allen drei Sweeps fast vollständig, und kein
gepaarter Test kommt unter p = 1,0. Auf GLM 5.3 stehen beide Arme am
Deckeneffekt der gezogenen Challenges, dort ist mythos lediglich schneller
(Median 135 s gegen 177 s). Wo das Gerüst wirken müsste, nämlich bei
mehrstufigen Ketten und Zugriffskontrolle, messen diese Challenges nicht: die
sieben gemeinsamen Fehlschläge tragen Tags wie `insecure_deserialization`,
`business_logic` und `privilege_escalation`, und genau dort liefert
Flag-Capture kein Teilergebnis.

Die Transkripte zeigen zwei Steuerungsfehler, die nicht am Modell liegen. Drei der sieben gemeinsamen Fehlschläge enden nach drei
bis vier Werkzeugaufrufen in rund zwanzig Sekunden, darunter eine Level-1-IDOR,
der Agent gibt also auf statt zu scheitern. Zwei andere laufen mit 103 und 112
Aufrufen über 22 bis 30 Minuten in eine Sackgasse. Der Orchestrator verbietet
seit Sweep C beides ausdrücklich; der Nachweis, dass die Regeln greifen, steht
aus und braucht mehrere Läufe je Zelle.

Per-Klassen-Aufschlüsselung und die Ablation mit und ohne Evidenz-Gating sind
offen. Der Recall auf den flaglosen Zielen (crAPI, Vuln Bank, DVGA, VAmPI)
gegen die dokumentierten Schwachstellenlisten ist der Messpunkt, an dem ein
Beitrag des Gerüsts überhaupt sichtbar werden kann; er fehlt noch.

## Earlier, uncontrolled evidence

Single manual engagements through the toolbox flow, no repeats, no control arm.
They show the flow works on real targets, not a measured advantage:
`benchmark-skill-driven.md` (Juice Shop), `benchmark-hard-targets.md` (DVGA
GraphQL chain, VAmPI, Vuln Bank), `benchmark-xbow.md`. A regression self-test
(`scripts/selftest.sh`, 21 checks: the deterministic surface probe and canary verifier, 7 vulnerability classes, a no-false-positive
control, scope-guard) runs on both hosts.

## Contribution

A reproducible, same-model evaluation of scaffolding value, with a bare-model
control, interval estimates and paired tests; an OpenCode-first, single-source
framework usable on both hosts; and explicit coverage of multi-account,
business-logic and stored-XSS/OAST work. Whether the scaffolding helps is the
open result above.

## Limitations

See `LIMITATIONS.md`. Architecture: `docs/architecture.md`.
