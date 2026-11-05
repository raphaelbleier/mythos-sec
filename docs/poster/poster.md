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

Sechs Sweeps vom 4. und 5. November 2026, Rohdaten unter
`/mnt/linux-data/mythos-bench/results/`. Jede Zelle bekommt eine frisch
gebaute Challenge mit zufälligem Flag, ein eigenes Compose-Projekt im eigenen
Netz, eine `scope.yaml` auf genau diesen Host und Port, dieselbe Wall-Clock und
ein sauberes HOME. Gewertet wird nur, was die Harness selbst nachweist; Zellen,
in denen der Anbieter die Quote verweigerte, stehen gelassen hat, der Runner
scheiterte oder ein Sicherheitsklassifikator die Antwort abbrach, zählen nicht.

**Sweep A, Claude Code, Modell `sonnet`, 40 Challenges (seed 7), ein Lauf je
Zelle, Budget 1800 s, apt_fix an.** Die Arme dieses Sweeps trugen das Gerüst
nicht (siehe Befund zur Messgültigkeit unten).

| Arm | gewertete Zellen | gelöst | Lösungsrate | Wilson 95 % CI | vom Klassifikator abgebrochen | Median s |
|---|---|---|---|---|---|---|
| control (nacktes Modell mit Shell) | 30 | 27 | 0,90 | 0,74 bis 0,97 | 9 | 32 |
| mythos (Gerüst nicht geladen) | 33 | 28 | 0,85 | 0,69 bis 0,93 | 7 | 30 |

Gepaart über 25 Challenges: 23 lösen beide, keine abweichenden Paare, 2 keiner.
McNemar exakt, p = 1,0.

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
an denen in Sweep A beide Arme gescheitert waren.**

| Arm | gewertete Zellen | gelöst | Lösungsrate | Wilson 95 % CI | Median s |
|---|---|---|---|---|---|
| control | 5 | 2 | 0,40 | 0,12 bis 0,77 | 872 |
| mythos | 5 | 2 | 0,40 | 0,12 bis 0,77 | 88 |

Beide Arme lösen zwei der fünf verwertbaren Zellen, gepaart bleiben drei
Challenges ohne abweichendes Paar.

**Befund zur Messgültigkeit I: das Gerüst war nicht geladen.** Die Arme auf dem
Claude-Code-Host der Sweeps A und C trugen es nicht. Das Plugin-Manifest
deklarierte `author` als Zeichenkette und `agents` als Pfadangabe; Claude Code
verwirft ein solches Manifest ohne Meldung, also lud
`claude -p --plugin-dir` weder den Befehl `/cybersecurity` noch die Sub-Agenten
noch die Plugin-Hooks. Der Arm las lediglich `CLAUDE.md` und `AGENTS.md` aus
seinem Arbeitsverzeichnis. Sweep B auf OpenCode ist nicht betroffen, weil
`opencode run --agent mythos` bei fehlendem Agenten abbricht. Das Manifest ist
korrigiert, und der Bench-Arm bricht eine Zelle ab, deren `init`-Ereignis
keinen Befehl `:cybersecurity` führt.

**Befund zur Messgültigkeit II: ein Sicherheitsklassifikator beendet Zellen.**
In etwa der Hälfte aller Zellen auf dem Claude-Code-Host griff ein
Klassifikator in eine Antwort ein. Endet eine Zelle darauf, hält der Agent
richtigerweise an und berichtet den Abbruch, gemessen wird dann aber der
Klassifikator und nicht der Agent. Sieben bis neun der zwölf ungelösten Zellen
je Arm endeten so. Diese Zellen tragen seit dem 5. November 2026 den Status
`classifier_blocked` und gehen wie eine Anbieterverweigerung nicht in die
Lösungsrate ein; alle Zahlen oben sind entsprechend neu ausgewertet. Die
OpenCode-Arme sind davon nicht betroffen.

**Sweep D, flagloses Ziel VAmPI, Claude Code, Modell `sonnet`, Deckungsauftrag
statt Flag-Suche, Budget 1500 bzw. 1800 s.** Gewertet wird der Recall gegen die
neun dokumentierten Schwachstellen; die Präzision ergibt sich aus der Handtriage
der Berichte.

| Arm | gefunden | verpasst | Recall | Präzision | Werkzeugaufrufe | Laufzeit s |
|---|---|---|---|---|---|---|
| control | 8 | 1 | 0,89 | 1,00 | 7 | 54 |
| mythos, Gerüst nachweislich geladen | 8 | 1 | 0,89 | 1,00 | 6 | 53 |
| mythos, Gerüst nicht geladen | 8 | 1 | 0,89 | 1,00 | 6 | 55 |

Alle drei Läufe verfehlen genau denselben Eintrag, den RegexDOS, und zwar mit
derselben Begründung: der Nachweis hätte eine Dienstverweigerung riskiert.
Falsch-positive Befunde traten nicht auf. Der geladene Arm nannte elf
Schwachstellen, die Kontrolle zehn; die zusätzlichen Treffer, der freiliegende
Werkzeug-Debugger und das unauthentifizierte `GET /createdb`, stehen nicht auf
der dokumentierten Liste und gehen daher in keinen Recall ein.

Bemerkenswert ist, wie der geladene Arm arbeitete: sechs gebündelte
Shell-Aufrufe, kein delegierter Sub-Agent, kein Werkzeugkasten, kein
deterministischer Surface-Probe. Das entspricht der Regel des Orchestrators,
die Arbeit an der Größe des Ziels zu bemessen, führt bei einer kleinen API aber
dazu, dass sich das Gerüst praktisch selbst abschaltet.

**Sweep E, dieselben 40 Challenges wie Sweep A, Claude Code, Modell `sonnet`,
Budget 1800 s, Gerüst nachweislich geladen.** Gepaart gegen den Kontrollarm aus
Sweep A, der vom Manifest-Fehler nicht betroffen war.

| Arm | gewertete Zellen | gelöst | Lösungsrate | Wilson 95 % CI | Werkzeugaufrufe | Kosten USD |
|---|---|---|---|---|---|---|
| control (nacktes Modell mit Shell) | 30 | 27 | 0,90 | 0,74 bis 0,97 | 390 | 8,63 |
| mythos, Gerüst geladen | 33 | 28 | 0,85 | 0,69 bis 0,93 | 928 | 20,88 |

Gepaart über 26 Challenges: 22 lösen beide, keine nur mythos, eine nur die
Kontrolle, drei keiner. McNemar exakt, p = 1,0. Das geladene Gerüst löst
dieselbe Anzahl Challenges wie der Arm, der es nicht geladen hatte, und kostet
dafür das 2,4-Fache an Geld und 2,4-mal so viele Werkzeugaufrufe.

Auf Flag-Capture-Challenges mit einer Schwachstelle pro Ziel ist der Beitrag
des Gerüsts null, soweit diese Stichproben das auflösen, und auf dem flaglosen
Ziel mit dokumentierter Liste ebenso. Beide Arme stehen nach dem Ausschluss der
abgebrochenen Zellen bei 0,85 bis 0,90, also nahe am Deckeneffekt der gezogenen
Challenges; drei bis fünf ungelöste Zellen je Arm lassen für einen Unterschied
kaum Spielraum. Wo das Gerüst wirken müsste, nämlich bei mehrstufigen Ketten und
Zugriffskontrolle, messen diese Challenges nicht: Flag-Capture liefert dort kein
Teilergebnis.

**Sweep F, flagloses Ziel DVGA, Claude Code, Modell `sonnet`, Budget 2400 s,
Gerüst nachweislich geladen.** 21 dokumentierte Schwachstellen, Handtriage mit
einem Belegzitat je Zeile.

| Arm | gefunden | verpasst | Recall | Präzision | Werkzeugaufrufe | Kosten USD |
|---|---|---|---|---|---|---|
| mythos, Gerüst geladen | 12 | 9 | 0,57 | 1,00 | 18 | 0,27 |
| control (nacktes Modell mit Shell) | 11 | 10 | 0,52 | 1,00 | 43 | 0,81 |

Der Abstand von einem Eintrag liegt im Rauschen. Fünf der 21 gewerteten
Einträge sind Dienstverweigerungsklassen, deren Nachweis die Sicherheitsregeln
des Auftrags verbieten; beide Arme lassen sie folgerichtig aus. Rechnet man sie
heraus, stehen beide Arme bei 10 von 16, also 0,63 gegen 0,63. Je ein Eintrag
ging nur an einen Arm: der geladene Arm wies die Feldvorschläge und die
Array-Bündelung nach, die Kontrolle den Schreibpfad des Verzeichniswechsels,
den sie über die zuvor erlangte Codeausführung lokalisierte. Acht Einträge fand
keiner der beiden.

Die Kostenrichtung dreht sich hier gegenüber Sweep E: die Kontrolle brauchte 43
Werkzeugaufrufe und 0,81 USD, der geladene Arm 18 und 0,27 USD. Der tiefere
Lauf war der der Kontrolle, und er brachte einen Eintrag weniger ein.

**Befund zur Messgültigkeit III: das Ziel hält den Angriff nicht aus.** DVGA
blockiert dauerhaft, sobald `importPaste` die eigene Adresse der Anwendung
abruft, und ein blockierter Prozess nimmt weiter TCP-Verbindungen an, sodass
eine Portprüfung den Ausfall nicht sieht. Zwei frühere Läufe verbrachten je etwa
35 Minuten an einem toten Ziel. Seit dem 5. November 2026 startet der Prüfstand
das Ziel neu, wenn es 90 Sekunden keine HTTP-Antwort gibt, und protokolliert
jeden Neustart neben dem Transkript; die beiden Läufe oben brauchten drei
beziehungsweise zwei Neustarts. Ein Lauf, dessen Ziel am Ende weiter
ausgefallen ist, trägt den Status `target_failed` und wird nicht gewertet.
Beide Arme veränderten dabei Bestandsdaten, obwohl der Auftrag
Zerstörungsfreiheit vorschreibt: die Kontrolle löschte einen fremden Eintrag
und überschrieb den Titel eines zweiten, der geladene Arm änderte einen Eintrag
und stellte ihn wieder her. Beide berichteten das von sich aus.

Per-Klassen-Aufschlüsselung und die Ablation mit und ohne Evidenz-Gating sind
offen. Der Recall auf den übrigen flaglosen Zielen (crAPI, Vuln Bank) steht
noch aus.

## Earlier, uncontrolled evidence

Single manual engagements through the toolbox flow, no repeats, no control arm.
They show the flow works on real targets, not a measured advantage:
`benchmark-skill-driven.md` (Juice Shop), `benchmark-hard-targets.md` (DVGA
GraphQL chain, VAmPI, Vuln Bank), `benchmark-xbow.md`. A regression self-test
(`scripts/selftest.sh`, 22 checks: the deterministic surface probe and canary verifier, 7 vulnerability classes, a no-false-positive
control, scope-guard, plugin manifest) runs on both hosts.

## Contribution

A reproducible, same-model evaluation of scaffolding value, with a bare-model
control, interval estimates and paired tests; an OpenCode-first, single-source
framework usable on both hosts; and explicit coverage of multi-account,
business-logic and stored-XSS/OAST work. Whether the scaffolding helps is the
open result above.

## Limitations

See `LIMITATIONS.md`. Architecture: `docs/architecture.md`.
