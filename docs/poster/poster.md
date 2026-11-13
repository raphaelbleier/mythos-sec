# Mythos: Does Skill-Driven Scaffolding Improve an LLM Pentest Agent?

Security Engineering, research poster, winter semester 2026/27.

## Problem

AI pentest agents are proliferating (CAI, Strix, HexStrike, PentestGPT,
Shannon). Published scores on the XBOW validation benchmarks (e.g. Strix 100/104,
Shannon 100/104, PentestGPT 90/104) are self-reported, use different models, and
were not independently replicated. They do not show whether the scaffolding or
the model produces the result. Mythos asks a narrower question: with the model
held fixed, what does a skill-driven scaffold add over the bare model?

None of those published scores was reproduced here, and this work does not
compare itself against them. Of the frameworks named, only Strix ever produced a
cell in this harness, on a different provider route and with 2 of 12 cells valid
(Sweep B below). The CAI and PentestGPT adapters in `bench/runners/` raise
`NotImplementedError` and have never run: CAI is an archived interactive REPL,
and PentestGPT's autonomous mode drives only Claude Code or Codex, so it cannot
be held to the shared model. Their numbers appear above as the claim this project
declines to replicate, not as a baseline.

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
  control). Strix ran as a third arm in Sweep B on its own CLI, sandbox and
  provider route, which makes it a different system and not a paired comparison.
  The control arm is additionally denied `edit`, `webfetch`, `websearch`, `task`
  and `skill`, so "scaffolding" is one undifferentiated condition: skills,
  sub-agents, toolbox, prompt and tool access all change together, and no
  ablation separates them.
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

**Prüfbefund vom 13. November 2026: ein Teil der folgenden Zahlen ist nicht
belastbar.** Eine Prüfung der Harness fand vier Fehler. Die Tabellen bleiben
stehen, damit nachvollziehbar bleibt, was veröffentlicht war; an jeder steht,
was die Prüfung von ihr übrig lässt. Korrigierte Harness und vollständiges
Verfahren: `bench/METHODOLOGY.md`.

1. **Der Mythos-Arm konnte den Bewertungsschlüssel lesen, der Kontrollarm
   nicht.** Er startete mit `--add-dir <repo>` und `--plugin-dir <repo>`, also
   lag `bench/data/ground_truth/*.json` in einem Verzeichnis, das dieser Arm
   lesen durfte, und sein Werkzeugkasten mountete dasselbe Repository unter
   `/repo`. Gegen genau diese Dateien wird der Recall der flaglosen Ziele
   gewertet. Der Kontrollarm bekam ein leeres Arbeitsverzeichnis und keine
   solche Freigabe. Keine Prüfung der Harness testete darauf, und der
   Transkript-Detektor hätte einen Pfad der Ground Truth nicht getroffen. Die
   Transkripte belegen daher weder, dass der Schlüssel gelesen wurde, noch, dass
   er es nicht wurde. Betroffen sind die Sweeps D, F, G und H, darunter die
   einzige Trennung, die diese Arbeit gemessen hat.
2. **Das Deckungs-Gate wurde mit einem Teilstring-Vergleich gemessen.**
   `scripts/coverage` wertete die Erwähnung eines Pfades im Bericht als dessen
   Abdeckung. Mit diesem Maß entstand Sweep H, einschließlich der Aussage, beide
   Läufe wiesen alle 42 kartierten Pfade aus.
3. **Ausschlüsse hingen am Ergebnis.** Eine Zelle verließ den Nenner nur dann,
   wenn sie zugleich gescheitert war, ein Ausschluss konnte die Rate also nur
   heben. Der Kontrollarm der 40 Challenges steht bei 0,69 ohne jeden
   Ausschluss und bei 0,90 nach der veröffentlichten Regel. Nach einer Regel,
   die nur Signale liest, die der Agent nicht selbst schreiben kann, stehen die
   beiden Arme bei 0,87 und 0,88, also umgekehrt zur veröffentlichten
   Reihenfolge 0,90 gegen 0,85. **Der Abstand wechselt das Vorzeichen.** Damit
   ist er als Artefakt der Ausschlussregel belegt und nicht als Messung.
   Dieselbe Korrektur löscht die Strix-Zeile: zehn von zwölf Strix-Zellen
   liefen in die Stillstandsgrenze, zwei in einen Runner-Fehler, darunter beide
   Zellen, die als verwertbar gemeldet waren. Sie blieben nur deshalb drin,
   weil sie gelöst hatten. Nach der korrigierten Regel hat Strix **keine
   gewertete Zelle**, nicht 2 von 2 bei 1,00.
4. **Präzision wurde nie gemessen.** Keine Triage-Zeile konnte den Status `fp`
   tragen; das Schema listete die dokumentierten Schwachstellen und fragte je
   Zeile nach gefunden oder verpasst. Die Präzision 1,00 in allen Tabellen unten
   ist eine Eigenschaft dieses Schemas und keine Messung. Sie steht unten als
   „nicht gemessen“.

Acht Sweeps vom 4. und 5. November 2026, Rohdaten unter
`/mnt/linux-data/mythos-bench/results/`, bisher nicht im Repository. Jede Zelle
bekommt eine frisch gebaute Challenge mit zufälligem Flag, ein eigenes
Compose-Projekt im eigenen Netz, eine `scope.yaml` auf genau diesen Host und
Port, dieselbe Wall-Clock und ein sauberes HOME. Gewertet wird nur, was die
Harness selbst nachweist; Zellen, in denen der Anbieter die Quote verweigerte,
stehen gelassen hat, der Runner scheiterte oder ein Sicherheitsklassifikator die
Antwort abbrach, zählen nicht. Dass diese Ausschlüsse am Ergebnis hingen, ist
Fehler 3 oben.

**Was dagegen geprüft wurde: die Flags kamen vom Ziel.** Audits anderer
CTF-Harnesses finden, dass 17 bis 23 Prozentpunkte eines Ergebnisses auf Flags
entfallen, für die nichts ausgenutzt wurde. Nachträglich über alle vier
gespeicherten Sweeps gerechnet, erscheinen alle 79 gelösten Flags zuerst in der
Werkzeugausgabe und erst nach einer Anfrage an das Ziel, keines zuerst im
eigenen Text des Agenten. Dieser Effekt tritt hier also nicht auf. Die Prüfung
ist eine notwendige Bedingung und kein Beweis, dass der vorgesehene
Schwachstellentyp der Weg war.

Zwei Werkzeugfehler schwächten außerdem die Scanner-Seite in jedem Sweep. Eine
Lieferketten-Prüfung des Toolbox-Images fand, dass `nuclei` im damals
veröffentlichten Image ohne Templates lief, weil pips Cache `/home/pentester`
als root anlegte, bevor `useradd` lief, und dass das Image den PyPI-Platzhalter
`graphw00f` statt des echten Werkzeugs trug, was besonders die DVGA-Zahlen
betrifft. Beides ist im aktuellen `toolbox/Dockerfile` behoben. Welcher Sweep
welches Image benutzte, lässt sich nicht mehr feststellen, weil kein Sweep einen
Image-Digest aufzeichnete; genau das wird jetzt je Zelle festgehalten.

Keine dieser Messungen kontrolliert Kontamination. XBEN und alle vier realen
Anwendungen sind öffentliche Repositories mit öffentlichen Lösungswegen, und bei
den flaglosen Zielen ist die Ground Truth die öffentliche README der jeweiligen
Anwendung. Das zufällige Flag je Zelle verhindert allein, dass sich das
Upstream-Flag `sha256(VERZEICHNISNAME)` vorab berechnen lässt. XBOW selbst
beschreibt die Validation Benchmarks inzwischen als in die Modelle eingelernt
und nur noch historisch geführt, in einer Warnung vom 7. Juli 2026. XBEN ist
hier deshalb ein Regressionstest und kein Nachweis von Fähigkeit. Die
Kanarienvogel-Prüfung der Harness kann Kontaminationsfreiheit nicht belegen und
behauptet das auch nicht: keine Arbeit schätzt, wie viel dieser Anwendungen in
den Trainingsdaten steckt, und für Sicherheitsdaten ist kein
Kanarienvogel-Verfahren validiert. Ebenso ist die Konstruktvalidität offen. Keine
Studie verknüpft die Punktzahl eines Sicherheits-Benchmarks mit einem Ergebnis
in der Praxis, etwa einer Bounty-Zahlung oder einer gefundenen CVE.

**Sweep A, Claude Code, Modell `sonnet`, 40 Challenges (seed 7), ein Lauf je
Zelle, Budget 1800 s, apt_fix an.** Die Arme dieses Sweeps trugen das Gerüst
nicht (siehe Befund zur Messgültigkeit unten).

| Arm | gewertete Zellen | gelöst | Lösungsrate | Wilson 95 % CI | vom Klassifikator abgebrochen | Median s |
|---|---|---|---|---|---|---|
| control (nacktes Modell mit Shell) | 30 | 27 | 0,90 | 0,74 bis 0,97 | 9 | 32 |
| mythos (Gerüst nicht geladen) | 33 | 28 | 0,85 | 0,69 bis 0,93 | 7 | 30 |

Gepaart über 25 Challenges: 23 lösen beide, keine abweichenden Paare, 2 keiner.
McNemar exakt, p = 1,0. Ohne ein einziges abweichendes Paar hat dieser Test
keine Aussagekraft: er misst nicht, dass kein Unterschied besteht, sondern dass
die Stichprobe keinen zeigen kann. Die Kontrollzeile dieses Sweeps ist dieselbe
Messung, die unten in Sweep E wieder erscheint; der Kontrollarm lief nur einmal.
Die Lösungsrate 0,90 beruht auf der ergebnisabhängigen Ausschlussregel
(Fehler 3): über alle 39 Zellen sind es 0,69, nach einer ergebnisunabhängigen
Regel 0,96.

**Sweep B, OpenCode, Modell `zai/glm-5.3`, 12 Challenges (seed 1), Budget
5400 s.** Strix lief im selben Sweep auf `openai/glm-5.3` über seine eigene
CLI und Sandbox.

| Arm | gewertete Zellen | gelöst | Lösungsrate | Wilson 95 % CI | Median s |
|---|---|---|---|---|---|
| control | 10 | 10 | 1,00 | 0,72 bis 1,00 | 177 |
| mythos | 10 | 10 | 1,00 | 0,72 bis 1,00 | 135 |
| strix (zurückgezogen, siehe unten) | 0 | - | - | - | 438 |

Gepaart über 10 Challenges: alle zehn lösen beide, keine abweichenden Paare.
Beide Arme stehen an der Decke der gezogenen Challenges, ein Unterschied ist
hier nicht messbar.

**Die Strix-Zeile ist zurückgezogen.** Sie entstand ausschließlich durch
Fehler 3. Nach der ergebnisunabhängigen Regel bleibt von zwölf Strix-Zellen
keine einzige gewertet: zehn liefen in die Stillstandsgrenze des Anbieters, zwei
in einen Runner-Fehler, und das gilt auch für die beiden Zellen, die oben als
verwertbar stehen. Sie blieben nur drin, weil sie gelöst hatten. Strix lief
zudem über seine eigene CLI, seine eigene Sandbox und mit `openai/glm-5.3` über
eine andere Anbieterroute, ist also kein Paarvergleich. Wo sonst eine
Strix-Zahl auftaucht, gilt dasselbe.

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
| control | 8 | 1 | 0,89 | nicht gemessen | 7 | 54 |
| mythos, Gerüst nachweislich geladen | 8 | 1 | 0,89 | nicht gemessen | 6 | 53 |
| mythos, Gerüst nicht geladen | 8 | 1 | 0,89 | nicht gemessen | 6 | 55 |

Beide Mythos-Läufe hatten Lesezugriff auf `bench/data/ground_truth/vampi.json`,
der Kontrollarm nicht (Fehler 1). Der Recall ist deshalb als Messung des
Gerüsts zurückgezogen. Dass alle drei Läufe gleich abschneiden, ist allerdings
nicht das Ergebnis, das ein Leck zugunsten des Mythos-Arms erzeugen würde.

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

| Arm | gewertete Zellen | gelöst | Lösungsrate | Wilson 95 % CI | Werkzeugaufrufe (alle / gewertete Zellen) | Kosten USD (alle / gewertete) |
|---|---|---|---|---|---|---|
| control (nacktes Modell mit Shell) | 30 | 27 | 0,90 | 0,74 bis 0,97 | 390 / 345 | 8,63 / 7,82 |
| mythos, Gerüst geladen | 33 | 28 | 0,85 | 0,69 bis 0,93 | 928 / 901 | 20,88 / 19,97 |

Die Kontrollzeile ist dieselbe Messung wie in Sweep A. Wiederholt wurde nur der
Mythos-Arm, nachdem das Plugin-Manifest korrigiert war; der Kontrollarm lief
einmal und erscheint in beiden Tabellen. Frühere Fassungen stellten die
Gesamtkosten über alle 40 bzw. 39 Zellen neben Lösungsraten, die nur die
gewerteten Zellen zählen. Die Tabelle nennt jetzt beide Bezugsmengen; das
Verhältnis von 2,4 hält in beiden.

Gepaart über 26 Challenges: 22 lösen beide, keine nur mythos, eine nur die
Kontrolle, drei keiner. McNemar exakt, p = 1,0. Das geladene Gerüst löst
dieselbe Anzahl Challenges wie der Arm, der es nicht geladen hatte, und kostet
dafür das 2,4-Fache an Geld und 2,4-mal so viele Werkzeugaufrufe.

Auf Flag-Capture-Challenges mit einer Schwachstelle pro Ziel ist kein Beitrag
des Gerüsts nachweisbar, und das ist nicht dasselbe wie „es gibt keinen“. Über
26 gepaarte Challenges steht ein abweichendes Paar. Bei 26 Paaren und einer
Diskordanzrate von 0,3 liegt der kleinste Unterschied, den der exakte Test mit
80 % Teststärke findet, bei 0,29; bei 30 Paaren bei 0,27 und bei 40 Paaren bei
0,24. Ein echter Unterschied von 0,2 würde bei 30 Paaren in zwei von fünf
Fällen gefunden. Unter sechs abweichenden Paaren kann der Test überhaupt nicht
ablehnen. Die Literatur zum selben XBOW-Benchmark („Baselines Before
Architecture“, arXiv 2607.13085) nennt für den Vorteil eines Gerüsts bei
gleichem Modell 5 bis 10 Prozentpunkte. Dieses Design war gegen diesen Effekt
also um etwa den Faktor drei unterdimensioniert und konnte ihn nie finden. Der
zutreffende Befund lautet: zu geringe Teststärke, kein feststellbarer
Unterschied, kleinster auflösbarer Unterschied etwa 0,29. Die Zahlen rechnet
`bench/stats.py --selftest` nach. Beide Arme stehen nach dem Ausschluss der
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
| mythos, Gerüst geladen | 12 | 9 | 0,57 | nicht gemessen | 18 | 0,27 |
| control (nacktes Modell mit Shell) | 11 | 10 | 0,52 | nicht gemessen | 43 | 0,81 |

Auch hier hatte nur der Mythos-Arm Lesezugriff auf die Ground Truth
(Fehler 1), weshalb der Recall als Messung des Gerüsts zurückgezogen ist.

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

**Sweep G, flagloses Ziel Vuln Bank, Claude Code, Modell `sonnet`, Budget
3600 s, Gerüst nachweislich geladen.** 76 dokumentierte Schwachstellen, das
breiteste Ziel der Reihe, Handtriage mit einem Belegzitat je Zeile.

**Diese Tabelle war falsch und ist dieselbe Messung wie zwei Zeilen aus
Sweep H.** Veröffentlicht standen hier 27 gefundene Einträge für den Mythos-Arm
und 29 für die Kontrolle. Die Triage-Dateien der beiden Läufe, eindeutig
identifizierbar über Werkzeugaufrufe und Kosten (18 Aufrufe, 0,42 USD bzw.
15 Aufrufe, 0,29 USD), zählen 28 und 30. Keine Messung dieser Reihe hat 27
ergeben. Es sind außerdem genau die Zeilen „mythos ohne Gate, Lauf 1“ und
„control, Lauf 1“ aus Sweep H, also kein eigener Sweep:

| Arm | gefunden | verpasst | Recall | Präzision | Werkzeugaufrufe | Kosten USD |
|---|---|---|---|---|---|---|
| mythos ohne Gate, Lauf 1 | 28 | 48 | 0,37 | nicht gemessen | 18 | 0,42 |
| control, Lauf 1 | 30 | 46 | 0,39 | nicht gemessen | 15 | 0,29 |

Zwei Einträge Abstand bei 76 gewerteten, mit dem Vorzeichen zugunsten der
Kontrolle. Der geladene Arm hatte den zweiten Einspritzpunkt für SQL
(`/check_balance`) und die Entwicklungsinformationen, die Kontrolle die fehlende
Token-Ablaufzeit, die Kartendaten im Klartext und die API-Schlüssel in den
Antworten. Nur der Mythos-Arm konnte dabei die Ground Truth lesen (Fehler 1).

Entscheidend ist, was keiner der beiden anfasste. Der GraphQL-Block der
dokumentierten Liste sind die Einträge vb-73 bis vb-77, fünf Stück, und keiner
der beiden Läufe fand einen davon. Darüber hinaus stand hier eine Aufteilung der
verpassten Einträge auf vier Oberflächenbereiche (GraphQL sechs, Händler sechs,
Rechnungen neun, Kartenlogik zehn, zusammen 31 beim Mythos-Arm und 29 bei der
Kontrolle). Diese Gruppierung wurde von Hand gemacht und steht in keiner Datei:
sie lässt sich aus den Triage-Dateien nicht nachrechnen und wird deshalb nicht
wiederholt. Auch die Aussage, beide Läufe hätten diesen Bereichen nie eine
Anfrage geschickt, ist aus den gespeicherten Artefakten nicht belegbar; sie
wäre eine Auswertung der Anfragen im Transkript, die nie geschrieben wurde. Was
bleibt: der geladene Arm berichtete 13 Befunde, die Kontrolle 15, und beide
hörten nach wenigen Minuten auf, obwohl das Budget 3600 s betrug. Der
Deckeneffekt liegt hier an der Abbruchentscheidung des Agenten und nicht am
Ziel.

**Befund zur Messgültigkeit IV: die Warnung des Scope-Guards kommt zu spät.**
Auf dem Claude-Code-Host erreicht der `additionalContext` eines
`PreToolUse`-Hooks den Agenten gemeinsam mit dem Werkzeugergebnis. Im Modus
`warn` ist die Anfrage also längst heraus, wenn die Warnung eintrifft; die
Anweisung „eine Warnung bedeutet: führe diesen Befehl nicht aus“ war so nicht
einzuhalten. Der geladene Arm nannte in einer SSRF-Nutzlast die Adresse
169.254.169.254, die außerhalb des Scope liegt, und das Ziel baute die
Verbindung auf. Der Agent berichtete den Vorfall von sich aus. Seit dem
5. November 2026 benennt `AGENTS.md`, was der Modus `warn` leisten kann,
verweist für Engagements ohne Toleranz auf `MYTHOS_SCOPE_ENFORCE=ask` und
hält fest, dass eine Anfrage, die das Ziel im Auftrag des Agenten stellt, als
Anfrage des Agenten gilt. Der Prüfstand zählt die Treffer des Guards seither
selbst (`scope_warnings` je Lauf), statt sich auf das Eingeständnis des Agenten
zu verlassen.

**Sweep H, Vuln Bank mit und ohne Deckungs-Gate, Claude Code, Modell `sonnet`,
Budget 3600 s, je zwei Wiederholungen.** Das Gate ist die Antwort auf den
Befund aus Sweep G: `scripts/probe` schreibt die Oberflächenkarte nach
`engagements/<dir>/surface.json`, `scripts/coverage` listet jeden kartierten
Pfad, den der Bericht nicht erwähnt, und ein `Stop`-Hook gibt diese Liste
zurück, wenn der Agent aufhören will, höchstens dreimal je Engagement. Läuft
die Recon-Phase nicht, kartiert der Hook die Oberfläche selbst aus der
Scope-Datei; genau das war nötig, weil der Agent `scripts/probe` in jedem
Benchmark-Lauf übersprang.

| Arm | gefunden | Recall | Präzision | Werkzeugaufrufe | Kosten USD |
|---|---|---|---|---|---|
| mythos mit Gate, Lauf 1 | 34 | 0,45 | nicht gemessen | 32 | 0,61 |
| mythos mit Gate, Lauf 2 | 33 | 0,43 | nicht gemessen | 31 | 0,67 |
| mythos ohne Gate, Lauf 1 | 28 | 0,37 | nicht gemessen | 18 | 0,42 |
| mythos ohne Gate, Lauf 2 | 29 | 0,38 | nicht gemessen | 20 | 0,39 |
| control, Lauf 1 | 30 | 0,39 | nicht gemessen | 15 | 0,29 |
| control, Lauf 2 | 29 | 0,38 | nicht gemessen | 14 | 0,25 |

**Diese Trennung ist derzeit nicht belastbar und wird neu gemessen.** Drei
Gründe, von schwer nach leicht:

1. Nur der Mythos-Arm konnte `bench/data/ground_truth/vulnbank.json` lesen, also
   genau die Liste, gegen die diese Zeilen gewertet werden; der Kontrollarm
   konnte es nicht (Fehler 1 oben). Die vier Zeilen mit und ohne Gate stammen
   alle vom Mythos-Arm und hatten denselben Zugriff, der Vergleich mit und ohne
   Gate ist davon also nicht verzerrt. Der Abstand zur Kontrolle ist es.
2. Das Gate handelt auf dem Urteil von `scripts/coverage`, und dieses Skript
   zählte eine Teilstring-Übereinstimmung im Bericht als abgedeckten Pfad
   (Fehler 2). Die Läufe mit Gate wurden also von einem fehlerhaften Maß
   gesteuert.
3. Zwei Wiederholungen je Bedingung, kein Intervall, kein Test. Dass die
   Wertebereiche sich nicht überschneiden (33 bis 34 mit Gate gegen 28 bis 30 in
   den vier Läufen ohne Gate), ist bei n = 2 je Bedingung eine Beobachtung und
   keine belegte Trennung.

Die Präzision 1,00 aus der veröffentlichten Fassung steht oben als „nicht
gemessen“: das Triage-Schema konnte keinen Falsch-Positiv-Eintrag aufnehmen.

Die beiden Läufe mit Gate erreichen unterschiedliche Zusatzflächen: Lauf 1 die
GraphQL-Introspektion samt der Admin-Auswertung über ein gefälschtes Token und
den Token im `localStorage`, Lauf 2 die negative Händlerbelastung auf
`/api/v1/payments/charge` und die freiliegende Werkzeug-Konsole. Das Gate
schreibt also keine Befunde vor, sondern verlangt eine Begründung, bevor der
Agent aufhört.

Die veröffentlichte Aussage, beide Läufe wiesen am Ende alle 42 kartierten Pfade
aus und benannten die drei, die sie bewusst nicht angefasst haben, ist
zurückgezogen. Sie ist zirkulär: der Hook übergibt dem Agenten die Liste der
Pfade, und `scripts/coverage` zählte die Erwähnung eines Pfades als dessen
Abdeckung. Die Aussage wiederholt damit ihre eigene Eingabe. Sie wird erst wieder
aufgestellt, wenn sie mit dem korrigierten Maß gemessen ist.

Bezahlt wird das mit Aufwand. Mit Gate liegen die Läufe bei 31 bis 32
Werkzeugaufrufen und 0,61 bis 0,67 USD, die Kontrolle bei 14 bis 15 und 0,25
bis 0,29 USD. Das Gerüst kostet hier also gut das Doppelte und findet vier bis
fünf Einträge mehr, während es in den Flag-Sweeps das 2,4-Fache kostete und
nichts hinzufügte.

Einschränkung: eine Bedingung, ein Ziel, zwei Wiederholungen, und das unter den
drei Vorbehalten oben. Mehr als „auf diesem Ziel sah der Lauf mit Gate in beiden
Wiederholungen mehr Einträge“ trägt die Messung nicht, und auch das erst nach der
Wiederholung mit sauberer Harness. Dass das Gerüst allgemein überlegen wäre,
folgt daraus ohnehin nicht; auf den kleinen Zielen (VAmPI, neun Einträge) bleibt
nichts zu holen.

**Befund zur Wirkungsgrenze: das Gate hilft nur, soweit die Karte das Ziel
trifft.** Auf DVGA kehrte dieselbe Mechanik das Ergebnis um: 6 von 21 gegen 12
ohne Gate und 11 in der Kontrolle, bei 0,77 statt 0,27 USD. Die Ursache liegt
nicht im Gate, sondern in der Karte. DVGA ist eine GraphQL-Anwendung; die
Oberflächenkarte bestand aus elf HTML-Seiten, während jede der 21
dokumentierten Schwachstellen hinter `/graphql` liegt. Der Agent arbeitete die
elf Seiten pflichtgemäß ab und kam nicht mehr zu den Feldern, die zählen. Auf
Vuln Bank war die Karte deshalb brauchbar, weil die Anwendung ihre
OpenAPI-Beschreibung veröffentlicht und daraus 39 Endpunkte entstehen.

`scripts/probe` stellt seit dem 5. November 2026 eine Introspektionsabfrage an
`/graphql` und gibt jedes Query- und Mutationsfeld mit seinen Argumenten aus;
auf DVGA sind das 19 Felder, darunter `systemDebug`, `systemDiagnostics`,
`pastes(filter:)`, `importPaste` und `uploadPaste`, also genau die Einstiege
der dokumentierten Liste. Ein GraphQL-Endpunkt antwortet auf GET mit 400,
weshalb die Abfrage vor dem Statusfilter laufen muss. Die Messung mit dieser
Karte steht noch aus; der bedingte Befund bleibt: das Gate wirkt, soweit die
Karte die tatsächliche Oberfläche enthält, und schadet, wo sie sie verfehlt.

Per-Klassen-Aufschlüsselung und die Ablation mit und ohne Evidenz-Gating sind
offen. Der Recall auf crAPI steht noch aus, ebenso das Gate auf VAmPI und auf
den Flag-Challenges. Vor allem aber steht die Wiederholung aller Messungen auf
dem Claude-Code-Host mit der korrigierten Harness aus; bis dahin ist keine der
Zahlen oben als Ergebnis zu lesen.

## Earlier, uncontrolled evidence

Single manual engagements through the toolbox flow, no repeats, no control arm.
They show the flow works on real targets, not a measured advantage:
`benchmark-skill-driven.md` (Juice Shop), `benchmark-hard-targets.md` (DVGA
GraphQL chain, VAmPI, Vuln Bank). The full reports of six of those engagements
are in `evidence/`. `benchmark-xbow.md` is superseded: it was produced by a
harness (`scripts/eval/xbow_bench.py`) and a model id that no longer exist, and
it is marked as such at the top of the file.

A regression self-test (`scripts/selftest.sh`: the deterministic surface probe
and canary verifier, 7 vulnerability classes, a no-false-positive control,
scope-guard, coverage gate, plugin manifest) runs on both hosts. The number of
checks is not quoted here. The script prints its own
`== result: N passed, M failed ==` line, the count depends on the host and on
which lab targets are reachable, and the counts published earlier, 31 here and
35 in the README, matched neither the file nor each other.

## Contribution

A same-model evaluation of scaffolding value, with a bare-model control,
interval estimates and paired tests; an OpenCode-first, single-source framework
usable on both hosts; and explicit coverage of multi-account, business-logic and
stored-XSS/OAST work. Whether the scaffolding helps is the open result above.

The evaluation is not yet reproducible from this repository, and the audit of
13 November 2026 belongs to the contribution rather than to an appendix. The raw
artifacts live outside the repository; the harness let one arm read the key it
was scored against; the exclusions depended on the outcome; precision was never
measurable. `bench/METHODOLOGY.md` states the design, the scoring rules, every
exclusion, the blinding procedure, which artifacts are committed and the known
limitations, so that the re-run can be checked by someone else. That is also the
honest headline: an evaluation of one's own scaffolding is easy to build in a way
that cannot fail, and here it took an audit rather than a measurement to notice.

## Limitations

See `LIMITATIONS.md`. Architecture: `docs/architecture.md`.
