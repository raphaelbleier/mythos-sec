# Three frameworks on Vuln Bank, 14 November 2026

The first head-to-head against a competitor this project has. Mythos, a bare
control agent and Strix, all on GLM 5.3 through the same key, the same 900
second budget, the same endpoint, scored against the same 76 documented
vulnerabilities and rated blind by two independent raters.

## The result

| framework | recall A | recall B | precision A | precision B | wall clock | cut off |
|---|---|---|---|---|---|---|
| Mythos | 0.34 | 0.39 | 1.00 | 1.00 | 900 s | yes |
| bare control | 0.33 | 0.39 | 0.95 | 0.95 | 568 s | no |
| Strix | 0.00 | 0.00 | 1.00 | 1.00 | 905 s | yes |

Inter-rater agreement 0.908 to 1.000, Cohen's kappa 0.801 to 1.000, the best in
any run this project has made.

Mythos against the control, paired on each of the 76 entries: McNemar exact
p = 1.0000 under both raters, with the discordant pairs split 6 against 5 and 7
against 7. There is no difference in how many either finds.

## The finding: same total, different vulnerabilities

| rater | mythos | control | both | mythos only | control only | union |
|---|---|---|---|---|---|---|
| A | 26 | 25 | 20 | 6 | 5 | 31 / 76 = 0.41 |
| B | 30 | 30 | 23 | 7 | 7 | 37 / 76 = 0.49 |

Each arm finds six or seven entries the other misses, and the union is 20 to 25
per cent above either arm alone. The scaffolding does not find more. It finds
different.

Which ones is not random. The scaffolded arm uniquely reached the bill-payment,
merchant and AI-configuration surfaces (vb-46, 56, 57, 58, 61, 66, 72). The
bare agent uniquely reached the reset PIN, localStorage exposure, SSRF, the weak
secret, CSRF and prompt injection (vb-07, 08, 28, 29, 32, 63, 69). The
scaffolding's own limitations file had recorded the merchant and bill-payment
surfaces as never reached by either arm, so that part is new.

A difference in composition at equal totals is a real, characterisable effect
and a better thing to measure next than breadth. It is also the first result
here that a null McNemar does not describe.

## Strix

Strix scored 0.00 recall under both raters, and that number needs reading
carefully rather than quoting.

It ran for its full budget and was cut off before writing
`penetration_test_report.md`. What it filed is seven SARIF entries, of which it
labels three "No issue identified" and four "Requires further review". Both
raters took those labels at their word, so every truth row is a miss, while all
four substantive claims are true, giving precision 1.00 on recall 0.00. That
pairing is an artefact of hedging, not evidence of accuracy, and both raters
said so unprompted.

Rater A noted that a looser reading of the concrete observations inside those
hedged entries, the three-digit reset PIN quoted as `"342"` in `debug_info`, the
system prompt and the database schema, would add three to five found entries. It
would still trail both other arms by a wide margin.

**Getting Strix to run at all took four attempts, and all four failures were
this project's, not Strix's:**

1. `STRIX_DIR` resolved under `BENCH_ROOT`, which moved to sit beside the repo
   when the hardcoded paths were made configurable earlier the same day. The
   checkout was not found and the cell reported `runner_failed`.
2. Strix takes LiteLLM ids, and `zai/` is not a provider prefix. It needs
   `LLM_API_BASE` pointed at the OpenAI-compatible endpoint the key is on.
3. The stall detector watched the transcript's size. Strix writes into
   `cwd/strix_runs/` while it runs and its runner appends the transcript
   afterwards, so the transcript never grew and the 420 second deadline fired
   every time. **This very likely accounts for the whole of the "Strix kept only
   2 of 12 valid cells" this project previously recorded about Strix.** That was
   a statement about this harness.
4. The lab publishes on 127.0.0.1, which an arm with its own sandbox container
   cannot reach. Strix spent a complete cell proving the target was refused and
   diagnosing why correctly, without help.

Anyone citing a Strix comparison from this project before 14 November 2026
should treat it as withdrawn.

## What this does not establish

- **One target, 76 entries, one cluster.** The minimum detectable difference is
  about 0.17. No clustered interval is possible from a single target.
- **One run per arm.** Run-to-run variance on agentic tasks is measured at 2.2
  to 6.0 points elsewhere, so the six-or-seven-entry disjoint sets are a single
  observation, not an established pattern. Repeating this is the obvious next
  step and the cheapest one.
- **Two arms were cut off and one was not.** Mythos and Strix used their whole
  budget; the control stopped at 568 seconds believing it was done. A longer
  budget could move two of the three.
- **The blinding leaked for the Strix cell.** The redaction list covered this
  project's own tokens and not its competitors', so `strix-coverage/` survived
  into the rendered SARIF headings and both raters reported recognising the arm.
  The redaction is fixed; this cell's rating was not blind, and the two full
  reports could be separated by delivery shape in any case.
- **Strix brings its own agent loop, sandbox and provider route**, so it differs
  from the other two in more than the scaffolding. Its runner says so, and that
  remains true now that it runs.
- **Two factual contradictions between the arms went unresolved**, by design: the
  JWT signing key is `secret123` cracked offline in one report and a 32-hex
  value read from an exposed `.env` in the other, both claiming an accepted
  forgery; and `?q=` on `/blog` is executed with a captured canary in one and
  assigned safely via `.value` in the other. No rater consulted the source to
  break either tie.

## Files

`sealed-map.json`, `blind/<id>/report.txt` (the redacted deliverable each rater
saw), `blind/<id>/triage-rater{A,B}.json`, `<arm>/result.json` and `proc.json`,
and `strix/findings.sarif` as Strix filed it. Transcripts are not committed.

Reproduce the pairing:

```bash
python3 bench/stats.py --vuln \
  mythos=blind/154592f1/triage-raterA.json \
  control=blind/c2d1f62c/triage-raterA.json
```
