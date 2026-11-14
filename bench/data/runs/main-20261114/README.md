# Mythos against a bare control agent, 14 November 2026

The main comparison, run on the repaired harness. 106 paired documented
vulnerabilities across three targets, two independent raters, blinded.

This is the largest sample this project has produced and the first time the
main question has been asked with enough units to answer anything.

## Design

Six cells, one run per arm per target, Claude Code host, Claude Sonnet.
`claude_mythos` loads the skills, sub-agents, toolbox, guards and the coverage
gate; `claude_control` is the same model with an empty working directory and
no file-writing tools. Both arms' readable roots are recorded per cell and are
symmetric apart from the treatment: the control sees only its own `cwd`, and
the mythos arm sees its `cwd` plus the content-addressed staged assets. Neither
can reach the ground truth.

Targets and budgets: VAmPI (9 scored entries, 600 s), DVGA (21, 600 s), Vuln
Bank (76, 1200 s).

Pairing is on each of the 106 scored ground-truth entries, not on the target.
Pairing per target gives three units and cannot reject anything.

Rating was blinded. Arm-identifying tokens were redacted, runs renamed to
hashes, and the deliverable is the union of `report.md` and the final message,
because the control cannot write files and taking one medium has biased this
comparison in both directions before. Two raters on different models filled
their triage independently against `bench/data/triage-rubric.md`, neither
seeing the other's file, the sealed map, the run records or the transcripts.

## Result

| rater | recall control | recall mythos | discordant | McNemar exact p | difference, 95% clustered |
|---|---|---|---|---|---|
| A | 0.36 | 0.37 | 6 : 7 | 1.0000 | [-0.039, +0.095] |
| B | 0.42 | 0.48 | 5 : 12 | 0.1435 | [-0.105, +0.048] |

**No detectable difference.** Both raters put the mythos arm at or slightly
above the control and neither reaches significance. The minimum detectable
difference at 106 pairs is 0.15.

The intervals are the informative part. Under rater B the point estimate is six
percentage points in the scaffolding's favour, which sits inside the 5 to 10
point scaffold effect the independent literature reports for a matched model,
and the interval's upper edge is 10.5 points. So this run is consistent with a
real effect of the size others have measured and cannot establish one. Unlike
the coverage-gate comparison of the same week, both raters agree on the
direction here.

Per cell, unsealed after both ratings were final:

| target | arm | recall A | recall B | precision A | kappa |
|---|---|---|---|---|---|
| VAmPI | control | 0.89 | — | 0.90 | 1.000 |
| VAmPI | mythos | 0.89 | — | 1.00 | 1.000 |
| DVGA | control | 0.33 | — | 1.00 | 0.800 |
| DVGA | mythos | 0.24 | — | 0.64 | 0.674 |
| Vuln Bank | control | 0.30 | — | 0.94 | 0.881 |
| Vuln Bank | mythos | 0.34 | — | 1.00 | 0.757 |

Inter-rater agreement is 0.857 to 1.000, Cohen's kappa 0.674 to 1.000, which
Landis and Koch call substantial to almost perfect. That is better than the
0.40 to 0.64 reported for LLM-versus-human agreement on security finding
matching, and better than the 0.70 to 0.77 on the gate comparison, where the
two raters disagreed across the 0.05 line.

Two things in this run did not exist before it:

- **Precision is measured**, between 0.64 and 1.00. The weakest figure belongs
  to the mythos arm on DVGA, with four false positives. Every precision of
  1.00 this project published before 13 November came from a schema in which no
  row could be a false positive.
- **Vuln Bank's merchant, bill-payment and card surfaces were reached**, which
  the earlier limitations recorded as never reached by either arm. The mythos
  arm's report demonstrates negative-amount transfer and negative-amount bill
  payment, which are business-logic flaws a scanner does not find.

## What this does not establish

- **It does not show the scaffolding beats a bare agent.** p = 1.0000 and
  p = 0.1435. The honest statement is underpowered against the effect size the
  literature reports, not "no difference".
- **One run per cell.** Run-to-run variance on agentic tasks is measured at 2.2
  to 6.0 points elsewhere, so a six-point point estimate from single runs is
  inside the noise band on its own.
- **Three clusters.** The bootstrap interval resamples targets, because entries
  behind one unreached surface fail together. Three clusters give a wide
  interval, and that width is honest rather than a defect.
- **The treatment is one bundle.** The control is denied file writing, web
  fetching, search, sub-agents and skills together, so this compares a
  scaffolded agent with a bare one and attributes nothing to any single
  component. The per-treatment flags are in each `result.json` so an ablation
  is possible later.
- **Public targets.** All three are public repositories with public write-ups,
  and nothing measures how much of them is in the model's training data. No
  study validates canary stripping for security corpora, so contamination
  cannot be ruled out, only noted.
- **The rubric still has gaps both raters hit.** Whether terse evidence that
  names an endpoint and an outcome without quoting a response counts as proof,
  how to rate a real finding the report hedges, and how to score a denial-of
  -service entry when the rubric and the target's own `dos_rule` disagree.
  Rater A notes that a strict "request and response quoted" bar would halve one
  VAmPI cell's recall.

## Files

- `sealed-map.json`: blind id to arm, with the per-cell treatment record.
- `blind/<id>/report.txt`: the redacted deliverable the raters saw.
- `blind/<id>/triage-raterA.json`, `triage-raterB.json`: the two ratings.
- `<arm>-<target>/result.json`: readable roots, host versions, resolved models,
  repo commit, treatment flags.

Transcripts are not committed: they contain created credentials and target
data. `bench/METHODOLOGY.md` states the policy.

Reproduce:

```bash
python3 bench/stats.py --vuln \
  mythos=blind/81ed6935/triage-raterA.json \
  mythos=blind/d80abe1f/triage-raterA.json \
  mythos=blind/56a31137/triage-raterA.json \
  control=blind/54287acd/triage-raterA.json \
  control=blind/060f94e3/triage-raterA.json \
  control=blind/992ae1bb/triage-raterA.json
```
