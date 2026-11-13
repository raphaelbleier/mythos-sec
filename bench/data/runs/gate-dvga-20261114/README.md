# Coverage gate on DVGA, 14 November 2026

The first measurement run after the harness audit of 13 November 2026, and the
first time this project has produced a precision figure or a second rater.

The question: does the coverage gate (`hooks/coverage-gate.py`, a Stop hook
that hands back mapped paths the report does not account for) change how many
of a target's documented vulnerabilities the framework finds?

## Design

Four cells on the Claude Code host, `claude_mythos` arm, DVGA, Claude Sonnet,
600 s budget each. Two with the gate wired, two without, switched by the
presence of `coverage-gate.py` in `hooks/hooks.json` and recorded per cell as
`treatment.coverage_gate`. `coverage_gate_effective` is also recorded, because
the gate is a Claude Code Stop hook and cannot fire on the OpenCode host at all.

Pairing is on each of DVGA's 21 scored ground-truth entries, not on the target.
Pairing per target gave four units and a minimum detectable difference of
0.293, against a scaffold effect the literature puts at 5 to 10 points. 21
entries is still only one cluster, so the McNemar p below treats entries as
independent, which they are not: entries behind one unreached surface fail
together. No clustered interval is possible from a single target.

Rating was blinded. `bench/labs.py seal` redacted arm tokens and renamed each
run to a hash; the mapping is in `sealed-map.json`. Two independent raters on
different models filled `triage-raterA.json` and `triage-raterB.json` against
`bench/data/triage-rubric.md`, neither seeing the other's file, the sealed map,
the run records or the transcripts.

## Result

| rater | recall gate off | recall gate on | discordant | McNemar exact p |
|---|---|---|---|---|
| A | 0.48 | 0.19 | 6 : 0 | 0.0312 |
| B | 0.57 | 0.29 | 7 : 1 | 0.0703 |

Both raters put the gate-off arm ahead. The direction is the opposite of the
separation this project previously published on Vuln Bank, which is withdrawn
pending re-measurement.

Per-run, the three substantive cells:

| blind id | arm | recall A | recall B | precision A | precision B | kappa |
|---|---|---|---|---|---|---|
| c42164fd | gate on, run 1 | 0.00 | 0.00 | refused | refused | 1.000 |
| 9e7b89f7 | gate on, run 2 | 0.19 | 0.29 | 0.82 | 0.92 | 0.741 |
| f1af439f | gate off, run 11 | 0.29 | 0.43 | 0.80 | 1.00 | 0.696 |
| e00db9c0 | gate off, run 12 | 0.29 | 0.29 | 0.89 | 1.00 | 0.767 |

Precision is between 0.80 and 1.00 depending on the rater, with six false
positives found between them. The 1.00 this project published before 13
November was an artifact of a triage schema in which no row could be a false
positive.

## What this does not establish

The result is not strong enough to claim the gate hurts.

- **One target, 21 entries, one cluster.** The minimum detectable difference at
  21 pairs is 0.30. The observed gap is at that boundary, and the entries are
  not independent.
- **The two raters disagree across the 0.05 line**, 0.0312 against 0.0703, on
  identical reports under one rubric. Cohen's kappa is 0.70 to 0.77 on the
  three substantive cells, which Landis and Koch call substantial and which is
  not high enough for a result that turns on six discordant pairs. The
  measurement is rater-sensitive, and that is itself a finding.
- **One gate-on cell is degenerate.** `c42164fd` produced a 363-byte fragment
  of mid-engagement narration with no finding, request or response, and recall
  0.00 under both raters. Excluding it changes nothing in the any-run reading,
  because it contributed no findings, so the result is not an artifact of it.
  But a 25% cell failure rate in one arm is a harness problem, not a treatment
  effect, and it needs explaining before the comparison is repeated.
- **Two repeats per arm.** Run-to-run variance on agentic tasks is measured at
  2.2 to 6.0 points elsewhere, so two runs cannot separate the treatment from
  the noise.
- **DVGA is the target where the gate previously inverted**, because the
  surface map was eleven HTML pages while the application sits behind
  `/graphql`. The probe now enumerates the schema (19 operations), which is why
  this re-measurement was worth doing, but it also means this target is the
  least representative one for the gate.
- **The rubric has gaps both raters hit independently**: whether a bounded
  denial-of-service query counts as proof, which conflicts with the ground
  truth's own `dos_rule`; how to rate a finding that is real, inside the
  documented list, and honestly hedged; and whether one request proving two
  entries is one reported row or two. Their divergence concentrates there.

## Files

- `sealed-map.json`: blind id to arm, with the per-cell treatment record.
- `blind/<id>/report.txt`: the redacted report the raters saw.
- `blind/<id>/triage-raterA.json`, `triage-raterB.json`: the two ratings.
- `blind/<id>/meta.json`: the blind id and the report hash.
- `run*/result.json`: the per-cell run record, including readable roots, host
  versions, resolved models, repo commit and the treatment flags.
- `run*/scope.yaml`: the scope each cell was given.

Transcripts are not committed. They contain created credentials and target
data. `bench/METHODOLOGY.md` states the policy.

Reproduce the analysis:

```bash
python3 bench/stats.py --vuln \
  gate_on=blind/c42164fd/triage-raterA.json \
  gate_on=blind/9e7b89f7/triage-raterA.json \
  gate_off=blind/f1af439f/triage-raterA.json \
  gate_off=blind/e00db9c0/triage-raterA.json
```
