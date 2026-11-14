# Open defects as of 14 November 2026

> **Working notes, not documentation.** Written at the end of the session that
> found these, so the next one starts from evidence rather than rediscovering
> them. Each entry has a reproduction.

## 1. `scripts/traffic exec` records nothing inside a benchmark cell

**Status:** FIXED 14 November 2026. Cause confirmed, not guessed: every Bash
tool call is a fresh shell, so the `export MYTHOS_SCOPE` made when the recorder
was started is gone by the next call, and `engagement()` resolved only from
`--dir` or that variable. The ten `exec` calls and nine `summary` calls were
all exiting with "no engagement". `scripts/traffic` now reads the same
`.mythos-scope` pin file the guards read, under both roots. Verified by
reproducing the failure in a fresh shell with the variable unset: `start`,
`exec` and `summary` now resolve the engagement and the request is recorded.

**What happens.** In three measured cells the agent started the recorder
correctly (`traffic/proxy.json`, `ca.crt` and `events.jsonl` are all written),
then ran `scripts/traffic exec` ten times and `scripts/traffic summary` nine
times. No `traffic/log.jsonl` was ever created, so not one exchange was
recorded. The nine summary calls are the agent checking, finding nothing and
retrying: it used the tool correctly and the tool did not record.

**Where it is not reproducible.** Outside a cell it works. With `MYTHOS_SCOPE`
pointing at a scope file in a temporary directory:

```bash
python3 scripts/traffic start
python3 scripts/traffic exec -- curl -sS http://172.17.0.1:5003/   # http 200
wc -l $D/traffic/log.jsonl                                         # 1
python3 scripts/traffic summary                                    # 1 recorded, capture complete
```

**The likely cause, not yet confirmed.** `start` resolves its directory from
the active scope and creates the proxy there. `exec` resolves independently, and
in a cell the agent's later shells do not carry `MYTHOS_SCOPE`, so `exec` can
resolve a different directory and set the proxy variables for a proxy that is
not the one running. The scope pin fixed the same class of problem for the
hooks; `scripts/traffic` has not been given it.

**What to do.** Give `scripts/traffic` the same pin resolution the guards now
use (`_pinned_scope`, both roots), and have `exec` fail loudly when the
directory it resolved holds no running proxy, instead of silently setting
variables for nothing. Then re-run the gate test.

**Why it matters beyond the recorder.** The gate can only require evidence of a
request where a traffic record exists. Without one it falls back to searching
the report for the path's name, which a run satisfies by listing the paths it
did not test. That fallback is why the "all mapped paths accounted for" claim
was withdrawn.

## 1a. The proxy still records nothing in a cell, for a reason not yet found

**Status:** open, narrowed.

With the pin fix in place the resolution failure is gone: `traffic exec` went
from ten calls (each exiting "no engagement", hence the retries) to two, and
`proxy.json`, `ca.crt` and `events.jsonl` are all written. Still no
`log.jsonl`, and `proxy.err` is empty, which is itself a signal: a refused or
failed exchange should leave something there.

Outside a cell the same sequence records correctly, including logging a request
that failed before a response. So what differs is inside the cell, and the
remaining candidates are the proxy's bind and client-address rules against a
target on the docker bridge gateway rather than loopback, and whether the
agent's requests went through the environment at all. Diagnosing it needs the
proxy's own view, which currently writes nothing when it declines a connection.

**What to do first.** Make the proxy log every connection it declines and why,
before guessing again. The absence of a log line is the only clue there is.

## 1c. Four nominally identical cells spanned 144 to 389 seconds and 33 to 851 report lines

**Status:** a measurement property, not a bug, and the reason the
early-termination hypothesis stays untested.

Same scaffolding, same target, same model, same 900 second budget, four cells:

| cell | wall clock | tool calls | report |
|---|---|---|---|
| 1 | 144 s | 23 | 33 lines |
| 2 | 172 s | 26 | — |
| 3 | 195 s | 25 | — |
| 4 | 389 s | 39 | 851 lines |

A single cell therefore cannot test whether a mechanism changed the agent's
persistence, and the fourth cell was nearly read as confirmation of the
evidence-based gate when that gate had no evidence to work with in any of the
four. Testing the hypothesis needs repeats per condition, which is the same
lesson the published variance figures of 2.2 to 6.0 points already carry: more
cells beat more cleverness.

## 1b. The recorder leaks a process and a CA directory per engagement

**Status:** open, and it compounds defect 1.

Three `scripts/traffic serve` processes were still running at the end of the
session, one per gate test, each holding a port and a `/tmp/mythos-ca-*`
directory containing a per-run TLS signing key. Nothing stops them: the agent
is told to start the recorder and never told to stop it, and the harness does
not tear it down when a cell ends.

Two consequences. A long-lived process holding a signing key is a worse leak
than an idle port. And several proxies bound to the same addresses on different
ports make it harder to establish which one a later `traffic exec` should be
talking to, which is exactly the territory of defect 1.

**What to do.** `start` should refuse or adopt when a proxy for that engagement
is already running, the harness should stop it when a cell ends, and `stop`
should remove the CA directory. `stop` already cleans up after a crashed
proxy; nothing calls it.

**A warning for whoever cleans these up.** `pkill -f "scripts/traffic serve"`
matches the shell running that very command and kills it. Match on the full
argument form instead, for example `ps -eo pid,args | grep -E 'traffic[ ]serve
--dir'`.

## 2. The recorder is started by the agent, which is the wrong layer

Both `engagement-setup` and the orchestrator ask the agent to run
`scripts/traffic start`. The agent complied in all three cells, so adherence is
not the problem here. It is still the wrong layer: a record that the engagement
depends on should not be optional on the model's cooperation, and the
literature on prompt-stated rules is clear that compliance is high but never
total (anti-cheat prompts cut cheating from 33.0% to 18.6% and to 8.5% under a
severe formulation, with 8 of 22 models still cheating).

`scripts/mythos` already wraps every container tool and could start the
recorder on first use, the way it starts the toolbox. That change makes the
record a property of the harness rather than a request to the agent.

## 3. The coverage gate stops nudging after three turns while work remains

`MAX_NUDGES = 3` in `hooks/coverage-gate.py`. In the measured cells the gate
nudged twice and the agent finished with open items anyway: the last run ended
at 195 seconds of a 900 second budget with 6 of 73 paths unaccounted for and a
parameter open.

The cap exists so that a surface the agent genuinely cannot reach does not trap
it in a loop, which is a real risk and the reason not to simply raise the
number. What is missing is a distinction between "cannot reach this" and "has
not tried this", and defect 1 is what would supply it: a path with no recorded
request has not been tried.

## 4. Early termination is the binding constraint, and it is unmeasured

Across the main sweep no cell hit its budget. On Vuln Bank, with 76 documented
vulnerabilities of which about a third were found, the bare control stopped
after 75 seconds of 1200 and the scaffolded arm after 270. Both believed they
were finished with three quarters of the budget unspent.

This is the most promising target for the next round of work, ahead of more
playbooks, and it is also the hypothesis this session failed to test: three
attempts, each blocked by a different defect above, in a chain where every link
had to work and one was broken each time.
