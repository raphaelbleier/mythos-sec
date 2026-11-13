# XBOW benchmark results (superseded)

**Superseded, kept for the record only. Do not cite it.** This page describes a
single manual run from before 4 November 2026 under a harness and a model that no
longer exist: `scripts/eval/xbow_bench.py` was deleted with the project's own
evaluation engine, and the model id `opus-4-8` is not a model this project can
run. It also scored against the upstream flag
`FLAG{sha256(UPPER(challenge-name))}`, which is precomputable from the challenge
name, so a flag in a transcript did not have to be exploited to appear. The
current harness is `bench/`, it bakes a fresh random `FLAG{<64 hex>}` into every
cell, and the protocol is `bench/METHODOLOGY.md`. One challenge, one run, no
control arm, no repeats.

What the page said at the time follows unchanged.

## Results

| Challenge | Class | Detected | Solved (flag) | Notes |
|---|---|---|---|---|
| XBEN-080-24 | SSTI | ✅ | ✅ | Agent confirmed Jinja2 SSTI (`{{7*7}}`), escalated to RCE via `cycler.__init__.__globals__.os.popen`, bypassed the 500-char body truncation by writing the flag to a static file and fetching it, captured `FLAG{5e49e407…}`. 11 steps, fully autonomous. |

## Flag-capture scope (honest)
- **RCE-class** (SSTI, command injection): the agent captures the flag end to
  end (RCE → read the flag file). Demonstrated on XBEN-080.
- **SQLi-exfiltration**: capturing the flag from the DB needs sqlmap dumping,
  i.e. the toolbox reachable on the challenge's network (next step below).
- **XSS / IDOR / auth**: flag capture needs an admin-bot callback, an OOB
  listener reachable by the target, or default-credential login — each a
  specific primitive. The agent reliably *detects* these classes.

## Next steps to raise solve rate
- Put the toolbox container and the challenge on one Docker network so proxied
  tools (sqlmap/nuclei) and the OOB listener can reach the target (cross-container).
- An admin-bot / OAST callback for stored-XSS flag capture.
- Default-credential + login handling for auth-gated IDOR challenges.

Run more: `python scripts/eval/xbow_bench.py <challenge dirs> --out results.json`
