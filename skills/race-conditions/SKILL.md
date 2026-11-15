---
name: race-conditions
description: Race conditions for a Mythos engagement - limit overrun on a once-only action (coupon, invite, withdrawal, MFA attempt counter), the HTTP/2 single-packet attack, and TOCTOU on a two-step flow - each measured as a hit rate over repeats with a Wilson interval, against a sequential control that must not overrun, judged by the authoritative state read back as the object's owner. Use when the surface shows a redeem, coupon, invite, vote, transfer, withdraw, confirm or two-step approve route, on objects the agent created itself. Never on another user's object and never on a destructive action.
---

# Race conditions: one success is not a finding

A check and the state change it guards are not atomic, so requests that arrive
together all pass the check. That part is easy. The hard part is that a race is
**stochastic**: the same burst against the same endpoint overruns sometimes and
not others, the response bodies lie in both directions (200 without a write,
409 after one), and a tester who stops at the first double-success reports noise
as a finding roughly as often as not.

So this skill is mostly about the measurement, and `scripts/race` encodes it
rather than asking you to remember it:

* the oracle is the **authoritative endpoint read back as the owner**, before
  and after every wave. A racing response body is never evidence.
* a **sequential control** of the same N requests runs for every repeat and
  must let exactly one through. If it overruns, the endpoint was never
  once-only and nothing can be attributed to concurrency.
* the result is a **hit rate over whole repeats** with Wilson and
  Clopper-Pearson intervals. `candidate` requires the parallel arm's 95% lower
  bound to clear the control's 95% upper bound. 6/6 against 0/6 clears it;
  3/3 against 0/3 does not and comes back `inconclusive`, which is a result and
  goes in the report as one.
* this script never writes `confirmed`, and never writes `candidate` into a
  finding either. It prints a verdict and records the bytes; the validate phase
  replays them on another model.

Read `knowledge/web/race-conditions.md` before step 2: it carries the
single-packet mechanics, the statistics rule and the sources.

## Preconditions, and what is refused

* Sessions from **auth-session**: the burst goes out as *your* identity, and
  the read-back must be done as the owner or it proves nothing about whose
  state moved.
* An object **you own**. `scripts/race` reads `--owner-url` as the owner before
  every wave and refuses when the object id is not in what comes back. There is
  no flag for this.
* A **non-destructive** action, unless the object was minted by this
  invocation through `--setup-url`. A destructive verb (delete, cancel, revoke,
  refund, transfer-out…) on an `--object` that predates the run is refused, and
  data destruction, brute force and denial of service are refused in every
  mode by `hooks/budget-guard.py`.
* `scope.yaml` names the host. A scope warning arrives after a burst has
  landed, so here it is a refusal.
* **Load.** A race is load by nature. With the defaults (`--n 8`,
  `--repeats 6`) one subcommand sends 132 requests, of which 48 arrive in six
  bursts of 8. The sequential control, the setups and the read-backs honour
  `rules.rate_limit_rps`; the parallel burst is bounded by N and by nothing
  else, because arriving together is the experiment. N is 2..20 by default;
  `MYTHOS_RACE_MAX_N` raises the ceiling to at most 50 for a lab you own. If
  the programme's rules do not permit a burst of N, do not run this and record
  `skipped` with that reason.

## 1. Find the aim points, and the counter that proves them

From `surface.json` and the app's own flows, list the actions that may succeed
**once**: redeem, claim, invite, vote, withdraw, apply-coupon, signup-bonus,
confirm, approve, and any MFA or rate-limit attempt counter. For each one write
down three things in `scan/race-aim.md`:

1. the action request (method, URL, body), with `{{R}}` where the object id goes;
2. the endpoint that **mints a fresh object** of that kind, and the field of its
   answer that carries the new id;
3. the **authoritative counter**: an endpoint that states the balance, the
   redemption count or the usage count, and a regex whose group 1 is the number.

Without the third one there is nothing to measure and the aim point is
`skipped`, not tested. An action whose effect is only visible in its own
response cannot be proven here.

## 2. Limit overrun, with the control

    scripts/race limit --url http://t/redeem --method POST --data '{"code":"{{R}}"}' \
      --setup-url http://t/coupon/new --setup-field code \
      --owner-url http://t/mine \
      --state-url http://t/balance --count-regex '"redemptions":\s*(\d+)' \
      --header 'Authorization: Bearer <own token>' \
      --n 8 --repeats 6 --dir engagements/<dir> --json

Per repeat it mints a fresh object, proves you own it, reads the counter, runs
the sequential control, then does the same again for the parallel wave. Flags
worth knowing: `--engine h1|h2|auto`, `--unit` (how far the counter may
legitimately move in one wave, default 1), `--success-regex` and
`--success-status` (diagnostics only — they never decide the verdict),
`--object` instead of `--setup-url` for a counter that resets rather than an
object that is consumed, `--rate`, `--timeout`, `--insecure`.

Exit codes: `0` candidate, `1` no-signal, `2` usage, `3` inconclusive,
`4` refused.

## 3. The single-packet attack

Last-byte sync still sends N segments that cross the network independently, so
jitter staggers them. The single-packet attack puts the final frame of every
request in one TCP segment, so the server sees them all within one read:

    scripts/race single-packet --url https://t/redeem --data '{"code":"{{R}}"}' \
      --setup-url https://t/coupon/new --setup-field code \
      --owner-url https://t/mine \
      --state-url https://t/balance --count-regex '"redemptions":\s*(\d+)' \
      --header 'Authorization: Bearer <own token>' \
      --n 20 --repeats 6 --insecure --dir engagements/<dir> --json

Identical protocol to `limit`; only the parallel wave differs. It needs ALPN
`h2` over TLS and falls back to HTTP/1.1 last-byte sync when the URL is not
https, when the peer negotiates something else, or when the peer's
`MAX_CONCURRENT_STREAMS` is below N. **Read `sync_mode` in the output**: a
`no-signal` under `h1-last-byte-sync` is much weaker than one under
`h2-single-packet`, and `fell_back_from_h2` says why it fell back. `--settle-ms`
is the pause between parking the streams and releasing them (default 120).

## 4. TOCTOU on a two-step flow

Confirm-then-use, check-then-write, reserve-then-charge: step one leaves the
object in a state step two consumes, and the gap is the window.

    scripts/race toctou --first http://t/order/confirm --first-data '{"id":"{{R}}"}' \
      --second http://t/order/use --data '{"id":"{{R}}"}' --gap-ms 0 \
      --setup-url http://t/order/new --setup-field id \
      --owner-url http://t/mine \
      --state-url http://t/balance --count-regex '"uses":\s*(\d+)' \
      --header 'Authorization: Bearer <own token>' \
      --n 8 --repeats 6 --dir engagements/<dir> --json

`--first` goes out once per wave, then the burst of `--second` after
`--gap-ms`. Sweep the gap: `0`, `20`, `100`, `250`. A window that only opens at
one gap size is still a window, and the gap that found it belongs in the
finding.

## 5. Write it up, or write down that it did not hold

A `candidate` goes in `candidates/<id>.md` with:

* the verdict and the **interval**, not the fraction: "6/6 repeats overran,
  95% CI 61%–100%, control 0/6, exact upper bound 46%";
* the sync mode that produced it, and the fallback reason if there was one;
* the counter that moved, the endpoint it was read from, and that it was read
  as the owner;
* the `traffic/<id>` of the parallel burst **and** of the sequential control.
  `scripts/traffic show <id>` prints the bytes and `scripts/traffic replay <id>`
  resends them, which is what the validator does. For a single-packet wave the
  whole connection is one record, preface included, so a replay re-runs the
  whole burst.

`inconclusive` and `no-signal` are results. Write them down with the N, the
repeats and the mode that ran, and say what would change the answer (more
repeats, a wider N, h2 instead of h1, a different gap). "Did not reproduce at
N=8 over 6 repeats under last-byte sync" is worth far more to the next run than
silence.

## Checks before you move on

- [ ] every aim point either has a verdict or a `skipped` with a reason
- [ ] no verdict rests on a racing response body
- [ ] every `candidate` has a clean sequential control in the same run
- [ ] every rate is reported as an interval
- [ ] `sync_mode` is stated next to every verdict
- [ ] every object raced was one you own, and no destructive action was raced
- [ ] `scripts/race selftest` passes (it asserts the HPACK and frame bytes and
      runs the whole protocol against a loopback server with a real race window)
