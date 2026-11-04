# Race Conditions (limit overrun, TOCTOU)

**Class:** business logic  **Updated:** 2026-11-04

## What it is
A check and the state change it guards are not atomic, so requests that arrive
together all pass the check: a coupon redeemed twice, a balance spent twice, a
rate limit or invite quota exceeded. Most common on redeem, transfer, vote,
signup-bonus and "one per user" endpoints.

## How Mythos detects it
- `skills/business-logic/scripts/race.py`: sequential wave vs parallel wave on a
  fresh one-shot resource, N <= 20, 2 repeats; HTTP/2 single-packet via
  h2spacex when installed (not in the image), else stdlib last-byte sync.
- Single-packet attack (Kettle, BH USA 2023): many HTTP/2 requests completed in
  one TCP packet arrive together regardless of jitter; reported 4-10x more
  effective than last-byte sync, ~20-30 requests per packet (~1,500 bytes).
- nuclei `race: true` + `race_count: N` for simple cases (whether it uses
  single-packet is undocumented).

## How to confirm (non-destructive)
Only on a resource the agent created. Proof = sequential wave 1 success,
parallel wave > 1 success, in both repeats, and the authoritative state
(balance, usage count) read back moved by more than one unit.

## Remediation
Make check-and-update atomic: DB transaction with row lock or a conditional
update (`UPDATE ... WHERE used = false`), unique constraints, idempotency keys.

## Sources
- PortSwigger Research, "Smashing the state machine" (2023-08)
- nxenon/h2spacex README (2026-10)
- ProjectDiscovery nuclei docs, HTTP race conditions (2026-10)
