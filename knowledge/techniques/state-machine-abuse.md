# State-machine abuse: skip, repeat, reorder, replay

**Class:** methodology / business logic  **Updated:** 2026-11-13

## What it is
Any multi-step flow (signup and verify, password reset, 2FA, checkout,
transfer, refund, invite, approval, trial, KYC, import) is a state machine
that the server must enforce at every transition. Developers test the happy
path; the bugs sit in transitions the UI never sends. This note generalizes
`web/race-conditions.md`, `web/auth-flows-ato.md` and the workflow part of
`skills/business-logic` into one method. Kettle's "Smashing the state
machine" (PortSwigger Top 10 2023, #1) argues that a request can also land
in a hidden sub-state that exists only for milliseconds, which is the
parallel move below.

## Method
1. **Draw the machine from recorded traffic**, one line per flow, with the
   guard on each arrow and where the state lives:
   ```
   cart --[items valid]--> address --[address saved]--> quote(price locked?) --[paid=true in DB]--> confirm --> fulfilled
   ```
   For every transition write the **guard** (what the server must check:
   previous step done, token matches user, amount equals quote) and the
   **carrier** (server session, DB row, signed token, or the client: hidden
   field, `step=3`, `status=paid`, price, cookie, JWT claim). Client-carried
   state is tamperable by definition.
2. **Pick the invariant** the flow protects ("a fulfilled order is paid",
   "one redemption per code", "no login without the second factor").
3. **Apply the moves to every arrow**, one at a time:

| move | request | invariant it tests |
|---|---|---|
| skip | call step N+2 directly with a valid session and no step N+1 | steps cannot be bypassed |
| repeat | send step N twice, sequentially, then with the same idempotency key | one-shot actions are one-shot |
| reorder | confirm before pay, apply coupon after price lock, change address after quote, verify email after changing it | later steps cannot precede earlier ones |
| replay | reuse an earlier token, callback or webhook (your own captured one), or another run's token in this run | tokens are single-use and bound to flow and user |
| tamper carrier | edit `step`, `status`, `price`, `currency`, `recipient` after validation | the server does not trust client state |
| cross-flow | start flow X, finish with flow Y's token; mix two sessions | tokens are bound to their flow |
| parallel | the same step N times at once | check and update are atomic; method in `web/race-conditions.md` (single-packet) |

4. **Add the exit states.** Cancel after confirm; refund twice; refund after
   partial use; downgrade after upgrade while keeping features; reactivate an
   expired trial; remove an item after discount thresholds were applied.
   Exits are where ledgers drift.
5. **Read the authoritative state** after every abuse run (order status,
   ledger, entitlement, session privilege), not the response of the abused
   step.

## Concrete shapes
```
# skip: straight to fulfilment on an order that was never paid (own order, sandbox)
POST /api/orders/{id}/confirm        # compare order.status with the paid path
# repeat: same one-shot action again
POST /api/redeem {"code":"MYTHOS-1"} ; POST /api/redeem {"code":"MYTHOS-1"}
# reorder / tamper: change value after validation
PUT /api/cart {"items":[...]} ; POST /api/pay {"orderId":..., "amount":0.01}
# replay: an already-used reset or verification token, a previously captured
# payment-success callback for your own order
```
For 2FA, reset and verification specifics see `web/auth-flows-ato.md`.

## How to confirm (non-destructive)
- Only flows the agent owns, on objects it created, with the agent's own
  accounts. Money flows only in a sandbox or test mode; if a flow moves real
  money or sends real messages, stop and ask.
- Use the smallest effect that shows the invariant broke: an order of one
  cent in the test mode, an own coupon, an own invite.
- Baseline: the intended flow completed once, state recorded. Abuse: one move,
  one flow. Control: the same abuse where the guard works (a different step in
  the same flow, or the sequential wave for a race).
- Proof is `skills/business-logic`'s five points: invariant, baseline vs
  abuse, negative control, durable server state, quantified impact.

## What does not count as proof
The UI showing a later step; a `200` on the skipped call with the state
unchanged; a client-side skip that the server rejects on the last step;
a status label the product itself defines as pending; a replay that returns the first result
idempotently without a second effect.

## Remediation
Keep state on the server and check the previous state in each handler; bind
tokens to user, flow and purpose; make one-shot transitions atomic and
idempotent; recompute server-side values (price, total, recipient) at the
final step; reject transitions that are not edges of the declared machine.

## Sources
- Kettle, "Smashing the state machine: the true potential of web race
  conditions", PortSwigger Research (2023-08); Top 10 Web Hacking Techniques
  of 2023, #1 (published 2024-02-19)
- OWASP WSTG-BUSL (business logic testing); OWASP API6:2023 Unrestricted
  Access to Sensitive Business Flows
