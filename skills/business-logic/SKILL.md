---
name: business-logic
description: Business-logic and authorization testing for a Mythos engagement with two or more authenticated principals - BOLA/IDOR via an owner/other/anonymous diff, BFLA, mass assignment via an OpenAPI request-vs-response schema diff, race conditions via sequential-vs-parallel waves, and workflow/price manipulation, each proven by an invariant violation. Use after auth-session has produced sessions for userA and userB, on APIs and multi-step flows (checkout, transfer, redeem, invite, approve).
---

# Business logic: prove the invariant breaks

Scanners cannot see these bugs: every request is well formed, only the
*principal* or the *order* is wrong. Method adapted from Strix's IDOR and
business-logic skills (usestrix/strix, Apache-2.0:
`strix/skills/vulnerabilities/idor.md`, `business_logic.md`); Auth Analyzer's
SAME/SIMILAR/DIFFERENT triage (PortSwigger/auth-analyzer).

Prerequisites: `scope.rules.allow_active`, sessions from **auth-session**
(`S=engagements/<dir>/sessions`, roles `userA`, `userB`, optionally `admin`),
recon's endpoint list or OpenAPI spec. Run `session_check.py` first. Output to
`engagements/<dir>/scan/`.

## 1. Build the Subject x Object x Action matrix

- **Subjects:** anon, userA, userB, admin (if any), plus tenant/org if multi-tenant.
- **Objects:** every resource type with an id (user, order, file, invoice,
  message, cart, api key). Collect *real* ids for each user from list, search,
  export and profile endpoints while logged in as that user.
- **Actions:** read, list, create, update, delete, and the workflow verbs
  (approve, refund, transfer, redeem, invite, export).

Write it as a table in `scan/matrix.md`: one row per (object, action), one
column per subject, cells = expected (allow/deny) from the app's own rules.
Every later test fills in "observed". A cell where observed != expected is a
candidate. The same table feeds the coverage matrix in **web-scan**.

## 2. BOLA / IDOR (horizontal), BFLA (vertical)

List A's object URLs, one per line (`URL` or `METHOD URL [JSON]`), then:

```
scripts/mythos python3 skills/business-logic/scripts/bola_diff.py --endpoints scan/ids-A.txt \
  --a $S/userA.headers --b $S/userB.headers --marker <A-only string, e.g. A's email> \
  --rps <scope rps> --out engagements/<dir>/scan/bola.jsonl
```

It sends each request as A (baseline), B and anon, classifies SAME/SIMILAR/
DIFFERENT and prints `candidate`/`enforced`/`review`. This is **triage**. For
BFLA, run the admin-only endpoints with `--a $S/admin.headers --b $S/userA.headers`.

Variations the script does not do, try them by hand on candidates and on
`review` rows: id in body vs path vs query, numeric neighbour vs UUID from a
leak, `/users/me` vs `/users/<id>`, older API version (`/v1/` vs `/v2/`),
other content type, other transport (REST vs GraphQL vs WebSocket). Strix
requires the same object to fall on **two transports** before you call it
systemic.

Write verbs (PUT/PATCH/DELETE, `--allow-write`) only on objects the agent
created with its own accounts (B's own test order, never a real user's).

False positives (Strix list): public-by-design data, idempotent metadata, an
empty 200 for another user's object (that is silent enforcement; compare with
the owner's view).

## 3. Mass assignment

```
scripts/mythos python3 skills/business-logic/scripts/mass_assign.py fields engagements/<dir>/recon/openapi.json
```

For each write operation it lists fields the resource returns but the request
schema does not declare (or marks `readOnly`), sensitive names first (`role`,
`isAdmin`, `balance`, `price`, `userId`, `tenantId`, `verified`). No spec: take
the fields from a GET response of the object, and use `arjun -m JSON` for
hidden ones. Then prove one on **your own** object:

```
scripts/mythos python3 skills/business-logic/scripts/mass_assign.py probe --headers $S/userA.headers \
  --method PUT --url <URL of A's object> --body '<normal body>' --field role=admin --get-url <same object>
```

`reproduced` = the confirming GET shows the injected value and the GET before
did not. A 200 on the write is not enough (many frameworks drop unknown fields
silently). Then show the effect: the new role reaches an admin function, the
new balance buys something.

## 4. Race conditions

Only on a **one-shot resource the agent created** (own coupon, own gift card,
own small balance, own invite), N <= 20, 2 repeats:

```
scripts/mythos python3 skills/business-logic/scripts/race.py --headers $S/userA.headers \
  --method POST --url <redeem URL> --data '{"code":"{{R}}"}' \
  --setup '<shell cmd that creates a fresh code and prints it>' \
  --success-regex '<what a success looks like>' --state-url <balance/usage URL> \
  --n 10 --repeats 2 --out engagements/<dir>/scan/race.jsonl
```

Each repeat runs a sequential wave (a correct app allows exactly 1) and a
parallel wave on a fresh resource. Engine: HTTP/2 single-packet via h2spacex if
installed and the target is https (Kettle 2023: 4-10x more effective than
last-byte sync), else the stdlib last-byte-sync threads. `reproduced` =
sequential 1 success, parallel > 1, in both repeats, **and** the authoritative
state (`state_before`/`state_after` in the JSONL) moved by more than one unit.
Simple cases can also use a nuclei template with `race: true` + `race_count`.
Never race a real user's resource or a payment that leaves the lab.

## 5. Workflow and price manipulation

Per workflow (signup, checkout, transfer, password reset, approval) write the
state machine, then: skip a step, repeat a step, reorder steps, change a value
after it was validated (price, quantity, currency, recipient), send negative /
zero / fractional / huge quantities and a client-supplied price on a cart the
agent owns. Success criterion is the **server-computed** total or ledger, never
the 200 or the UI.

## Proof standard (all classes)

A business-logic finding is `validated` only with:

1. **Invariant named:** "user can only read own orders", "one redemption per
   code", "balance never negative".
2. **Baseline vs abuse, same principal:** the intended flow and the abused flow
   side by side (for BOLA: owner request/response and other-user request/response).
3. **Negative control:** the same request properly denied (B on an object that
   is enforced, or the sequential wave).
4. **Durable state** read back from the authoritative source (GET of the
   object, ledger, admin view), not the write response.
5. **Quantified impact:** how many objects, how much money, which role.

Without all five it stays `candidate` or `reproduced`. Hand candidates to
**exploit**, which records closure state and runs the validator pass.
