# Webhooks (receiver verification and sender SSRF)

**Class:** server-side / integrity  **Updated:** 2026-11-13

## What it is
Two attack surfaces. Receiver side: the target exposes an endpoint that a
provider (payments, git host, chat, CRM) calls with a signed event; if the
signature, timestamp or event id is not enforced, an attacker can forge or
replay events (fake `payment_succeeded`, fake `member_added`). Sender side:
the target lets a user register a webhook URL and then makes the request
itself, which is an SSRF sink (`knowledge/web/ssrf.md`).

## How Mythos detects it
- Receiver: find `/webhook`, `/webhooks/<provider>`, `/hooks`, `/api/events`,
  `/callback` in recon, JS and docs; note the provider from header names
  (`Stripe-Signature`, `X-Hub-Signature-256`, `X-Slack-Signature`,
  `X-GitHub-Delivery`).
- Sender: any "add webhook / callback URL / notification URL" feature.

## How to confirm (non-destructive): receiver
Use only an endpoint tied to a test account/tenant of the agent, and a benign
event type with no money or data effect (a ping or a test event). Send:

```
1. unsigned:        POST /webhooks/x  (no signature header)           -> expect 401/400
2. wrong signature: header present, HMAC with a random key            -> expect 401/400
3. empty secret:    HMAC-SHA256 over the body with key ""             -> expect 401/400
4. replay:          the exact genuine delivery, sent again           -> expect rejected or deduplicated
5. stale timestamp: provider timestamp 1 day old, re-signed only if you hold the secret -> expect rejected
6. same event id, changed body (signed with a key you own)            -> expect deduplicated, not reprocessed
```

Oracle: a differential in durable state the agent can read (an event log, a
test-mode order or status field, an audit entry), not the HTTP status. Step 1
or 2 returning 200 is only a candidate: many receivers return 200 to every
call and drop the event silently. Confirm with the state change on the
agent's own test object, then the negative control (the same request with an
invalid signature must NOT change it, and a request with a valid one must).
Empty-secret signing matters when the secret comes from an unset environment
variable. Replay proof = the second identical delivery changes state a second
time (counter, credit, email). Signature comparison with `==` is a timing
side channel; do not attempt to exploit it over the network, report the code
pattern only when source is visible. Reference: the Ruby `pay` gem Paddle
Billing verifier compared the HMAC with `String#==`, GHSA-mjgf-xj26-9qf9
(CVSS 7.4, CWE-208, published 2026-07-01, versions up to 11.6.1).

## How to confirm (non-destructive): sender
Register a webhook URL that points at your own OAST host and trigger a test
delivery; the hit confirms an outbound request. Then test redirect handling
(your OAST host answers 302 to a second OAST path), a hostname that resolves
to a private range you control for DNS-rebinding style checks, and the scheme
and port allowed. All SSRF bypass lists, redirect-loop and cloud metadata
reality are in `knowledge/web/ssrf.md`; the delivery body, headers and
retries are also attacker-visible data: record what the sender discloses
(internal hostnames in headers, auth tokens in the signature header).

## Proof standard
Receiver: state change on the agent's own object from an unsigned, replayed or
stale delivery, with the invalid-signature negative control refused.
Sender: an OAST hit carrying a per-registration nonce in the path, plus the
SSRF note's proof for any internal target. Closure states per
`skills/exploit/SKILL.md`.

Does NOT count: a 200 from an endpoint that ignores the body; a signature that
is verified but whose secret you do not hold (nothing to forge); replaying
events that move real money; any request that triggers a third party's real
account.

## Remediation
Verify an HMAC over the raw body with a constant-time compare, reject a
missing/empty secret at startup, enforce a timestamp tolerance, store and
deduplicate event ids, and for sender features resolve and validate the
destination at connect time with no redirect following.

## Sources
- GitHub Docs, "Validating webhook deliveries" (accessed 2026-11-13):
  `X-Hub-Signature-256`, HMAC-SHA256, constant-time comparison advised.
- Stripe Docs, "Webhooks" (accessed 2026-11-13): timestamp inside the signed
  `Stripe-Signature` payload against replay; process event ids to deduplicate.
- GitLab Advisory Database, GHSA-mjgf-xj26-9qf9 (`pay` gem, 2026-07-01).
