# crAPI BOLA — CONFIRMED end-to-end (two-account method)

Autonomous chain via `scripts/eval/crapi_bola.py` + `mythos.scan.bola`:

1. Registered two users (alice, bob) on crAPI identity.
2. Completed vehicle onboarding by reading each user's VIN + pincode from the
   HTML welcome email in MailHog (quoted-printable decoded, tags stripped).
3. Enumerated alice's vehicle UUID via `/identity/api/v2/vehicle/vehicles`.
4. As **bob**, requested **alice's** vehicle location
   `GET /identity/api/v2/vehicle/{alice_uuid}/location`.

**Result: BOLA CONFIRMED (HIGH, certain)** — bob received alice's vehicle
location (content match 100%): a user reading another user's object with no
object-level authorization. This is crAPI's signature Broken Object Level
Authorization vulnerability, found by the framework's two-account BOLA check.
