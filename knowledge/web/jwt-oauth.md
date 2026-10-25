# JWT / OAuth / Session

**Class:** authentication  **Updated:** 2026-10-25

## How Mythos detects it
- Engine: captures JWT-shaped tokens from traffic; checks `alg:none` acceptance and cracks HS256 against a weak-secret list.
- Tools: `jwt_tool` for alg confusion (RS256→HS256), `kid` injection, and exp/nbf handling.

## How to confirm (non-destructive)
Forge a token with a benign claim change (e.g. a harmless attribute) and show it is accepted; do not escalate to another real user's data beyond proof.

## Remediation
Pin the expected algorithm; reject `none`; use a long random HMAC secret or proper asymmetric keys; validate `kid`, `iss`, `aud`, `exp`.

## Sources
- RFC 8725 (JWT BCP); PortSwigger — JWT attacks (2026-10).
