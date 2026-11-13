# MCP Security (remote MCP endpoints, OAuth proxies, tool metadata)

**Class:** AI application / auth / SSRF  **Updated:** 2026-11-13

## Scope
A remote MCP endpoint, its OAuth proxy or its authorization server is a web
target when the programme lists it. Testing a user's local IDE client, rug
pulls against it, or `npx` startup commands on someone's machine is out of
scope here; so is anything touching an account you did not create.
Spec read: MCP specification, draft revision, "Security Best Practices"
(fetched 2026-11-13). The 2025-11-25 revision differs, notably session
hijacking became "state handle hijacking" in the draft.

## How Mythos detects it
Fingerprint: `/.well-known/oauth-protected-resource`,
`/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`,
`/mcp`, `/sse`, a 401 with `WWW-Authenticate: Bearer resource_metadata=...`.
OAuth mechanics (PKCE, redirect_uri, state) are in `jwt-oauth.md`. Read the metadata documents first; they tell you proxy vs native auth server,
DCR (`registration_endpoint`), CIMD support, `scopes_supported`.

## Attacks from the spec page, with a non-destructive probe each
| attack | probe on your own accounts and your own OAST host | oracle |
|---|---|---|
| confused deputy in an OAuth proxy (static client_id, DCR, consent cookie) | register a client via DCR with `redirect_uri` on your OAST host; with a session that already consented once, open `/authorize` for the new client | code or redirect reaches your host with no consent screen; control: first-time client shows consent |
| token passthrough, no audience check | present a token issued for a different resource you control to the MCP server | server accepts it; control: token with right `aud` works, a malformed one fails |
| SSRF in OAuth discovery (client side) | only for MCP clients you operate; a metadata URL pointing to `http://169.254.169.254/` or your OAST host, redirects and DNS rebinding variants | OAST hit from the client; internal reach needs `ssrf.md` cloud rules |
| SSRF in the authorization server via Client ID Metadata Documents | `client_id=https://<your-oast>/<nonce>.json` | OAST hit from the AS; then a redirect from it to an internal URL |
| state handle hijacking | A mints a handle (cart or workflow id), B's token replays it | B reads or changes A's state; control: A's own call works |
| malicious authorization URL (`javascript:`) | only against a client you run, with a metadata field set to a `javascript:` URL carrying a canary | canary executes; client-side target, see `client-side-dom.md` |
| mix-up | AS A (yours) returns another honest AS's code; PKCE does not stop it because the verifier goes to the attacker's token endpoint | code accepted at the wrong token endpoint; absence of `iss` validation |
| localhost redirect impersonation | a native client using a CIMD with a `localhost` redirect: another local process on a free port receives the code | your own process receives the code; consent screen shows only the legit client name |
| scope inflation | read `scopes_supported`; request all; check the token carries wildcard or omnibus scopes and that tools enforce per-tool scope | token authorises tools beyond the consented operation |

The spec's own text: PKCE alone does not prevent mix-up; exact-match
`redirect_uri` is required; the consent cookie must bind to `client_id`; the
`state` cookie must be set only after consent is approved. Test those exact
conditions. Redirect, rate and request budget per `scope.yaml`.

## Tool descriptions and metadata injection
Tool names, descriptions, schemas and results are model input. Invariant Labs
(2025-04-01) named "tool poisoning" (instructions in a description the user
does not see), tool shadowing across servers and rug pulls. Invisible Unicode
tag characters can hide the text from review (see `llm-prompt-injection.md`).
For a remote server in scope: fetch `tools/list` as your own user, scan every
description and schema field for instruction-like text and tag-block
characters (U+E0000 to U+E007F), and check whether the server returns
user-controlled strings (another tenant's content) inside tool results. The
oracle is the nonce plus k-replay procedure of `skills/ai-app`.

## Proof standard and what does NOT count
Proof is the observable bypass (code to attacker host without consent, token
accepted with wrong audience, cross-principal state read) with its control.
Not proof: a missing `Origin` check alone, `scopes_supported` listing many
scopes, a tool description that merely looks suspicious without a model
acting on it, theoretical SSRF from a client you cannot reach.

## Remediation
Per-client consent before the third-party flow, exact redirect URI match,
audience validation on every token, per-user binding of state handles,
block private ranges and re-validate redirects (egress proxy), only
`http(s)` authorization URLs, send `iss` and validate it, minimal initial
scopes with step-up challenges.

## Sources
- Model Context Protocol, Security Best Practices, draft revision (read 2026-11-13); older revision 2025-11-25
- Invariant Labs, "MCP Security Notification: Tool Poisoning Attacks" (2025-04-01)
- RFC 9207 (OAuth issuer identification), RFC 9728 s7.7, as cited by the spec page
