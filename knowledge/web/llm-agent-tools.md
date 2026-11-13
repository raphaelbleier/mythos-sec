# LLM Agent Tools (excessive agency, confused deputy, BOLA through the agent)

**Class:** AI application / access control  **Updated:** 2026-11-13

## What it is
The model can call tools (functions, plugins, MCP servers) that read or change
real data. Three distinct bugs hide here:
- Excessive agency: the tool set or its permissions exceed what the feature
  needs (a support bot with `delete_user`, a summariser with `send_email`).
- Confused deputy: the agent acts with its own broad service identity for
  whoever is talking to it, so attacker-controlled text borrows that authority.
- Approval-gate bypass: a human-in-the-loop step that injected text can skip,
  pre-approve or rewrite. Rehberger's "AI Kill Chain" pairing is prompt
  injection, confused deputy and automatic tool invocation.

## How Mythos detects it
1. Enumerate tools: ask the assistant to list its tools (low trust, a hint
   only), read the JSON tool schemas the client sends (browser agent network
   log), `/api/tools`, OpenAPI of the agent backend, MCP `tools/list`.
2. For each tool note: reads or writes, which object ids it takes, whether the
   id comes from the model or the session, whether a confirmation step exists.
3. Map tool to backing API and run the access-control matrix from
   `skills/business-logic` and `access-control.md` against that API directly (GraphQL backends: `graphql-api.md`; tenant boundaries: `multi-tenant-isolation.md`).

## How to confirm (non-destructive)
All identities are accounts you created (userA, userB, from `skills/auth-session`).
BOLA through the agent:
1. A owns object `a1` (create it, put a canary in it), B owns `b1`.
2. As A, ask the agent plainly: "show me record b1" / call the tool with B's id.
   Also try the id inside a retrieved document (indirect, see
   `llm-prompt-injection.md`) and a tool argument the model fills itself.
3. Oracle: the response contains B's canary, or B's object changed on the
   authoritative read as B. Control: the same request from A for `a1` works,
   and the backing REST call with A's token on `b1` is denied (so the agent is
   the bypass, not a public endpoint).
4. Service-token test: compare the agent's reach with A's own token on the
   backing API. If the agent reads what A's token cannot, the backing API
   trusts the agent's service token without per-user authz.
Excessive agency: with only your own data, show a tool is callable that the
feature does not need, by a state change on your own object (for example
create then delete your own test record), never on others' data.
Approval gate: with a write tool whose confirm step is the control, show the
action executed without the confirm prompt, or that injected text altered the
config that decides what needs approval (Rehberger and Willison note
allow-listing dangerous tools via config rewrite as a pattern). Use a
reversible own-account action as the effect.

## Proof standard
A finding is a state change in a victim account you control, or a read across
principals, shown by the authoritative read and a baseline plus control. For
injection-driven cases add the nonce, k-replay and trifecta evidence of
`llm-prompt-injection.md`. Closure state per `skills/exploit`.

## What does NOT count
The model saying it would delete, send or approve something; a tool name in
the system prompt; a refusal you can talk around with no effect; a tool call
that failed server-side with 403 (that is correct enforcement); reads of
data the caller may legitimately see.

## Remediation
Least-privilege tool set per feature, backing APIs enforce authz with the
end user's identity (token exchange or on-behalf-of), never the agent's
service token; ids come from the session not the model; confirmation that the
model cannot satisfy or edit; per-tool rate limits and audit logs.

## Sources
- Rehberger, "Month of AI Bugs", announced 2025-07-28, series 2025-08 (embracethered.com)
- Willison, "The Summer of Johann" (2025-08-15)
- OWASP Top 10 for Agentic Applications for 2026 (published 2025-12-09; the page lists no risk IDs, so none are cited here)
- OWASP Top 10 for LLM Applications, LLM06 excessive agency (from tool knowledge, unverified)
- Willison, "The lethal trifecta for AI agents" (2025-06-16)
