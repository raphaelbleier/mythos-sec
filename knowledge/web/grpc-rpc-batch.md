# gRPC, Connect, tRPC, JSON-RPC and batch authorization

**Class:** api / access control  **Updated:** 2026-11-14

## What it is
A framework that routes every operation through one HTTP endpoint also
collapses every per-route authorization check into one. Two consequences.

**Batch authorization.** A caller sends several operations in one request and
the framework authorizes the *request* instead of each operation. The guard
passes because one of the ids in the array belongs to the caller, and the rest
go through with it. Seen in the wild on tRPC (`?batch=1` with an indexed input
map), JSON-RPC (a top-level array), GraphQL (an array of operations, or aliases
in one document) and OData (`$batch`). The second failure is partial
execution: a batch where one operation is refused still applies the others, so
a refusal becomes a partial write.

**Streaming and metadata.** A streaming RPC is commonly authorized at stream
open and never again, so a later message on the open stream addressed at
another principal's object is unchecked. And metadata headers are trusted far
more often than HTTP headers: an `x-user-id`-style key that a gateway forwards
without validating is a privilege claim the backend believes.

Transport shapes worth recognising: gRPC is `application/grpc` over HTTP/2;
gRPC-web is `application/grpc-web-text` or `application/grpc-web+proto`;
Connect speaks plain JSON over `POST /<pkg.Service>/<Method>` with
`Content-Type: application/json`, so `curl` is enough and no protobuf tooling
is needed; tRPC is `/api/trpc/<router>.<procedure>`; JSON-RPC is a body with
`"jsonrpc": "2.0"` and a `method` name, so authorization must inspect that
name. HTTP/2 connection reuse also makes per-request rate limiting brittle on
all of these.

## How Mythos detects it
- `skills/api-protocols`: `apiproto rpcbatch` runs the three-request comparison
  below for JSON-RPC and tRPC, `apiproto grpc` enumerates methods over
  reflection or from a recovered bundle and runs the per-method role matrix,
  and `apiproto graphql` runs the per-field one. Each of them classifies the
  endpoint itself from what it answers; there is no separate detect step.
- Operation lists: `grpcurl list` and `describe` over server reflection
  (`grpc.reflection.v1`); with reflection off, the service descriptors are in
  the web bundle — `grpc-pentest-suite` extracts services, methods and field
  numbers from webpacked JavaScript, `protoscope` edits frames by hand. tRPC's
  router map is in the bundle too. JSON-RPC method names come from captured
  traffic or a documented list, never from a guessed sweep.
- Patch level, checked live before it is claimed: tRPC prototype pollution
  giving an authorization bypass in the Next.js App Router caller
  (CVE-2025-68130, 10.27.0 up to <10.45.3 and <11.8.0). A version match is a
  candidate.

## How to confirm (non-destructive)
Three requests per operation, with two accounts the agent owns, and the
comparison between them is the whole test:

1. the operation **alone** with `userB`'s id, sent as `userA` — expected
   refused;
2. a **batch of two**, `userA`'s id first and `userB`'s id second, as `userA`;
3. the same batch with **both ids belonging to `userA`** — the baseline.

(1) refused and (2) returning `userB`'s data or applying the write means the
guard ran once for the batch. (1) is the negative control; without it, (2) only
shows that the caller can read something. Writes only on objects the agent
created. Then read the state back from the authoritative endpoint as the owner:
the batch's own response is not evidence of a write.

Streaming: open the stream as the owner (baseline), then send a second message
on the same open stream naming the other account's object, with an
unauthenticated stream as control. Metadata: send the claim key as `userA` and
check whether the backend's answer changes; the control is the same request
without the key.

Does not count: a batch that returns a per-operation error for the
unauthorized half; an operation on public-by-design data; an empty `200` for
another user's object, which is silent enforcement until compared with the
owner's view; a reflected method name in an error message.

**Denial-of-service shapes to cap, not to exercise:** array batching, alias
overloading, field duplication, directive overloading and circular
introspection. N <= 10 against the agent's own data, with a single-request
control. The finding is "no cost limit is enforced", shown by a latency slope
over ten requests, never by a request that hurts.

## Remediation
Authorize every operation in a batch independently and fail the whole batch
when any one fails; derive the subject from the session and never from a
request field or a forwarded metadata key; re-check authorization on every
streaming message, not only at stream open; strip client-supplied metadata at
the gateway; enforce a per-operation cost and depth limit rather than a
per-request rate limit.

## Sources
- tRPC security research (LogicalHunter, 2026): batch where one id belongs to the caller passes the guard
- Conar broken-ownership cross-user write write-up (2026)
- OSV / GHSA for CVE-2025-68130 (tRPC prototype pollution to authorization bypass)
- StackHawk, JSON-RPC security best practices: single endpoint, authorization must inspect `method`; batch arrays risk partial execution
- nxenon/grpc-pentest-suite (gRPC-web frames, bundle scanner, Burp extension); protoscope
- NCC Group, "Attacking gRPC" (referenced as the reference whitepaper; not read in this pass)
