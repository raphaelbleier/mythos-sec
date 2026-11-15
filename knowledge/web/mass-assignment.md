# Mass Assignment (BOPLA write side)

**Class:** access control / business logic  **Updated:** 2026-11-04

## What it is
The API binds request JSON straight onto the model, so a client can set fields
it should not: `role`, `isAdmin`, `balance`, `price`, `userId`, `tenantId`,
`verified`. OWASP API3:2023 (Broken Object Property Level Authorization).

## How Mythos detects it
- `scripts/mass-assign fields <openapi.json>`: per
  write operation, fields the resource returns but the request schema lacks (or
  marks `readOnly`), sensitive names first.
- No spec: fields of the object's GET response; `arjun -m JSON` for hidden ones.

## How to confirm (non-destructive)
On the agent's own object: GET before, write with the extra field, GET after
(`mass-assign probe`). `reproduced` only when the after-GET shows the value
and the before-GET did not; a 200 on the write proves nothing (unknown fields
are often dropped silently). Then show the effect (new role reaches an admin
function).

## Remediation
Explicit allowlist of writable fields per operation (DTOs / serializers with
read-only fields); never bind request bodies to persistence models directly.

## Sources
- OWASP API Security Top 10 2023, API3 BOPLA
- Strix business_logic.md (usestrix/strix, Apache-2.0), durable-state rule (2026-10)
