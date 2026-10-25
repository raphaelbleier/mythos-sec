# Honest limitations and environment notes

The framework is complete and tested; these are the boundaries established empirically.

## Capability vs. lab choreography
- **Two-account BOLA** is implemented (`scan/bola.py`) and unit-tested: an attacker
  identity reading a victim's object is confirmed (vulnapp `/api/order`, HIGH/certain).
- Demonstrating it specifically on **crAPI's vehicle BOLA** requires crAPI's
  *pre-seeded demo users*, which already own vehicles. Fresh signups get an empty
  vehicle list (`GET /identity/api/v2/vehicle/vehicles` -> `[]`) and no VIN email,
  so the vehicle-claim chain cannot be staged with new accounts. This is crAPI's
  internal data seeding, not a Mythos capability gap. `scripts/eval/crapi_bola.py`
  runs the full chain and will confirm the BOLA when pointed at accounts that own
  vehicles (seeded users, or the UI onboarding completed).

## Environment (this VM: 3.7 GB RAM, no sudo)
- **nuclei** runs on heavy SPAs when the template set is scoped (`MYTHOS_NUCLEI_TAGS`)
  and the engine runs lean (`MYTHOS_LEAN`); the full unscoped template set plus a
  heavy SPA plus sqlmap/dalfox simultaneously needs more RAM. Give WSL 8 GB to lift this.
- **crAPI** full stack (10 services) needs ~4 GB; the identity core subset runs here.
- The headless browser is provided via **toolbox Chromium** (built as root), so no
  host Chrome/sudo is required.

## Known hard problem (whole tool category)
Fully autonomous business-logic exploitation (multi-step object ownership, mass
assignment chains) is not reliably solved by any scanner, including the frameworks
Mythos was modeled on. Mythos provides the building blocks (two-account identities,
path/body injection, OpenAPI import) for the agent layer to drive these in a live
engagement; it does not claim autonomous business-logic exploitation.
