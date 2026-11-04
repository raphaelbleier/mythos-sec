---
name: engagement-setup
description: Set up a new Mythos engagement workspace and scope. Use at the start of a /cybersecurity run, or whenever the user wants to begin testing a new target, define scope, or import a bug-bounty program's rules before any scanning.
---

# Engagement setup

Create a clean, scoped workspace before any traffic reaches the target. Scope
is the authorization boundary; nothing runs until it is written down.

## Steps

1. **Identify the target** and the authorization. Ask the user which program /
   client this is and confirm they are authorized to test it. If they cannot
   confirm authorization, stop.

2. **Create the workspace**:
   `engagements/<target-host>-<YYYYMMDD>/` with subdirs `recon/`, `scan/`,
   `findings/`. Everything about the engagement stays here (it is git-ignored).

3. **Write `scope.yaml`** directly in the engagement dir (template below),
   then edit it to match the program exactly:

   ```yaml
   target: https://target.example
   in_scope:
     - target.example # only hosts/CIDRs the program lists; *.example.com for wildcards
   out_of_scope: [] # every excluded host the program names
   rules:
     rate_limit_rps: 5
     max_requests: 20000
     allow_active: false # true only if active scanning is permitted
     allow_exploit: false # true only if PoC exploitation is permitted
   identities: [] # optional: two accounts for BOLA/IDOR testing
   notes: "" # paste the program's testing rules verbatim
   ```

   Field rules:
   - `in_scope`: only the hosts/CIDRs the program lists. Use `*.example.com`
     for wildcard programs.
   - `out_of_scope`: every excluded host the program names.
   - `rules.rate_limit_rps` and `rules.max_requests`: respect the program's
     limits (default 5 rps / 20000 requests).
   - `rules.allow_active`: true only if active scanning is permitted.
   - `rules.allow_exploit`: true only if the program permits proof-of-concept
     exploitation. Default false.
   - `notes`: paste the program's testing rules (e.g. "no DoS, no automated
     testing of the login form, no social engineering").

4. **Read the scope back** to the user in one line and get a nod before
   starting recon. This is the single human gate of an engagement. A scope
   file passed with `--scope` counts as that confirmation (non-interactive
   runs); after it, the phases run through to the report.

## Bug-bounty program import

If the user pastes a program's scope page, extract in-scope and out-of-scope
assets, the rate limit, and any forbidden techniques into `scope.yaml`. When in
doubt, exclude rather than include. Record the program name and URL in `notes`.

The scope file is the authorization boundary. It is read by the scope-guard hook
(warns on out-of-scope hosts in any Bash/WebFetch command) and is the reference
you (the agent) must honor in every tool invocation — target only in-scope hosts,
stay under the rate limit, and exploit only when `allow_exploit` is true.
