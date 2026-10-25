# Broken Access Control (IDOR / BFLA / BOLA)

**Class:** access control  **Updated:** 2026-10-25

## What it is
The app does not enforce per-object or per-function authorization, so a user reaches other users' objects (IDOR/BOLA) or privileged functions (BFLA).

## How Mythos detects it
- Engine: IDOR heuristic compares responses across sequential numeric references on id-like params; distinct non-empty objects while unauthenticated are a strong lead (confidence: tentative — needs human/exploiter confirmation against the auth model).
- Manual: two-account testing (A's token on B's objects).

## How to confirm (non-destructive)
With two low-privilege test accounts, access account A's resource using account B's session. A success with no extra privilege is the proof.

## Remediation
Enforce authorization on every object and function server-side; scope queries to the authenticated principal; use unguessable identifiers.

## Sources
- OWASP API Security Top 10 (API1 BOLA, API5 BFLA); WSTG-ATHZ.
