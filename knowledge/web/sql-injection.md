# SQL Injection

**Class:** injection  **Updated:** 2026-10-25

## What it is
User input reaches a SQL query without parameterization, letting an attacker alter the query.

## How Mythos detects it
- Engine: error-based probe (`1'"` triggers a DB error signature) and time-based blind probe (`SLEEP()/pg_sleep()` differential latency, deep mode).
- Tools: `sqlmap` (confirmation, DBMS fingerprint), `nuclei` (known endpoints).

## How to confirm (non-destructive)
`sqlmap -u '<url>' --batch --level 2 --risk 1 --banner` — capture the injectable parameter and DBMS banner only. Do not dump tables.

## Remediation
Parameterized queries / prepared statements; least-privilege DB account; no string concatenation.

## Sources
- OWASP WSTG-INPV-05; PortSwigger Web Security Academy — SQL injection (2026-10).
