# SQL Injection (and ORM, NoSQL, LDAP query injection)

**Class:** injection  **Updated:** 2026-11-13

## What it is
User input reaches a query without parameterization and alters its structure.
The same shape exists in ORM filter features, document-store operators and LDAP
filters, where the "query language" is an object or a filter string.

## How Mythos detects it
Every manual probe is a pair: a payload and a matched control that differs only
in the injected truth value.
- Error: `'` and `"` each alone; a DB error signature (`SQLSTATE`, `ORA-`,
  `syntax error at or near`, `unterminated quoted string`) that the benign
  value does not produce. Note the DBMS from the message.
- Boolean: `id=1 AND 1=1` vs `id=1 AND 1=2` (numeric), `' AND '1'='1` vs
  `' AND '1'='2` (string). Oracle = a stable, repeatable difference in body,
  length or status between true and false, and the true case equals the
  untouched baseline. Add a third arm `AND 1=1` with a different spelling
  (`AND 2>1`) to show it is logic, not a filter on the string `AND`.
- Time: a delay function with a baseline and repeats. MySQL `SLEEP(5)`,
  PostgreSQL `pg_sleep(5)`, MSSQL `WAITFOR DELAY '0:0:5'`, Oracle
  `dbms_pipe.receive_message('a',5)`, SQLite has none (use a heavy
  `randomblob` expression only as a candidate). Run baseline x3, payload x3
  with 5 s and 0 s; all three delayed runs exceed all baselines by about the
  delay, and the 0 s control does not.
- UNION: `ORDER BY n` or `UNION SELECT NULL,...` only to find the column count
  and one reflected column; print the DB version string, nothing else.
- Second order: the payload is stored (profile name, address, filename) and
  fires on a later request that reuses it. Store `mythos<nonce>'` ; trigger
  each page that later renders or queries your object; an error or changed
  result tied to your nonce is the oracle. The store request alone shows
  nothing.
- Tools: `sqlmap` and `nuclei` are candidate generators and confirmers.

## ORM and operator leaks (PortSwigger Top 10 2025 #2)
Search, filter and sort parameters that map straight into ORM lookups leak data
without any SQL syntax: Django `?filter__user__password__startswith=a`,
Prisma `where` objects from JSON, Sequelize/TypeORM operators in query strings,
`?filter[password][startsWith]=a` style bracket syntax. Oracle: for a field on
a related object you own, `startsWith` the true prefix returns your row, a
wrong prefix returns none, over at least 3 prefixes. Prove on your own
record's hidden field, never by walking other users' hashes. Source: Alex
Brown, elttam, "ORM Leaking More Than You Joined For" (2025-12-18; earlier
posts on Django and Prisma exist in the same series).

## NoSQL and LDAP
- JSON body operator injection: `{"user":"mythos-a","pass":{"$ne":"x"}}` logs in
  as your own account only if the password check is bypassed; test with your
  own user and a wrong password: wrong string denied, `{"$ne":""}` allowed =
  operator injection. `{"$regex":"^a"}` true/false pair gives a boolean oracle
  on your own field. `$where` with `sleep(5000)` is a time oracle (baseline x3).
  Form-encoded `user[$ne]=x` is the same bug through qs-style parsing.
- LDAP: `*` in a name field returning many results vs a literal; `*)(uid=*))(|(uid=*`
  style breakouts change the result count; oracle = result count differs
  between `(cn=mythos-a*)` true and `(cn=zzz*)` false arms.

## How to confirm (non-destructive)
`sqlmap -u '<url>' --batch --level 2 --risk 1 --banner --current-user` after
the manual pair above; or the pair alone is enough. Proof = request, matched
true/false (or baseline/delay) arms, repeated, plus DBMS banner or error
signature. Limits: no `--dump`, no stacked write queries, no `--os-shell`, no
`--risk 3` (OR payloads can hit UPDATE/DELETE), no reading other users' rows.
Time payloads only with delay <= 5 s and a small number of repeats.

Does NOT count: a database error on a malformed value with no differential
control, one slow response, a WAF 403 on `'`, a reflected payload in the page,
a sqlmap "might be injectable" line.

## Remediation
Parameterized queries; allowlist filter and sort fields and operators server
side; map ORM lookups explicitly; cast JSON values to scalars before queries;
escape LDAP filters; least-privilege DB account.

## Sources
- OWASP WSTG-INPV-05; PortSwigger Web Security Academy, SQL injection (2026-10)
- PortSwigger Top 10 Web Hacking Techniques of 2025 (2026-02-05): #2 "ORM Leaking More Than You Joined For"
- elttam, "ORM Leaking More Than You Joined For" (2025-12-18)
