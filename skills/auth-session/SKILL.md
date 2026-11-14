---
name: auth-session
description: Log in once per role (userA, userB, admin) via form, JSON API or Playwright, persist the session as Playwright storage_state, header files and a nuclei secret file, and keep it alive with a re-login check. Use after recon whenever the target has a login, before any authenticated scanning, and always before business-logic (BOLA, mass assignment, race) or stored-XSS testing, which need two accounts.
---

# Auth session — one login per role, reused by every tool

Unauthenticated scans see the login page and little else. This skill makes
every later phase run as a real user, and gives BOLA testing its two principals.
`auth-login` and `session-check` run in the toolbox as `scripts/mythos python3
/repo/scripts/<name>`, or through the `script` tool by name;
sessions live in `engagements/<dir>/sessions/` (git-ignored; the `.login.json`
recipe contains the test credentials).

Triage selects this skill (`skills/registry.yaml`) when the surface shows a
login or session route, a password field, a session identifier in `Set-Cookie`
(including a JWT in a cookie), or a `WWW-Authenticate` header. It drives
`auth-login` and `session-check`, reachable through the `script` tool by those
names. Everything authenticated lists it as a prerequisite: **business-logic**,
**tenant-isolation**, **account-takeover**, **stored-xss-oast**,
**api-protocols**, **oauth-audit** and **ai-app**.

## 0. Accounts

Use only accounts that `scope.yaml` lists under `identities` or that the
program lets you self-register. For BOLA you need **two low-privilege accounts
of the same role** (`userA`, `userB`); `admin` only if the program hands you one
(lab targets often do). Self-register in labs with generated names
(`mythos-a-<rand>`, `mythos-b-<rand>`), record them in `scope.yaml`
`identities`. Never log in as a real user, never brute-force a login.

## 1. Find the login

From recon (`recon.md`, `surface.json`): the login form, or the login API the
SPA calls (watch the `browser` tool's request log, or `katana -headless -xhr`).
An API login is faster and more stable than driving the UI; prefer it.

## 2. Log in, once per role

```
S=engagements/<dir>/sessions
# JSON API (token auto-detected: access_token/token/jwt/... or any JWT; else --token-path data.auth_token)
scripts/mythos python3 /repo/skills/auth-session/scripts/auth_login.py --role userA --out $S \
  --base http://vampi:5000 --mode json --login-url /users/v1/login --user mythos-a --password '...'
# HTML form (hidden CSRF inputs are carried over automatically)
scripts/mythos python3 /repo/skills/auth-session/scripts/auth_login.py --role userB --out $S \
  --base http://dvwa --mode form --login-url /login.php --user mythos-b --password '...'
# SPA / JS-only login: Playwright fills the first password form
scripts/mythos python3 /repo/skills/auth-session/scripts/auth_login.py --role admin --out $S \
  --base http://juiceshop:3000 --mode browser --login-url /#/login --user admin@juice-sh.op --password '...' \
  --user-selector '#email' --pass-selector '#password'
# Token obtained elsewhere (OAuth PKCE, SSO, TOTP done by hand): just store it
scripts/mythos python3 /repo/skills/auth-session/scripts/auth_login.py --role userA --out $S \
  --base https://app.example --mode token --token 'eyJ...' [--cookie 'sid=...']
```

Options worth knowing: `--user-field/--pass-field` (JSON keys or form names),
`--extra '{"otp":"123456"}'` (additional login fields), `--token-header X-Api-Key
--token-prefix ''` (non-Bearer schemes).

Output per role: `<role>.state.json` (Playwright storage_state),
`<role>.headers` (`Cookie:` / `Authorization:` lines), `<role>.nuclei-secrets.yaml`,
`<role>.login.json` (replay recipe), and in browser mode
`<role>.session_storage.json` (Playwright does not persist sessionStorage;
restore it with `context.add_init_script` if the app keeps its token there).

Then record each account's **own object IDs** (orders, profile id, files) by
calling the list endpoints as that user. BOLA testing needs "A's ids" vs "B's ids".

## 3. Keep the session alive

Pick a cheap authenticated baseline (`/api/me`, `/profile`). Before every tool
batch:

```
scripts/mythos python3 /repo/skills/auth-session/scripts/session_check.py --sessions $S \
  --check-url http://vampi:5000/me [--dead-regex 'please log in'] userA userB admin
```

401/403, a redirect to a login page or the dead-regex triggers a re-login with
the saved recipe. Exit 1 = still dead: stop and fix the login, do not scan
logged out and call the result "authenticated".

## 4. Feed the session to the tools

All header files hold one `Name: value` per line. Pass `-H` once per line,
or build the flags in the shell:

```
H=$(sed 's/.*/-H "&"/' $S/userA.headers | tr '\n' ' ')     # -H "Cookie: ..." -H "Authorization: ..."
C=$(sed -n 's/^Cookie: //p' $S/userA.headers)              # raw cookie string
```

| tool | how it takes the session | notes |
|---|---|---|
| nuclei | `-sf $S/userA.nuclei-secrets.yaml` (add `-ps` to prefetch) | one secret per target; secrets do not apply to headless templates; OAuth PKCE is not possible in nuclei, use `--mode token` |
| katana | `-H $S/userA.headers` (file, one header per line) or `-H "Cookie: $C"` | add `-headless -xhr` to record authed XHR calls |
| ffuf | `-H "Cookie: $C"` / `-H "Authorization: ..."` | repeat `-H` per header |
| sqlmap | `--cookie "$C"` and/or `-H "Authorization: ..."` | or a saved raw request with `-r req.txt` |
| dalfox | `--cookie "$C"` and `-H "Authorization: ..."` | the image pins v2 (`dalfox url ...`); v3 (Rust) uses `dalfox scan ...`. Run `scripts/mythos dalfox --help` and use the flags it lists |
| jwt_tool | `-t <URL> -rc "$C"` (cookie) or `-rh "Authorization: Bearer <JWT>"` | then `-M pb` / `-X a` etc. on the authed request |
| curl | `eval curl -s $H <URL>` | ad-hoc checks |
| the `browser` tool | load `$S/userA.state.json` into the page before navigating; it drives one context, so switch roles in sequence | a second role needs its own navigation, not a second context |
| bola-diff, race, xss-verify | `--a/--b/--headers $S/<role>.headers`, `--state $S/<role>.state.json` | see business-logic and stored-xss-oast |

Flag syntax for ffuf, sqlmap and dalfox is from tool knowledge, not re-verified
against the pinned versions; if a flag errors, check `--help` in the toolbox.

## Rules

- A role is "logged in" only when `session-check` says `valid: true`, not
  when the login call returned 200.
- Scanning as a logged-in user sends authenticated state-changing requests
  (nuclei, ffuf on POST). Respect `scope.rules`; exclude logout, delete-account
  and password-change endpoints from fuzzing so the session survives.
- Next: **business-logic** (BOLA/mass assignment/race), **stored-xss-oast**,
  and re-run the **web-scan** steps with the session.
