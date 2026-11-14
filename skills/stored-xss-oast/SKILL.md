---
name: stored-xss-oast
description: Prove stored and blind XSS with execution evidence instead of scanner output - a unique token per injection point, payload injected as user A, rendered in a second Playwright context (dialog/console canary + screenshot), and for blind sinks an admin-bot visit plus an OAST hit (lab oast catcher or interactsh). Use when web-scan or dalfox reports a stored/blind XSS candidate, or for any input that is rendered to other users or admins (comments, profiles, tickets, support chats, file names).
---

# Stored XSS and OAST: it executed, or it did not happen

A dalfox "V" line, a reflected `<script>` in the HTML source or a 200 on the
injecting POST is not a finding. Proof is one of:

Triage selects this skill (`skills/registry.yaml`) when the surface shows a
persisted text field (`comment`, `body`, `text`, `message`, `description`,
`title`, `name`, `bio`, `review`, `filename`) or a comments, posts, messages,
tickets, reviews, feedback, profile, support, notes or upload route. It drives
`xss-verify`, and needs **auth-session** first.

1. the canary **fired in a browser** (dialog or console message carrying the
   token) on the page where the payload renders, viewed as a different role; or
2. an **OAST hit** whose token maps to exactly one injection point.

XBOW validates XSS the same way (headless browser checks the payload executed).

## Setup

- Sessions from **auth-session**: `S=engagements/<dir>/sessions`, injecting role
  `userA`, viewing role `userB` or `admin`.
- Lab: `docker compose -f lab/docker-compose.yml up -d oast admin-bot` and
  `scripts/mythos net mythos-lab`. In-lab callback base `http://oast:8080`
  (log: `GET http://oast:8080/__log`, DNS on `oast:5353/udp`); admin-bot at
  `http://admin-bot:8000`, `POST /visit {"url": ...}`, visits only hosts in its
  `ALLOWED_HOSTS` with the admin cookie from `ADMIN_COOKIE_NAME/VALUE`.
- Internet target (in scope, OAST allowed by the program):
  `scripts/mythos sh 'interactsh-client -json -o engagements/<dir>/scan/interactsh.jsonl'`
  in the background, use the printed `*.oast.*` host as the callback base.
  An `https` page will block an `http://` callback (mixed content); use an https
  OAST base there.

## Steps

1. **Mint a token per injection point** (never reuse one, or late callbacks
   cannot be attributed):

   ```
   scripts/mythos python3 /repo/skills/stored-xss-oast/scripts/xss_verify.py token \
     --map engagements/<dir>/scan/xss-tokens.jsonl --point 'POST /api/comments body.text' --oast http://oast:8080
   ```

   It prints payloads for HTML body, attribute break-out, script block, JS
   string and URL sinks; each calls `alert` and `console.log('MYTHOS-XSS:<token>')`
   and loads `<oast>/<token>`. Pick the one that fits the render context recon
   or dalfox showed.

2. **Inject as user A** with curl (`$S/userA.headers`) or the `browser` tool.
   Keep the payload harmless: canary and callback only, no cookie theft beyond
   the callback query string in the lab, no persistence, no worm.

3. **Render as another role and listen:**

   ```
   scripts/mythos python3 /repo/skills/stored-xss-oast/scripts/xss_verify.py verify --token <token> \
     --url <page that renders it> --state $S/userB.state.json \
     --oast http://oast:8080 --shot engagements/<dir>/scan/xss-<token>.png
   ```

4. **Blind sink** (admin panel, support queue, log viewer you cannot open):
   add `--admin-bot http://admin-bot:8000` (lab) and `--no-browser` if you
   cannot view the page yourself; on an internet target replace the bot with
   the program's own reviewer flow and `--interactsh-log <file> --poll 600`.

5. Clean up: delete the injected comment/profile text from your own account.

## Verdict

`xss-verify verify` reports evidence (`browser_hit`, `oast_hit`, nonce, timestamps) and
sets no closure state; set it yourself from that evidence. Exit 1 = no evidence observed.
The OAST callback carries the nonce and `location.origin` only; `--include-cookies` on `token`
adds `document.cookie` and needs the program's authorization. Evidence for the
report: the token map line (token -> injection point), the injecting request,
the render URL and role, the dialog/console text or the OAST log line, and the
screenshot. A token seen in the OAST log from the **toolbox's own** IP (your
own verify browser) proves execution in a victim-equivalent context; from the
admin-bot it proves the privileged-viewer impact.

**Cite the request, not only the screenshot.** The `browser` tool now runs
behind the recording proxy, so the navigation that rendered the payload is in
`traffic/log.jsonl` like any other request. The finding names
`proof: traffic/<id>` for that navigation **as well as** the screenshot and the
dialog or console canary: the screenshot is the oracle, the traffic record is
what a human replays. `scripts/evidence check` refuses a finding that cites no
request, in those words — *a capture is not a request: cite the exchange that
set it up* — and it has already rejected real DOM-XSS findings that were proven
in Chromium and cited nothing. Run `scripts/evidence build engagements/<dir>`
and then `scripts/evidence check engagements/<dir>` before the report.

Write the result into the finding file the **exploit** skill describes; its
closure state and the validator pass apply unchanged.
