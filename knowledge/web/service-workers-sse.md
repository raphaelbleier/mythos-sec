# Service workers, the Cache API and server-sent events

**Class:** client-side  **Updated:** 2026-11-14

## What it is
A service worker is script the origin installs into the browser, outside any
page, with its own lifetime and its own fetch interception. Three things follow.
If the registration URL or an `importScripts` source is attacker-controllable,
the attacker's script runs on the origin for the scope's lifetime and survives
the tab, the navigation and the session — persistent XSS with no payload left
in any response. If a worker writes into the Cache API from a URL the page
controls, a poisoned entry is served to the origin on later visits, which is
cache poisoning inside the victim's own browser. And a worker with a `push`
handler can be made to render attacker-controlled notifications.

Server-sent events (`EventSource`) are the one-way sibling of WebSockets: a
long-lived `text/event-stream` response. The failure modes are the stream's,
not the handshake's: a token in the query string that lands in logs and
`Referer`, no `Origin` check (`EventSource` sends cookies and has no preflight),
and authorization checked at connect but never per event, so a channel or
subscription name addressed at another principal's object is a BOLA over a
transport nobody tested.

Measured scale: WWXSS (IEEE EuroS&P 2025) looked at 4,757,077 workers from
56,945,781 sites and confirmed XSS, server- and client-flavoured, in at least
89,945 workers across 31,619 sites. An earlier Cache-API study found 95.8% of
3,436 Cache-API-using service-worker sites in the Tranco 150k potentially
vulnerable to the cache-MITM escalation.

## How Mythos detects it
- `skills/client-side` step 5: `clientside serviceworker <URL>` reports registrations,
  scope, the worker script as served, every `importScripts` source, the
  `Service-Worker-Allowed` header, push handlers and the Cache API contents.
- In the browser directly: `navigator.serviceWorker.getRegistrations()` for
  the installed set, `caches.keys()` and `caches.open(k).keys()` for the cache,
  and the browser tool's `cdp` for `ServiceWorker.*` events.
- Static reads that cost nothing: is the registration path built from a URL
  parameter, a hash or `postMessage` data; is `importScripts` given a URL from
  a config object that a bundle or a clobbered global could set; does
  `Service-Worker-Allowed` widen the scope above the script's directory.
- SSE: capture the stream with CDP `Network.eventSourceMessageReceived`. The
  handshake tests are the ones in `csrf-websocket-clickjacking.md`, with
  `Accept: text/event-stream` instead of the upgrade headers.

## How to confirm (non-destructive)
Registration control: register the worker with the controlled URL on the
agent's own account, then **navigate a second time** and observe the effect in
that fresh navigation — persistence across navigations is the finding, a
one-shot is not. Negative control: the same navigation in a fresh context with
no worker registered. Cache poisoning: write one entry carrying a per-attempt
token through the controlled path, then fetch the cached URL normally and see
the token; control is a second, untouched URL that stays clean.

SSE per-message authorization: open the stream as `userA`, subscribe to a
channel or object id that belongs to `userB` (an account the agent owns), and
compare against `userA`'s own channel as baseline and an unauthenticated
stream as control. The same object reachable over REST and over the stream,
with a different answer on each, is the two-transport result that makes an
authorization bug systemic.

**Unregister everything you registered, in the step that proved the point.**
`getRegistrations()` then `unregister()`, and `caches.delete` what you added. A
worker outlives the engagement; one left behind is a backdoor the agent
installed. Record the cleanup in the finding.

Does not count: a worker that exists (every PWA has one); an `importScripts`
from a hard-coded CDN host; a stream that carries only public data; a
`Service-Worker-Allowed` header on a site with one worker at the root.

## Remediation
Never build a registration URL or an `importScripts` source from
request-controlled data; serve the worker script with a strict
`Content-Type` and a CSP that names its `script-src`; keep the scope at the
narrowest path that works; validate what goes into the Cache API; check
`Origin` on the event-stream request, keep tokens out of the URL, and
authorize every event against the subscribing principal rather than once at
connect.

## Sources
- WWXSS: "A Systematic Study and Large-Scale Measurement of Cross-Site Scripting in Web Workers Contexts", IEEE EuroS&P 2025 (CISPA)
- "Cache Me If You Can: Service-worker Cache API MITM escalation", IEEE S&P 2021
- Appified web security (TAMU): service-worker XSS and push hijacking across 200 sites
- Include Security, "Cross-Site WebSocket Hijacking Exploitation in 2025" (2025-04) — the handshake tests SSE shares
