# Oracle building: telling "payload processed" from "payload ignored"

**Class:** methodology  **Updated:** 2026-11-13

## What it is
Every confirmation in this knowledge base rests on an observable that differs
when the target acted on the input and when it did not. A `200`, a reflected
string or a scanner line is not that observable: all of them appear when the
payload was ignored. Define the oracle before sending the payload, measure its
noise, and run a positive and a negative control. Other notes name the oracle
for their class; this note is how to build and check one.

## Procedure
1. **State the claim as a sentence the oracle can falsify:** "the server
   evaluates the expression", "B can read A's object", "the code reaches my
   host".
2. **Pick the observable type** (table below). Prefer the one that cannot be
   produced by anything except the claimed behaviour.
3. **Measure the noise floor:** send the unmodified baseline 5 times. Whatever
   varies (timing, tokens, ordering) is the noise. A signal inside the noise
   is not a signal.
4. **Positive control:** an input that must trigger the observable if the
   mechanism exists (a known-true condition, your own marker on your own
   object).
5. **Negative control:** an input that must not (a known-false condition, the
   wrong principal, a nonsense value of the same shape). A WAF or error page
   that returns the same thing for payload and control means no signal.
6. **Repeat the pair at least twice**, alternating order, so caching and
   warm-up do not decide the result.
7. **Write down the verdict rule** before reading results, then apply it.

## Observable types
| type | use when | rule |
|---|---|---|
| boolean | output is not reflected but conditions change it | true condition equals baseline, false condition differs, a nonsense condition equals the false one. Any change alone is not proof: the payload may just break the request |
| time | no output, no egress | delay `d` vs delay 0, 3 alternating pairs; median gap >= 0.8 d, baseline jitter < d/3; double `d` and the gap doubles |
| error | stack traces or DB errors leak | a specific signature (engine name, exception class, line) appears with the payload and not with a benign value of the same shape; a generic `500` is nothing |
| out-of-band | blind execution, fetch or parse | one unique token per injection point; the hit carries the token; attribute the source (below) |
| stateful read-back | writes, logic, races, access control | write, then read through a different request or principal; the authoritative state moved. The write response is never the oracle |
| execution | client-side code | a canary in a real browser (dialog, console token, OAST beacon), not the string in the source |
| identity | auth bugs | the response or session carries the identity or marker of the claimed principal |

**Out-of-band attribution.** A hit counts only if it came from the thing under
test. Check source address, `User-Agent`, method and timing: mail scanners,
link previews, WAFs and the agent's own verify browser all fetch URLs. A
single-use link or code consumed by a scanner prefetch also invalidates the
test itself. Interactsh (`interactsh-client -json`) and the lab catcher
(`GET http://oast:8080/__log`) both record these fields.

**Marker choice.** Use values that cannot occur by chance: `{{1337*7331}}`
(9801547) instead of `{{7*7}}` (49 appears in prices and ids), a
`mythos-<hex>` string for reflection and state, known file content
(`/etc/hostname`, or a `root:x:0:0` line) for traversal.

## Response-diff normalization
Comparing two responses (owner vs other user, payload vs control) is wrong
until the parts that always change are removed.
1. Fetch the identical request 5 times. Whatever differs is the **mask
   list**: CSRF tokens, nonces, request or trace ids, timestamps and epochs,
   per-response UUIDs, `Date`, `ETag`, `Set-Cookie`, sort order of lists.
2. Mask the **echo**: if the response repeats your payload, replace it, or
   every payload trivially differs from the control.
3. Canonicalize: sort JSON keys, collapse whitespace, compare body after
   decompression; recompute length after masking.
4. Compare in tiers: status, then headers that matter (`Location`,
   `Content-Type`), then normalized body. Label the result SAME (identical),
   SIMILAR (same structure, values differ), DIFFERENT. `bola_diff.py` uses
   the same labels.
5. If the 5 baselines already disagree after masking, the endpoint is not a
   stable oracle: pick another field or a state read-back.

```python
import re, json
MASK = [(r'\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:?\d\d)?', '<TS>'),
        (r'\b1\d{9}(\d{3})?\b', '<EPOCH>'),
        (r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '<UUID>'),
        (r'\b[A-Za-z0-9+/_=-]{24,}\b', '<BLOB>')]   # heuristic: long tokens
def norm(body, echo=()):
    try: body = json.dumps(json.loads(body), sort_keys=True)
    except ValueError: pass
    for e in echo: body = body.replace(e, '<ECHO>')
    for rx, rep in MASK: body = re.sub(rx, rep, body)
    return re.sub(r'\s+', ' ', body)
noise = {norm(fetch()) for _ in range(5)}   # fetch() is your request; len(noise) == 1 means stable
```

## Oracle per class (primary / control)
| class | primary oracle | negative control |
|---|---|---|
| SQLi | boolean pair, time, or OOB | nonsense condition; `d`=0 |
| XSS | canary fires in a browser | same page, payload absent |
| SSRF | OOB hit from target address | token on a different parameter |
| command injection, XXE, deserialization | OOB token (DNS/HTTP) | blob or command unchanged but benign |
| SSTI | unique product reflected | literal text of the expression in a non-template field |
| path traversal | known file marker | same request, `..` removed |
| BOLA/BFLA | owner-only marker in other principal's response | enforced endpoint, same principal |
| mass assignment, workflow | read-back differs before/after | request without the extra field |
| race | state delta greater than sequential wave | sequential wave |
| cache poisoning | value served on a clean fetch of own cache key | different cache key stays clean |
| smuggling | differential on own connection | well-formed request |
| JWT, SAML | identity of claimed principal in `/me` | one signature byte flipped |
| OAuth | code or token at OAST from own account | unrelated host refused |
| CSRF, CORS, CSWSH | read-back or marker from a real cross-site browser page | session-less context, protected endpoint |
| reset, MFA | login with the new credential | wrong token or skipped step |

## Confounders to rule out
Caches (add a buster); load-balancer variance (repeat); a WAF or error page
identical for payload and control; A/B or personalized content; session expiry
mid-test (`session_check.py`); rate limiting turning later requests into `429`;
gzip and chunking changing `Content-Length`; clock skew in timing tests.

## When no safe oracle exists
Say so. Leave the finding at `candidate`, record which oracle was tried and
what is missing (no egress, no second account, no browser). Do not widen the
payload to force a signal.

## Sources
- PortSwigger Web Security Academy, blind SQL injection, OAST techniques
- `skills/exploit` anti-over-claiming rules; `skills/business-logic` proof standard
