# Server-Side Template Injection (SSTI)

**Class:** injection  **Updated:** 2026-11-13

## What it is
User input is concatenated into a template that the server then evaluates, so
the attacker runs template expressions. Typical places: email and notification
templates, "custom message" fields, PDF/report headers, error pages, CMS and
wiki page bodies, marketing-tool merge fields. Client-side template injection
(AngularJS-style expressions in the browser) is a different class: see
`client-side-dom.md`.

## How Mythos detects it
- Polyglot first, one request: `${{<%[%'"}}%\` (widely reproduced polyglot;
  its original author is unverified). A 500, a template parse error or a
  changed render, where the same field with `abc` renders normally, marks the
  field as a candidate.
- Arithmetic with distinct primes so a literal echo cannot match: `{{1337*1337}}`,
  `${1337*1337}`, `#{1337*1337}`, `<%= 1337*1337 %>`, `{1337*1337}`; the product
  `1787569` that is not in the request is evaluation.
- Engine disambiguation:
  - `{{7*'7'}}`: `7777777` Jinja2 (Python string repeat); `49` Twig (PHP).
  - `${7*7}` evaluates, `{{7*7}}` does not: Freemarker, Velocity, Thymeleaf,
    Mako, or a Java EL context. `#{7*7}` Ruby/Pug interpolation or Thymeleaf.
  - `<%= 7*7 %>`: ERB (Ruby) or EJS (Node). `{7*7}` or `{$smarty.version}`: Smarty.
  - `@(7*7)`: Razor (.NET). `{{ .Name }}` renders a field: Go `text/template`
    or `html/template`. Handlebars has no arithmetic: `{{7*7}}` errors or
    echoes, so test with a helper such as `{{#if true}}x{{/if}}` rendering `x`.
  - Engine-specific no-side-effect probes: Jinja2 `{{config.__class__}}`,
    Twig `{{_self}}`/`{{7|length}}`, Freemarker `${.version}`, Velocity
    `$velocityVersion` (engine-dependent, may be empty).
- Error-based oracle for blind SSTI (nothing rendered back): force an error
  whose message carries a value, for example a division or type error whose
  text includes your nonce or computed result; the error text in a response,
  log page or status code difference is the oracle. Technique: Korchagin,
  "Successful Errors" (PortSwigger Top 10 2025 #1; published 2026-02-05 list).
  Time oracle is the fallback: a bounded loop differential on your own request,
  baseline plus 3 repeats.
- Tools: `tplmap`/`sstimap` and `nuclei` are candidate generators only.

## Relation to skills/exploit — this note wins
`skills/exploit` shows a Jinja2 gadget chain that calls `popen('id')` and says
to read a file as proof. This note said "stop before RCE". **Where the two
disagree, the stricter rule applies, and it is this one.** Scoped:

1. Detection and engine identification (above) need only active scope
   (`allow_active`). They change nothing on the target and are where most
   findings should end.
2. The proof step runs only when `scope.rules.allow_exploit` is true. If it is
   false the finding stays `reproduced` at arithmetic or engine
   identification, with that stated.
3. When it does run, the proof is **one** of: an OAST callback carrying the
   run's nonce, a no-op marker, or a single read of `/etc/hostname`. In that
   order of preference. Never a shell, never a write, never a state change,
   never a second command, never enumeration, never config, env or secrets,
   and never `id` outside a lab.

Why the stricter rule wins, rather than splitting the difference. A template
engine with a gadget chain is arbitrary code on the target, and arbitrary code
is the one class where the agent cannot undo what it did and cannot know in
advance what the command touches — a run already emptied a target's table with
one well-formed request, which is why destruction is refused in code rather
than left to judgement. And the extra command buys nothing: about 44% of proofs
of concept that passed exit-code, marker and trace checks were invalid, so a
second command is another chance to be confidently wrong, not more proof. The
callback with a nonce is a deterministic oracle; `id` output in a transcript
is a reading of a transcript.

## How to confirm (non-destructive)
Negative control: the same field with the expression escaped or replaced by a
literal renders the literal. Proof = the evaluated product plus the engine
name from a disambiguation step, with raw request and response excerpts. If a
sandbox blocks gadget access (Jinja2 `SandboxedEnvironment`, Twig sandbox,
Freemarker `new_builtin_class_resolver`), report evaluation plus the sandbox;
do not hunt for a sandbox escape on a real target. Does NOT count: the literal
payload reflected in the HTML, a client-side-only render, a WAF block page
that echoes the payload, an error that does not depend on the payload.

## Remediation
Never build templates from user input; pass user data only as bound
variables; use logic-less or sandboxed engines; keep email and report
templates under developer control.

## Sources
- PortSwigger Research, James Kettle, "Server-Side Template Injection" (Black Hat USA 2015)
- PortSwigger Web Security Academy, SSTI (2026-10)
- PortSwigger Top 10 Web Hacking Techniques of 2025 (2026-02-05): #1 "Successful Errors: New Code Injection and SSTI Techniques", Vladislav Korchagin
