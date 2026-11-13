# Source to sink (trace the value by hand, then probe it)

**Class:** methodology  **Updated:** 2026-11-14

## What it is
A grey-box candidate is a claim about one path: a value the request controls
reaches a call that does something dangerous with it, and nothing on the way
makes it safe. Taint analysis names the three parts — source, sanitizer, sink
(Pixy, 2006; TAJ, 2009) — and the claim is false if any of them is wrong. The
sink can be reachable, the source can be request-controlled, and the finding
can still not exist, because a sanitizer, a type conversion, a framework
binding or a missing route makes the path unreachable in the deployed build.
This note is how to settle that by hand when `scripts/sourcemap` says
`confidence: low`, and how to turn whatever survives into one live request.

## Detection signal, and where the tool stops
`scripts/sourcemap` pairs a sink with a route when both sit in the same block
and the block reads the request. It reports `medium` when a request value or a
variable assigned from one appears in the sink call itself, `low` when it only
knows that the block does both. It never traces across a function boundary, an
ORM, a queue, a template or dynamic dispatch, so `low` means "look yourself"
and `medium` means "this is worth one request", never "this is a bug".

Trace by hand whenever the candidate is `low`, when the sink is in a different
file from the route, or when the payoff is high (`exec`, `deserialize`, `sql`
on a state-changing route).

## Trace it by hand
Walk forward from the source, not backward from the sink: the question is what
the sink receives, and a backward walk invites you to assume the answer.

1. **Pin the source.** The exact parameter, its position (query, body, path,
   header, cookie) and the method the route accepts. A body field that only a
   PUT reaches is not reachable by the GET you were about to send.
2. **Follow every assignment, one hop at a time.** Write the chain down as
   `param -> name -> name -> sink arg`. A hop you cannot see (a helper in
   another module, a DI container, a serializer) is the end of the trace: mark
   it unresolved rather than assuming it passes the value through.
3. **Name every transformation on the way** and decide what it does to the
   payload: `int()`, a schema parse (pydantic, zod, Joi, `Service.parse`), an
   allowlist comparison, a regex, an escape, a prepared-statement binding, a
   length cut, a `replace`. A conversion to a number kills injection; a regex
   that merely rejects some characters usually does not.
4. **Check the sink's own protection.** A parameterized query with the value
   bound is not a SQL sink however the string was built; `subprocess.run` with
   a list and `shell=False` is not a shell; `html/template` escapes where
   `text/template` does not; a template rendered from a fixed file with the
   value as a variable is not SSTI.
5. **Check reachability.** Is the route mounted (a prefix, a feature flag, an
   environment check)? Is the branch holding the sink reachable with the input
   you can send? Does a guard above it run first?

Per language, where the value enters and the hop that is easy to lose:

| language | request sources | the hop that hides the value |
|---|---|---|
| python | `request.args/form/json/files/headers/cookies`, Django `request.GET/POST`, FastAPI and Flask handler arguments (path and query parameters bind straight in) | a dict hop (`data = request.get_json()`, then `data["x"]`), `**kwargs` into a model, an ORM `filter(**params)` |
| js / ts | `req.query/body/params/headers/cookies`, `searchParams`, `await req.json()`, a server action's arguments | destructuring (`const { id } = req.params`), a middleware that writes onto `req`, an object spread into an ORM call, a template literal built two lines earlier |
| php | `$_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES`, `$request->input()/query()/all()` | `extract()`, a model `fill()`/`create($request->all())` (mass assignment), string concatenation inside a Blade include |
| java | `@RequestParam`, `@PathVariable`, `@RequestBody` into a DTO, `request.getParameter` | the DTO: the value is now a field, and the sink reads the getter several classes away |
| go | `r.URL.Query().Get`, `r.FormValue`, `c.Param/Query`, `ShouldBind`/`BindJSON` into a struct, `chi.URLParam` | struct binding, then a method on that struct builds the query with `fmt.Sprintf` |
| ruby | `params[...]`, `request.body` | strong parameters (`permit`) and what it does **not** filter, `render inline:`, `find_by_sql` with interpolation |

## From hypothesis to live probe
The trace produces a request, not a verdict.

1. Write the request the trace implies: method, path, parameter position,
   content type, and the smallest value that would reach the sink unchanged.
2. Pick the oracle before sending it (`oracle-building.md`), from the sink:

| sink kind | oracle | note |
|---|---|---|
| sql | a DBMS-specific error signature, or a boolean/time differential | a generic 500 is nothing |
| exec | an OOB hit carrying this run's token, or a time oracle | `knowledge/web/command-injection.md` |
| deserialize | an OOB hit from a gadget, or a parser-specific error | never a destructive gadget |
| template | an arithmetic expression that evaluates (`{{1337*7331}}` -> 9801547) | `49` occurs by chance |
| path | known file content (`root:x:0:0`, `/etc/hostname`) | not a 200 and not a different length |
| redirect | the `Location` header pointing at a host you chose | not a body that mentions the host |
| http-client | an OOB hit, attributed to the target | mail scanners and previews also fetch URLs |
| xss-sink | execution in a real browser, or the unescaped reflection in the right context | the string in the source is not execution |

3. Send it inside `rules.rate_limit_rps`, non-destructive, on your own objects.
4. Send the negative control: the same request with a benign value of the same
   shape, and, for an authorization candidate, the same request as the
   principal that should be denied.
5. Repeat the pair once, alternating order, so a cache does not decide it.

## Negative control
The control has to kill the specific claim. For a sink claim it is the benign
value of the same shape through the same parameter, showing the oracle does not
fire. For a missing-guard claim it is a route the same guard does cover,
showing that the guard mechanism works and this route is the exception. A
control that merely returns a different status proves nothing: the payload may
just have broken the request.

## Does NOT count as proof
The line of code. The sourcemap row, at any confidence. A sink the trace
reached with an unresolved hop in the middle. A 200, a reflected string, an
exit code, or a scanner line. A finding that reproduces in a local checkout of
the application but not against the target: that is a bug in the product, and
it belongs to the engagement only if the live target shows it. The version in
the checkout: confirm the deployed version live before it counts as a
fingerprint for `scripts/cvefeed`.

## Remediation (what to write in the report)
Bind the value instead of interpolating it (prepared statement, argument list
instead of a shell string, template variable instead of a template string);
validate against an allowlist at the boundary and convert to a type; put the
authorization check in a guard that every route inherits rather than in each
handler; and name the file and line, because the fix is cheap for the vendor
when the report points at the sink.

## Sources
- N. Jovanovic, C. Kruegel, E. Kirda, "Pixy: A Static Analysis Tool for
  Detecting Web Application Vulnerabilities", IEEE Symposium on Security and
  Privacy, 2006-05.
- O. Tripp, M. Pistoia, S. Fink, M. Sridharan, O. Weisman, "TAJ: Effective
  Taint Analysis of Web Applications", PLDI 2009-06.
- E. J. Schwartz, T. Avgerinos, D. Brumley, "All You Ever Wanted to Know About
  Dynamic Taint Analysis and Forward Symbolic Execution (but Might Have Been
  Afraid to Ask)", IEEE Symposium on Security and Privacy, 2010-05.
- OWASP Code Review Guide v2.0, 2017.
- GitHub, CodeQL documentation, "About data flow analysis" (living
  documentation, no fixed date) — the source/sanitizer/sink vocabulary this
  note uses.
- Semgrep documentation, "Taint tracking" (living documentation, no fixed
  date) — intra-procedural taint and its stated limits.
