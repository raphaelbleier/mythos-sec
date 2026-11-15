/**
 * The runnable check: `node dist/selftest.js`, no network, no model, no docker.
 *
 * It covers the logic that decides what the agent is allowed to do and when a
 * phase is finished, because those are the places where a silent mistake does
 * not look like a crash. The scope parser in particular: if it read `in_scope`
 * wrongly, the guards would warn about the wrong hosts and the run would look
 * clean while testing something it was not authorized to touch.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chunk, verdictState } from "./driver.js";
import { parseYaml, readScope } from "./scope.js";
import { Ledger, endpointKey, isResolved, surfaceFromMap } from "./verdicts.js";
import { argUrls, shq, summariseJson } from "./agent/tools.js";
import { shotName } from "./agent/browser.js";
import { rawRecord, requestLine, statusOf, unescapeBytes } from "./agent/raw.js";
import { splitModel } from "./providers/registry.js";
import { needsHostNetwork, toolboxTarget } from "./prompts.js";
import { renderLine } from "./plain.js";
import { colourEnabled } from "./tui/theme.js";

let ran = 0;
function test(name: string, fn: () => void) {
  fn();
  ran += 1;
  process.stdout.write(`  ok  ${name}\n`);
}

const tmp = mkdtempSync(join(tmpdir(), "mythos-selftest-"));

test("the scope parser reads a real scope file", () => {
  const f = join(tmp, "scope.yaml");
  writeFileSync(
    f,
    [
      "# a comment",
      "target: http://127.0.0.1:5013",
      "in_scope:",
      "  - 127.0.0.1",
      "  - lab.internal",
      "out_of_scope: []",
      "ports: [5013, 8080]  # trailing comment",
      "rules:",
      "  rate_limit_rps: 20",
      "  allow_exploit: true",
      "  allow_active: false",
      "identities: []",
      'notes: "Isolated lab target."',
    ].join("\n"),
  );
  const s = readScope(f);
  assert.equal(s.target, "http://127.0.0.1:5013");
  assert.deepEqual(s.in_scope, ["127.0.0.1", "lab.internal"]);
  assert.deepEqual(s.out_of_scope, []);
  assert.deepEqual(s.ports, [5013, 8080]);
  assert.equal(s.rules.rate_limit_rps, 20);
  assert.equal(s.rules.allow_exploit, true);
  assert.equal(s.rules.allow_active, false);
  assert.equal(s.notes, "Isolated lab target.");
});

test("a scope file with no target is refused rather than defaulted", () => {
  const f = join(tmp, "empty.yaml");
  writeFileSync(f, "in_scope:\n  - example.com\n");
  assert.throws(() => readScope(f), /no 'target'/);
});

test("an inline list and a block list parse the same", () => {
  assert.deepEqual(parseYaml("ports: [1, 2]").ports, [1, 2]);
  assert.deepEqual(parseYaml("hosts:\n  - a\n  - b\n").hosts, ["a", "b"]);
});

test("the surface map is read the way scripts/coverage reads it", () => {
  const f = join(tmp, "surface.json");
  writeFileSync(
    f,
    JSON.stringify({
      origin: "http://t:5000",
      pages: [{ url: "http://t:5000/login", forms: [{ action: "/doLogin" }] }, { url: "http://t:5000/" }],
      reachable_paths: [{ path: "/admin" }, "/me"],
      api_endpoints: ["POST /register", "mutation importPaste(a, b)"],
      parameters: [{ name: "q" }, { name: "id" }],
    }),
  );
  const items = surfaceFromMap(f);
  assert.ok(items.includes("/login"), "page paths are relative to the origin");
  assert.ok(items.includes("/doLogin"), "form actions count");
  assert.ok(items.includes("/admin") && items.includes("/me"), "both shapes of reachable_paths");
  assert.ok(items.includes("/register"), "a method prefix is stripped");
  assert.ok(items.includes("mutation importPaste(a, b)"), "a GraphQL entry stays whole");
  assert.ok(items.includes("param:q"), "parameters are their own items");
  assert.ok(!items.includes("/"), "the bare root is not work");
  assert.equal(new Set(items).size, items.length, "no duplicates");
});

test("an unreadable surface map yields no endpoints instead of throwing", () => {
  const f = join(tmp, "broken.json");
  writeFileSync(f, "{not json");
  assert.deepEqual(surfaceFromMap(f), []);
});

test("work is split round robin so every worker gets a mix", () => {
  assert.deepEqual(chunk([1, 2, 3, 4, 5], 2), [
    [1, 3, 5],
    [2, 4],
  ]);
  assert.equal(chunk([1], 3).length, 1, "no empty workers");
  assert.deepEqual(chunk([], 3), [], "nothing to do means no workers");
});

test("shell quoting survives a quote in a payload", () => {
  assert.equal(shq("a'b"), `'a'\\''b'`);
  assert.equal(shq("' ; rm -rf /"), `''\\'' ; rm -rf /'`);
});

test("a model spec names its provider", () => {
  assert.deepEqual(splitModel("openrouter/z-ai/glm-5.3"), {
    provider: "openrouter",
    model: "z-ai/glm-5.3",
  });
  assert.deepEqual(splitModel("anthropic/claude-sonnet-5-5"), {
    provider: "anthropic",
    model: "claude-sonnet-5-5",
  });
  assert.equal(splitModel("glm-5.3").provider, "zai", "a known bare id finds its owner");
  assert.equal(splitModel("z-ai/glm-5.3").model, "z-ai/glm-5.3", "an unknown head is part of the model");
});

test("a loopback target puts the toolbox on the host network, and keeps its address", () => {
  assert.equal(needsHostNetwork("http://127.0.0.1:5001"), true);
  assert.equal(needsHostNetwork("http://localhost:8080/x"), true);
  assert.equal(needsHostNetwork("https://app.example.com"), false);
  // On the host network the loopback is shared, so no rewriting happens.
  assert.equal(toolboxTarget("http://127.0.0.1:5001"), "http://127.0.0.1:5001");
  assert.equal(toolboxTarget("https://app.example.com/x"), "https://app.example.com");
});

test("a map written to a file is described rather than echoed", () => {
  assert.equal(
    summariseJson('{"origin":"http://t","pages":[1,2,3],"parameters":[]}'),
    "origin: string, pages: 3, parameters: 0",
  );
  assert.equal(summariseJson("[1,2]"), "array of 2");
  assert.equal(summariseJson("nope"), "not valid JSON");
});

test("the same endpoint written three ways counts once", () => {
  const same = ["http://127.0.0.1:5001/login", "/login", "/login/", " /Login "];
  assert.equal(new Set(same.map(endpointKey)).size, 1);
  assert.notEqual(endpointKey("/login"), endpointKey("/logout"));
  assert.equal(endpointKey("http://h/"), "/", "a bare origin is the root");
  assert.equal(
    endpointKey("mutation importPaste(a, b)"),
    "mutation importpaste(a, b)",
    "a GraphQL entry keeps its argument list",
  );
});

test("raw bytes are framed exactly as the caller typed them", () => {
  assert.deepEqual(
    [...unescapeBytes("GET / HTTP/1.1\\r\\nHost: h\\r\\n\\r\\n")],
    [...Buffer.from("GET / HTTP/1.1\r\nHost: h\r\n\r\n")],
    "the escapes are resolved and nothing else is added",
  );
  assert.equal(unescapeBytes("\\x41\\x42").toString(), "AB", "a byte can be given in hex");
  assert.equal(unescapeBytes("a\\0b").length, 3, "a NUL survives");
  assert.equal(unescapeBytes("C:\\path").toString(), "C:\\path", "an unknown escape stays as typed");
  assert.equal(unescapeBytes("x\\").toString(), "x\\", "a trailing backslash is not an escape");
});

test("a raw probe is recorded the way the proxy records a request", () => {
  const bytes = Buffer.from("HTTP/1.1 501 Not Implemented\r\n\r\n");
  const rec = rawRecord(
    { host: "t.lab", port: 443, tls: true, half_close: true, why: "0.CL probe" },
    [
      { bytes: "POST /x HTTP/1.1\\r\\nHost: t.lab\\r\\n\\r\\n" },
      { bytes: "GET /y HTTP/1.1\\r\\n\\r\\n", delay_ms: 50 },
    ],
    { sent: [33, 19], received: bytes.length, bytes, dur: 0.5, cut: false },
    "probe",
    1_000_000_000_000,
  );
  assert.equal(rec.kind, "raw", "scripts/traffic selects records by kind");
  assert.equal(rec.scheme, "https");
  assert.equal(rec.host, "t.lab");
  assert.equal(rec.port, 443);
  assert.equal(rec.m, "POST");
  assert.equal(rec.p, "/x", "the first request line is the index line");
  assert.equal(rec.s, 501, "the status is read out of what came back");
  assert.equal(rec.t, 999_999_999.5, "t is when the connection opened, in seconds");
  assert.equal(rec.half_close, true);
  assert.deepEqual(rec.writes, [{ bytes: 33, delay_ms: 0 }, { bytes: 19, delay_ms: 50 }]);
  assert.equal(
    Buffer.from(rec.req as string, "base64").toString(),
    "POST /x HTTP/1.1\r\nHost: t.lab\r\n\r\nGET /y HTTP/1.1\r\n\r\n",
    "the record replays byte for byte",
  );
  assert.deepEqual(requestLine(Buffer.from("POST /x?a=1 HTTP/1.1\r\n")), { m: "POST", p: "/x?a=1" });
  assert.equal(statusOf(Buffer.from("nothing came back")), null, "no status is null, not a guess");
});

test("a screenshot is named after the page it shows", () => {
  assert.equal(
    shotName("http://127.0.0.1:5001/a/b?q=1", "victim", new Date("2026-11-14T10:20:30Z")),
    "2026-11-14T10-20-30-victim-127-0-0-1-5001-a-b-q-1.png",
  );
  assert.equal(
    shotName("about:blank", "default", new Date("2026-11-14T10:20:30Z")),
    "2026-11-14T10-20-30-default-blank.png",
  );
});

test("an exploit worker cannot confirm its own finding", () => {
  // The prompt forbids it, but a prompt is not a control. A worker that writes
  // `confirmed` anyway must land as a candidate, or the validate phase is
  // optional in practice and the one measured safeguard is gone.
  assert.equal(verdictState("confirmed", "exploit"), "candidate");
  assert.equal(verdictState("confirmed", "validate"), "confirmed");
  assert.equal(verdictState("rejected", "validate"), "rejected");
  assert.equal(verdictState(" Candidate ", "exploit"), "candidate");
  assert.equal(verdictState("nonsense", "exploit"), "tested", "an unreadable state means it was looked at");
  assert.equal(isResolved("candidate"), false);
  assert.equal(isResolved("rejected"), true, "a rejection is an answer, not an omission");
});

test("the validator resolves a candidate and nothing walks it back", () => {
  const dir = mkdtempSync(join(tmpdir(), "mythos-ledger-"));
  const ledger = new Ledger(dir);
  ledger.record("/transfer", "candidate", "negative amount seems to credit", "exploit-w1");
  assert.equal(ledger.unresolved().length, 1);
  assert.equal(ledger.summary().candidate, 1);

  ledger.record("/transfer", "confirmed", "replayed, control differs", "validator");
  assert.equal(ledger.unresolved().length, 0);
  assert.equal(ledger.summary().confirmed, 1);
  assert.equal(ledger.summary().candidate, 0);

  // A second Ledger over the same directory reads the resolved state back, so a
  // resumed or retried phase cannot reopen a finding that was reproduced.
  const reread = new Ledger(dir);
  assert.equal(reread.get("/transfer")?.state, "confirmed");
  assert.equal(reread.unresolved().length, 0);
});

// ---------------------------------------------------------------------------
// The command line itself.
//
// Four things the guidelines make non-negotiable and a reader cannot check by
// eye after every change: colour is off unless the stream and the environment
// both allow it, --quiet and --verbose actually move what is printed, --json
// puts nothing but the document on stdout, and the exit code says which kind
// of failure happened. The last two are checked by running the built CLI,
// because they are properties of the process and not of a function.
// ---------------------------------------------------------------------------

test("colour is decided by the stream and the environment, in that precedence", () => {
  const tty = { isTTY: true };
  const pipe = { isTTY: false };
  assert.equal(colourEnabled(tty, {}, []), true, "a terminal gets colour");
  assert.equal(colourEnabled(pipe, {}, []), false, "a pipe does not: clig.dev, and it is what leaks ANSI into a log");
  assert.equal(colourEnabled(tty, { NO_COLOR: "1" }, []), false, "NO_COLOR, set to anything non-empty");
  assert.equal(colourEnabled(tty, { NO_COLOR: "" }, []), true, "an empty NO_COLOR is not set, per no-color.org");
  assert.equal(colourEnabled(tty, {}, ["--no-color"]), false, "the flag works too");
  assert.equal(
    colourEnabled(tty, { FORCE_COLOR: "1" }, ["--no-color"]),
    false,
    "a flag outranks the environment",
  );
  assert.equal(colourEnabled(tty, { NO_COLOR: "1", FORCE_COLOR: "1" }, []), false, "NO_COLOR outranks FORCE_COLOR");
  assert.equal(colourEnabled(pipe, { FORCE_COLOR: "1" }, []), true, "forced colour reaches a pipe");
  assert.equal(colourEnabled(pipe, { CLICOLOR_FORCE: "1" }, []), true, "the BSD spelling of the same thing");
  assert.equal(colourEnabled(tty, { FORCE_COLOR: "0" }, []), false, "FORCE_COLOR=0 means never, as Node reads it");
  assert.equal(colourEnabled(tty, { TERM: "dumb" }, []), false, "a dumb terminal cannot show it");
  assert.equal(colourEnabled(tty, { MYTHOS_THEME: "mono" }, []), false);
});

test("--quiet and --verbose move the line, and neither drops an outcome", () => {
  const call = { t: "tool:call", id: "w1", tool: "request", summary: "GET /" } as const;
  const result = { t: "tool:result", id: "w1", tool: "request", ok: true, summary: "200" } as const;
  const finding = { t: "finding", id: "f1", title: "leaked key", severity: "high" } as const;
  const refusal = { t: "guard", kind: "destructive", action: "block", message: "refused" } as const;

  assert.equal(renderLine(call, 0), null, "quiet drops the step-by-step");
  assert.ok(renderLine(call, 1), "normal narrates it");
  assert.equal(renderLine(result, 1), null, "a successful result is implied by the next call");
  assert.ok(renderLine(result, 2), "verbose shows it");
  // Everything an unattended run exists to report survives every level: a quiet
  // log that could not say what was found would be worse than no log at all.
  for (const level of [0, 1, 2] as const) {
    assert.ok(renderLine(finding, level), `a finding survives level ${level}`);
    assert.ok(renderLine(refusal, level), `a refusal survives level ${level}`);
    assert.ok(renderLine({ t: "run:end", ok: true, wall: 1, summary: "s" }, level), `the verdict survives ${level}`);
  }
});

const CLI = join(dirname(fileURLToPath(import.meta.url)), "index.js");
const mythos = (...argv: string[]) =>
  spawnSync(process.execPath, [CLI, ...argv], {
    encoding: "utf8",
    // A pipe, not a terminal: this is also how the non-TTY fallback is checked.
    env: { ...process.env, MYTHOS_HOME: join(tmp, "home"), NO_COLOR: "" },
  });

test("the exit code says which kind of failure it was", () => {
  assert.equal(mythos("--help").status, 0, "0: help is not a failure");
  assert.equal(mythos("--version").status, 0);
  assert.equal(mythos("--frobnicate").status, 2, "2: a flag that does not exist, nothing ran");
  assert.equal(mythos("frobnicate").status, 2, "2: a command that does not exist");
  assert.equal(mythos("doctor", "--headed").status, 2, "2: a flag of another command");
  assert.equal(mythos("login").status, 2, "2: a required argument missing");
  assert.equal(mythos("-t", "https://example.com", "--no-input").status, 2, "2: a confirmation that cannot be asked");

  // 1, not 2: the directory is a real engagement and was read, it simply never
  // got far enough to write a ledger. A wrapper may retry a 1 and must not retry a 2.
  const dir = mkdtempSync(join(tmpdir(), "mythos-empty-"));
  writeFileSync(join(dir, "scope.yaml"), "target: http://127.0.0.1:1\n");
  const r = mythos("verdicts", dir);
  assert.equal(r.status, 1);
  assert.equal(r.stdout, "", "a failure says nothing on stdout");
  assert.match(r.stderr, /no verdict ledger/);
});

test("a usage error names the next command, and never lands on stdout", () => {
  const r = mythos("login", "nosuchprovider");
  assert.equal(r.stdout, "");
  assert.match(r.stderr, /unknown provider/);
  assert.match(r.stderr, /next: mythos providers/, "every error carries the one command that answers it");
});

test("--json writes one document to stdout and nothing else", () => {
  const r = mythos("providers", "--json");
  assert.equal(r.status, 0);
  const doc = JSON.parse(r.stdout) as Array<{ id: string; usable: boolean }>;
  assert.ok(doc.length > 0 && doc.every((p) => typeof p.id === "string"));
  assert.ok(!r.stdout.includes("\u001b"), "no escape sequences in a redirected document");
  assert.ok(!/Providers|Subscription/.test(r.stdout), "no human prose on stdout");
  // And the flag is refused where there is no document, rather than printing nothing.
  assert.equal(mythos("demo", "--json").status, 2);
});

test("a stdout that is not a terminal gets the line logger, unasked", () => {
  // No -n: the view would redraw a terminal that is not there. The timestamped
  // lines are the whole point of 'mythos ... | tee run.log'.
  const r = mythos("demo");
  assert.equal(r.status, 0);
  assert.ok(!r.stdout.includes("\u001b"), "no cursor tricks and no colour into a pipe");
  assert.match(r.stdout, /^\d\d:\d\d:\d\d target http/, "one line per event, each one stamped");
  assert.ok(!r.stdout.includes("\u2588"), "and no block-letter wordmark");
});

test("the guard sees a URL in the middle of an argument, not only at its start", () => {
  // `--map host=URL` and `--registry-base npm=URL` are how two capability
  // scripts take a second destination. The old extraction kept only arguments
  // that *began* with http, so those hosts reached the network unvetted.
  assert.deepEqual(argUrls(["--map", "app.test=https://evil.test/fp"]), ["https://evil.test/fp"]);
  assert.deepEqual(argUrls(["http://a.test/", "--state", "https://b.test/x"]),
    ["http://a.test/", "https://b.test/x"]);
  assert.deepEqual(argUrls(["--limit", "10"]), [], "a plain argument carries no destination");
});

test("inconclusive is a verdict of its own, not quietly folded into tested", () => {
  // Five capability scripts return `inconclusive` where no oracle could decide
  // (a 403 that may be a policy or a missing route, a hit rate whose interval
  // straddles the control). Mapping it to `tested` would print "tested, nothing
  // proven" over an endpoint nobody could judge.
  assert.equal(verdictState("inconclusive"), "inconclusive");
  assert.equal(verdictState("inconclusive", "exploit"), "inconclusive");
  assert.ok(isResolved("inconclusive"), "validate owes it nothing further");
  assert.equal(verdictState("probably fine"), "tested", "an unoffered word stays cautious");
  assert.equal(verdictState("confirmed", "exploit"), "candidate", "and never confirmed");
  const l = new Ledger(mkdtempSync(join(tmpdir(), "mythos-verdicts-")));
  l.record("GET /a", "inconclusive", "no owner view to compare against", "x");
  assert.equal(l.summary().inconclusive, 1);
  assert.equal(l.unresolved().length, 0);
});

process.stdout.write(`\n${ran} checks passed\n`);
