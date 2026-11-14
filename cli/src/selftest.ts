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
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chunk, verdictState } from "./driver.js";
import { parseYaml, readScope } from "./scope.js";
import { Ledger, endpointKey, isResolved, surfaceFromMap } from "./verdicts.js";
import { shq, summariseJson } from "./agent/tools.js";
import { shotName } from "./agent/browser.js";
import { rawRecord, requestLine, statusOf, unescapeBytes } from "./agent/raw.js";
import { splitModel } from "./providers/registry.js";
import { needsHostNetwork, toolboxTarget } from "./prompts.js";

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

process.stdout.write(`\n${ran} checks passed\n`);
