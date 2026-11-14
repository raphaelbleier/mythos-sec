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
import { chunk } from "./driver.js";
import { parseYaml, readScope } from "./scope.js";
import { endpointKey, surfaceFromMap } from "./verdicts.js";
import { shq, summariseJson } from "./agent/tools.js";
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

process.stdout.write(`\n${ran} checks passed\n`);
