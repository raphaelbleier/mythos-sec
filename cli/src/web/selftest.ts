/**
 * The runnable check for `mythos web`: `node dist/web/selftest.js`.
 *
 * No network beyond a server this file starts on 127.0.0.1 on a random port, no
 * model, no docker, no engagement of its own — it builds a fixture engagement
 * in a temp directory and talks to the real server over real HTTP, because the
 * five claims below are claims about what goes over the wire and a unit test of
 * the handler would not catch a header that never gets set.
 *
 * What it proves, in order:
 *
 *   1. a request without the token is refused, and so is a near-miss token
 *   2. a non-loopback bind is refused unless it was asked for explicitly
 *   3. a path that climbs out of the engagement directory is refused
 *   4. the CSP is on every response, including the 401 and the stylesheet
 *   5. a stored-XSS payload captured from a target comes back inert: escaped in
 *      the JSON, never served as a document, and never handed to a DOM sink —
 *      the shipped page has no `innerHTML`, no `eval` and no `new Function`
 *
 * Each assert carries the sentence it is defending, so a failure says what
 * broke rather than which line it broke on.
 */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PathError, engagementDir, fileIn, summary, trafficRecord } from "./data.js";
import { CSP, assetDir, hostOk, isLoopback, safeJson, serve, tokenOk } from "./server.js";

let ran = 0;
const tests: Array<[string, () => Promise<void> | void]> = [];
const test = (name: string, fn: () => Promise<void> | void) => tests.push([name, fn]);

/** The payload. It is the shape a real target reflected in this project's own
 *  lab: it sets document.title and marks the body, so if it ever executed in
 *  this UI the page would say so out loud. */
const XSS = `<img src=x onerror="document.title='XSS-OWNED';document.body.setAttribute('data-xss','1')"><script>alert(1)</script>`;

function fixture(): { root: string; dir: string } {
  const root = mkdtempSync(join(tmpdir(), "mythos-web-"));
  const name = "127.0.0.1-5001-29991231";
  const dir = join(root, name);
  mkdirSync(join(dir, "traffic"), { recursive: true });
  mkdirSync(join(dir, "findings"), { recursive: true });

  writeFileSync(join(dir, "scope.yaml"), [
    "target: http://127.0.0.1:5001",
    "in_scope:",
    "  - 127.0.0.1",
    "out_of_scope: []",
    "ports: [5001]",
    "rules:",
    "  rate_limit_rps: 5",
    "  allow_active: true",
    "  allow_exploit: true",
    'notes: "fixture"',
    "",
  ].join("\n"));

  writeFileSync(join(dir, "surface.json"), JSON.stringify({
    origin: "http://127.0.0.1:5001",
    reachable_paths: [{ path: "/search" }, { path: "/never-looked-at" }],
  }));
  writeFileSync(join(dir, "verdicts.json"), JSON.stringify([
    { endpoint: "/search", state: "confirmed", note: "reflected, control escapes", by: "-search.md", at: "2999-12-31T00:00:00Z" },
  ]));
  writeFileSync(join(dir, "run-events.jsonl"), [
    JSON.stringify({ ts: "2999-12-31T00:00:00Z", t: "run:start", target: "http://127.0.0.1:5001", dir, model: "m", budget: 60 }),
    JSON.stringify({ ts: "2999-12-31T00:00:01Z", t: "phase:start", phase: "recon", attempt: 1, of: 3, model: "m", budget: 30 }),
    JSON.stringify({ ts: "2999-12-31T00:00:09Z", t: "phase:end", phase: "recon", state: "done", wall: 8 }),
    JSON.stringify({ ts: "2999-12-31T00:00:10Z", t: "guard", kind: "scope", action: "warn", message: "⚠️  MYTHOS SCOPE GUARD: this command targets host(s) that are OUT OF SCOPE: evil.example" }),
    JSON.stringify({ ts: "2999-12-31T00:00:11Z", t: "run:end", ok: true, wall: 11, summary: "1 finding" }),
  ].join("\n") + "\n");

  // One recorded exchange whose response body is the payload, exactly as the
  // proxy would have written it: base64 of the bytes that crossed the wire.
  const res = Buffer.from(
    `HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ${XSS.length}\r\n\r\n${XSS}`,
    "latin1",
  );
  const req = Buffer.from("GET /search?q=payload HTTP/1.1\r\nHost: 127.0.0.1:5001\r\n\r\n", "latin1");
  writeFileSync(join(dir, "traffic", "log.jsonl"), JSON.stringify({
    kind: "exchange", t: 1, dur: 0.01, client: "127.0.0.1:1", scheme: "http",
    host: "127.0.0.1", port: 5001, ip: "127.0.0.1", m: "GET", p: "/search?q=payload", s: 200,
    ua: "curl", req: req.toString("base64"), res: res.toString("base64"),
    req_cut: false, res_cut: false,
  }) + "\n");

  writeFileSync(join(dir, "findings.json"), JSON.stringify({
    engagement: name,
    findings: [{
      id: "xss-search", file: "xss-search.md", title: "Reflected XSS in /search",
      class: "xss", state: "validated", asset: "http://127.0.0.1:5001/search",
      param: "q", route: "/search", cwe: 79,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", cvss_score: 6.1,
      severity: "medium", proof: "traffic/1", negative_control: "traffic/1",
      problems: [], evidence: `## Exact request\n\n\`\`\`\n${XSS}\n\`\`\`\n`,
    }],
    counts: { validated: 1 }, problems: [],
  }));
  writeFileSync(join(dir, "report.md"), `# Report\n\nOne finding. The payload was \`${XSS}\`.\n`);
  return { root, dir };
}

const { root, dir } = fixture();

// ------------------------------------------------------------ pure checks

test("a near-miss token is not a token", () => {
  assert.equal(tokenOk("abc123", "abc123"), true);
  assert.equal(tokenOk("abc123", "abc124"), false, "one wrong byte is a wrong token");
  assert.equal(tokenOk("abc123", "abc12"), false, "a prefix is not a token");
  assert.equal(tokenOk("abc123", "abc1234"), false, "nor is a superstring");
  assert.equal(tokenOk("abc123", ""), false);
  assert.equal(tokenOk("abc123", null), false, "no token at all is not a pass");
});

test("the bind check knows what loopback is", () => {
  for (const ok of ["127.0.0.1", "::1", "[::1]", "localhost"]) {
    assert.equal(isLoopback(ok), true, `${ok} is loopback`);
  }
  for (const bad of ["0.0.0.0", "192.168.1.10", "::", "example.com"]) {
    assert.equal(isLoopback(bad), false, `${bad} is not loopback and must not be bound by default`);
  }
});

test("a non-loopback bind is refused unless it was asked for", async () => {
  await assert.rejects(
    () => serve({ root, host: "0.0.0.0" }),
    /refusing to bind/,
    "binding every interface exposes engagement data and needs an explicit flag",
  );
  await assert.rejects(() => serve({ root, host: "192.168.1.10" }), /refusing to bind/);
});

test("the Host check stops a rebound name from reaching the API", () => {
  assert.equal(hostOk("127.0.0.1", "127.0.0.1:8080", 8080), true);
  assert.equal(hostOk("127.0.0.1", "localhost:8080", 8080), true);
  assert.equal(hostOk("127.0.0.1", "rebind.attacker.example:8080", 8080), false,
    "a name that resolves to 127.0.0.1 is still not a host we answer to");
  assert.equal(hostOk("127.0.0.1", undefined, 8080), false);
});

test("a path that climbs out of the engagement is refused", () => {
  assert.throws(() => engagementDir(root, "../../etc"), PathError, "../.. must not escape the root");
  assert.throws(() => engagementDir(root, "/etc"), PathError, "an absolute path is not a name under the root");
  assert.throws(() => engagementDir(root, "."), PathError, "the root itself is not an engagement");
  assert.throws(() => fileIn(dir, "../other/scope.yaml"), PathError);
  assert.throws(() => fileIn(dir, "../../../../etc/passwd"), PathError);
  assert.throws(() => fileIn(dir, "/etc/passwd"), PathError);
  // The legitimate shapes still resolve, or the check would be useless by
  // being too strict to use.
  assert.ok(fileIn(dir, "report.md").endsWith("report.md"));
  assert.ok(fileIn(dir, "evidence/x/manifest.json").includes("evidence"));
});

test("JSON carries no character that could start a tag", () => {
  const out = safeJson({ body: XSS });
  assert.ok(!out.includes("<"), "a < in a captured body must be escaped before it leaves the server");
  assert.ok(!out.includes(">"), "and so must a >");
  assert.ok(out.includes("\\u003c"), "it survives as an escape, so the data is not altered");
  assert.deepEqual(JSON.parse(out), { body: XSS }, "escaping is lossless: the record still holds the real bytes");
});

test("the shipped page has no DOM sink a payload could reach", () => {
  const js = readFileSync(join(assetDir(), "app.js"), "utf8");
  const code = js.replace(/^\s*\*.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
  for (const sink of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"]) {
    assert.ok(!code.includes(sink), `${sink} must not appear in the page: a captured payload would reach it`);
  }
  assert.ok(code.includes("createElement"), "the page builds elements, which is what makes the above true");
  const html = readFileSync(join(assetDir(), "index.html"), "utf8");
  assert.ok(!/<script(?![^>]*\bsrc=)/i.test(html), "no inline script, because the CSP forbids one");
});

test("the recorded payload is read back as the bytes it was", () => {
  const rec = trafficRecord(dir, 1);
  assert.ok(rec, "the fixture exchange is readable");
  assert.ok(rec.response.text.includes("onerror"), "the UI does not sanitise evidence; it renders it inert");
  // Verified against `scripts/traffic`'s own byte_shape on the same bytes:
  // both print "181 bytes, sha256 e63118b84a5c4025, 4 CRLF, 0 bare LF, 0 bare CR".
  assert.equal(
    rec.response.shape,
    "181 bytes, sha256 e63118b84a5c4025, 4 CRLF, 0 bare LF, 0 bare CR",
    "the byte shape is character-for-character the one scripts/traffic prints",
  );
  assert.equal(summary(dir).open, 1, "an endpoint mapped and never judged shows as the gap it is");
});

// ------------------------------------------------------------ over HTTP

test("the server refuses, serves and never widens", async () => {
  const web = await serve({ root });
  const base = `http://127.0.0.1:${web.port}`;
  const get = (path: string, init?: RequestInit) => fetch(base + path, init);
  const withToken = (path: string) =>
    fetch(base + path, { headers: { Authorization: `Bearer ${web.token}` } });

  try {
    // 1. the token
    const bare = await get("/");
    assert.equal(bare.status, 401, "the page itself needs the token");
    const wrong = await get(`/?t=${web.token.slice(0, -1)}x`);
    assert.equal(wrong.status, 401, "a wrong token is not a token");
    const css = await get("/app.css");
    assert.equal(css.status, 401, "assets are checked too, not only the API");
    const apiBare = await get("/api/engagements");
    assert.equal(apiBare.status, 401);

    const ok = await get(`/?t=${web.token}`);
    assert.equal(ok.status, 200, "the printed URL works");
    assert.ok((await ok.text()).includes("MYTHOS"), "and it is the shell");

    // 2. the headers, on every kind of response
    for (const res of [bare, ok, css, await withToken("/app.css"), await withToken("/api/engagements")]) {
      assert.equal(res.headers.get("content-security-policy"), CSP, "the CSP is on every response");
      assert.equal(res.headers.get("x-content-type-options"), "nosniff");
      assert.equal(res.headers.get("access-control-allow-origin"), null,
        "no CORS header, ever: another origin must not be able to read an engagement");
      assert.equal(res.headers.get("set-cookie"), null, "no cookie, so nothing is sent ambiently");
    }
    assert.ok(CSP.includes("default-src 'none'"), "the policy starts closed");
    assert.ok(!CSP.includes("unsafe-inline"), "and never allows inline script or style");

    // 3. read-only
    const post = await fetch(`${base}/api/engagements?t=${web.token}`, { method: "POST" });
    assert.equal(post.status, 405, "there is no write path to reach");

    // 4. traversal, over the wire
    for (const bad of ["../../../../etc/passwd", "/etc/passwd", "..%2f..%2fscope.yaml"]) {
      const res = await withToken(`/api/e/${dir.split("/").at(-1)}/download?path=${encodeURIComponent(bad)}`);
      assert.ok(res.status === 400 || res.status === 404,
        `a traversal path must not be served (${bad} returned ${res.status})`);
    }
    const escape = await withToken(`/api/e/${encodeURIComponent("../..")}/summary`);
    assert.equal(escape.status, 400, "nor may the engagement name climb out of the root");

    // 5. the payload, over the wire
    const name = dir.split("/").at(-1)!;
    const rec = await withToken(`/api/e/${name}/traffic/1`);
    assert.equal(rec.headers.get("content-type"), "application/json; charset=utf-8",
      "a captured body leaves as data, never as a document");
    const body = await rec.text();
    assert.ok(!body.includes("<img"), "the payload is escaped on the way out");
    assert.ok(!body.includes("<script"), "including the script tag");
    assert.ok(JSON.parse(body).response.text.includes("<img src=x"),
      "and it is still the real bytes once parsed, because evidence must not be altered");

    // An evidence file is handed over as an opaque attachment, so a captured
    // HTML page is never rendered as a document by this origin.
    const report = await withToken(`/api/e/${name}/download?path=report.md`);
    assert.equal(report.headers.get("content-type"), "application/octet-stream");
    assert.match(report.headers.get("content-disposition") ?? "", /^attachment/);
    const inline = await withToken(`/api/e/${name}/image?path=report.md`);
    assert.equal(inline.status, 415, "only a real image may render inline");

    assert.ok(web.url.startsWith("http://127.0.0.1:"), "the printed URL is loopback");
    assert.ok(web.url.includes(web.token), "and it carries the token, which is the only way in");
  } finally {
    await web.close();
  }
});

async function main() {
  for (const [name, fn] of tests) {
    await fn();
    ran += 1;
    process.stdout.write(`  ok  ${name}\n`);
  }
  process.stdout.write(`\n${ran} checks passed\n`);
}

void main().catch((e: Error) => {
  process.stderr.write(`\nFAILED: ${e.message}\n${e.stack ?? ""}\n`);
  process.exit(1);
});
