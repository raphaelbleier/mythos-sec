/**
 * The agent's whole reach: six tools, and nothing else.
 *
 * Everything that touches the target goes through `Guards.vet` first, and
 * everything that runs a security tool runs it inside the Kali container, not
 * on the operator's machine. The small set is deliberate. The published
 * evidence on these agents is that the tool layer decides the outcome — in one
 * study every model scored zero without high-level actions, and small models
 * with them beat large models without — so the useful work is making a few
 * tools carry a lot, not giving the model a wide menu.
 *
 * `script` is where that happens: probe, verify, coverage, findings and cvefeed
 * each collapse what would otherwise be dozens of model round trips into one
 * deterministic call, and they stay Python because they are tested, have
 * selftests, and are the files an auditor reads.
 */
import { execFile } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { REPO, script as scriptPath } from "../paths.js";
import type { Bus } from "../bus.js";
import type { Scope } from "../scope.js";
import { GuardRefusal, type Guards } from "./guards.js";
import { Browser } from "./browser.js";
import { sendRaw } from "./raw.js";

export interface ToolContext {
  scope: Scope;
  guards: Guards;
  bus: Bus;
  agentId: string;
  /** Shared across the phase so the browser is launched at most once. */
  browser: Browser;
}

const MAX_OUT = 24_000;

/** One entry of the script allowlist: what it is for, where it is, what it touches. */
interface ScriptEntry {
  what: string;
  /** Relative to the repository root, for a script that lives beside its skill. */
  path?: string;
  /** It sends requests at the target, so it is vetted and recorded. */
  reaches?: boolean;
}

function clip(s: string, max = MAX_OUT): string {
  if (s.length <= max) return s;
  const head = s.slice(0, Math.floor(max * 0.7));
  const tail = s.slice(-Math.floor(max * 0.25));
  return `${head}\n\n…[${s.length - head.length - tail.length} characters cut]…\n\n${tail}`;
}

function exec(
  file: string,
  args: string[],
  opts: { cwd?: string; timeout: number; env: NodeJS.ProcessEnv },
): Promise<{ code: number; out: string }> {
  return new Promise((done) => {
    execFile(
      file,
      args,
      { cwd: opts.cwd ?? REPO, timeout: opts.timeout, maxBuffer: 64 << 20, encoding: "utf8",
        env: opts.env },
      (err, stdout, stderr) => {
        const e = err as (Error & { code?: number | string; killed?: boolean }) | null;
        const out = [stdout, stderr].filter(Boolean).join("\n").trim();
        if (e?.killed) {
          done({ code: 124, out: `${out}\n[killed after ${Math.round(opts.timeout / 1000)}s]`.trim() });
          return;
        }
        done({ code: typeof e?.code === "number" ? e.code : e ? 1 : 0, out });
      },
    );
  });
}

/** Paths an agent may read or write: its own engagement directory only. */
function inEngagement(ctx: ToolContext, p: string): string {
  const abs = isAbsolute(p) ? resolve(p) : resolve(ctx.scope.dir, p);
  const rel = relative(ctx.scope.dir, abs);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(
      `${p} is outside the engagement directory. Files go under ${ctx.scope.dir}; ` +
        `the repository's own skills and knowledge are readable with the 'reference' tool.`,
    );
  }
  return abs;
}

export function buildTools(ctx: ToolContext) {
  /**
   * The environment every child gets.
   *
   * `MYTHOS_SCOPE` is the important one and it was missing. Without it
   * `scripts/mythos` asks `scripts/traffic env` for nothing and injects no proxy
   * variables, so not one request the agent sent was recorded while the prompt
   * told it recording was on; and every host-side script fell back to the newest
   * scope file under `engagements` by modification time, which is how a leftover
   * directory ends up authorizing a run. Both failures are silent, which is why
   * the pin is set here, once, for all of them.
   */
  const env: NodeJS.ProcessEnv = { ...process.env, MYTHOS_SCOPE: ctx.scope.file };

  const announce = (name: string, summary: string) =>
    ctx.bus.emitEvent({ t: "tool:call", id: ctx.agentId, tool: name, summary });
  const settle = (name: string, ok: boolean, summary: string) =>
    ctx.bus.emitEvent({ t: "tool:result", id: ctx.agentId, tool: name, ok, summary });

  const shell = tool({
    description:
      "Run a shell pipeline inside the Kali toolbox container (nuclei, sqlmap, ffuf, httpx, " +
      "katana, dalfox, nikto, whatweb, arjun, jwt_tool, curl, jq, python3 …). The repository is " +
      "at /repo read-only and the engagement directory is writable. Reach a host-bound lab " +
      "target as host.docker.internal:PORT. Every request is recorded by the proxy.",
    inputSchema: z.object({
      command: z.string().describe("one shell pipeline, as you would type it in the container"),
      timeout_s: z.number().int().min(5).max(1800).optional().describe("default 900"),
      why: z.string().describe("one line: what this is meant to establish"),
    }),
    execute: async ({ command, timeout_s, why }) => {
      announce("shell", `${why} — ${command.slice(0, 120)}`);
      let notes: string;
      try {
        // Vet the invocation as it will actually run. The guard's recording
        // rule distinguishes a bare host curl from one inside the toolbox, and
        // it can only do that if it sees the wrapper.
        notes = await ctx.guards.vet(`scripts/mythos sh ${shq(command)}`);
      } catch (e) {
        if (e instanceof GuardRefusal) {
          settle("shell", false, "refused by the guard");
          return e.message;
        }
        throw e;
      }
      const r = await exec(
        "python3",
        [scriptPath("mythos"), "--timeout", String(timeout_s ?? 900), "sh", command],
        { timeout: (timeout_s ?? 900) * 1000 + 30_000, env },
      );
      settle("shell", r.code === 0, `exit ${r.code}, ${r.out.length} bytes`);
      return clip(`${notes}exit code: ${r.code}\n\n${r.out || "(no output)"}`);
    },
  });

  const request = tool({
    description:
      "Send one HTTP request to the target and get the status line, headers and body back. Use " +
      "this for single aimed requests; it is recorded and replayable, and clearer in the report " +
      "than a curl line buried in a pipeline.",
    inputSchema: z.object({
      method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]).default("GET"),
      url: z.string().describe("absolute URL, on a host your scope authorizes"),
      headers: z.array(z.string()).optional().describe("each as 'Name: value'"),
      body: z.string().optional(),
      why: z.string(),
    }),
    execute: async ({ method, url, headers, body, why }) => {
      const parts = ["curl", "-sS", "-i", "--max-time", "30", "-X", method];
      for (const h of headers ?? []) parts.push("-H", shq(h));
      if (body !== undefined) parts.push("--data-binary", shq(body));
      parts.push(shq(url));
      const command = parts.join(" ");
      announce("request", `${why} — ${method} ${url}`);
      let notes: string;
      try {
        notes = await ctx.guards.vet(`scripts/mythos sh ${shq(command)}`);
      } catch (e) {
        if (e instanceof GuardRefusal) {
          settle("request", false, "refused by the guard");
          return e.message;
        }
        throw e;
      }
      const r = await exec("python3", [scriptPath("mythos"), "--timeout", "60", "sh", command], {
        timeout: 90_000,
        env,
      });
      const status = /^HTTP\/[\d.]+ (\d{3})/m.exec(r.out)?.[1] ?? "?";
      settle("request", r.code === 0, `${status}, ${r.out.length} bytes`);
      return clip(`${notes}${r.out || "(no response)"}`);
    },
  });

  /**
   * The deterministic tools: what each is for, where it lives, and whether it
   * reaches the target.
   *
   * `path` exists because six of these were written, given selftests and then
   * unreachable: they ship beside the skill that documents them, under
   * `skills/<name>/scripts/`, and this map was the allowlist while it could only
   * resolve `scripts/<name>`. `reaches` decides two things that have to agree:
   * whether the guards vet the call, and whether it runs through
   * `scripts/traffic exec` so its requests appear in the recording. A script
   * that sends requests and is not marked is the one part of an engagement a
   * reader cannot replay.
   */
  const SCRIPTS = {
    probe: {
      what: "map the surface: GET only, plus the GraphQL introspection POST. --json for a map.",
      reaches: true,
    },
    verify: {
      what: "send benign canaries at named parameters and judge each against an oracle.",
      reaches: true,
    },
    coverage: { what: "which mapped paths the report does not account for yet. Exits 1 while any remain." },
    findings: { what: "build findings.json and SARIF from findings/*.md, with CVSS computed from vectors." },
    cvefeed: { what: "ranked CVE candidates for the fingerprinted stack, from KEV, EPSS, NVD, GHSA, OSV." },
    sourcemap: { what: "routes, missing guards and sinks from a source tree (grey box only)." },
    traffic: { what: "what was recorded: summary, list, show ID, replay ID, export HAR." },
    watch: { what: "what changed on this target since the last engagement." },
    lessons: { what: "class priors from past engagements (an untested hypothesis, treat as a hint)." },
    triage: {
      what:
        "rank the endpoints in surface.json by how likely each is to carry a flaw, so the " +
        "exploit fan-out starts with the best ones.",
    },
    evidence: {
      what:
        "assemble one finding's bundle: the request, the response that proves it, the negative " +
        "control and the artifacts it cites.",
    },
    clientside: {
      what:
        "the client-side classes in a real browser: sink hooks, postMessage, DOM clobbering, " +
        "prototype pollution, CSP.",
      reaches: true,
    },
    apiproto: {
      what: "the non-REST protocols: GraphQL, gRPC-web, tRPC, JSON-RPC batches, OData, SOAP.",
      reaches: true,
    },
    authflows: {
      what:
        "exercise the authentication flows per role: OAuth and OIDC, SAML, reset, MFA, session " +
        "fixation.",
      reaches: true,
    },
    ssrfprobe: {
      what:
        "send SSRF candidates at in-scope destinations and the lab metadata emulator, and judge " +
        "each callback.",
      reaches: true,
    },
    aiplatform: {
      what:
        "fingerprint AI platforms and surfaces, then a mutating prompt-injection pass with a " +
        "control per variant.",
      reaches: true,
    },
    "auth-login": {
      what:
        "log in once as one role and persist the session for every later tool: a Playwright " +
        "storage state, a header file, nuclei secrets.",
      path: "skills/auth-session/scripts/auth_login.py",
      reaches: true,
    },
    "session-check": {
      what:
        "check each saved role session against an authenticated baseline GET and re-run its " +
        "login when it is dead. Exit 1 while a role is still dead.",
      path: "skills/auth-session/scripts/session_check.py",
      reaches: true,
    },
    "bola-diff": {
      what:
        "replay id-bearing endpoints as the owner, as another user and anonymously, and class " +
        "each as candidate, enforced or review.",
      path: "skills/business-logic/scripts/bola_diff.py",
      reaches: true,
    },
    "mass-assign": {
      what:
        "'fields' diffs an OpenAPI spec for fields a write returns but does not accept; " +
        "'probe' proves one on an object you own, with a GET before and after.",
      path: "skills/business-logic/scripts/mass_assign.py",
      reaches: true,
    },
    race: {
      what:
        "race a one-shot resource you created yourself: a sequential wave against a parallel " +
        "wave, judged by the authoritative state.",
      path: "skills/business-logic/scripts/race.py",
      reaches: true,
    },
    "xss-verify": {
      what:
        "'token' mints a per-point XSS token and its payloads; 'verify' opens the render page " +
        "as another role and waits for the dialog, console line or OAST hit.",
      path: "skills/stored-xss-oast/scripts/xss_verify.py",
      reaches: true,
    },
  } as const satisfies Record<string, ScriptEntry>;

  const scriptTool = tool({
    description:
      "Run one of the project's deterministic tools. These replace whole conversations with the " +
      "model, so reach for them before writing a paragraph:\n" +
      Object.entries(SCRIPTS)
        .map(([k, v]) => `  ${k}: ${v.what}`)
        .join("\n"),
    inputSchema: z.object({
      name: z.enum(Object.keys(SCRIPTS) as [keyof typeof SCRIPTS, ...Array<keyof typeof SCRIPTS>]),
      args: z.array(z.string()).default([]),
      out: z
        .string()
        .optional()
        .describe(
          "write stdout to this file in the engagement directory instead of returning it. " +
            "Use it for every --json run, above all `probe ... --json out: surface.json`.",
        ),
      timeout_s: z.number().int().min(5).max(1800).optional(),
      why: z.string(),
    }),
    execute: async ({ name, args, out, timeout_s, why }) => {
      announce("script", `${why} — ${name} ${args.join(" ")}`);
      const entry: ScriptEntry = SCRIPTS[name];
      const file = entry.path ? resolve(REPO, entry.path) : scriptPath(name);
      // A script that reaches the target is vetted like any request. Every URL
      // in the arguments is checked, not only the first: these scripts take a
      // base, a check URL and a state URL, and a slip in the second one is
      // still a slip.
      if (entry.reaches) {
        const urls = args.filter((a) => a.startsWith("http"));
        if (urls.length) {
          try {
            await ctx.guards.vet(`${name} ${urls.join(" ")}`);
          } catch (e) {
            if (e instanceof GuardRefusal) {
              settle("script", false, "refused by the guard");
              return e.message;
            }
            throw e;
          }
        }
      }
      const t = (timeout_s ?? 600) * 1000;
      // These send requests from the host, not from the container, so they get
      // the proxy variables the way a host command does: through
      // `scripts/traffic exec`. Without it their traffic is the one part of an
      // engagement that never appears in the recording, which is exactly the
      // surface map, the canary pass and the role replays a reader would most
      // want to replay.
      const argv = entry.reaches
        ? [scriptPath("traffic"), "--dir", ctx.scope.dir, "exec", "--", "python3", file, ...args]
        : [file, ...args];
      const r = await exec("python3", argv, { timeout: t, cwd: REPO, env });
      settle("script", r.code === 0, `${name} exit ${r.code}`);

      // Routing a surface map through the model and back out is how a truncated
      // surface.json gets written: the result is clipped to fit a context, the
      // agent copies what it was given, and every later phase counts endpoints
      // from the short version without anything saying so. With `out` the bytes
      // go straight to the file and the model gets a description of them.
      if (out) {
        try {
          const abs = inEngagement(ctx, out);
          mkdirSync(resolve(abs, ".."), { recursive: true });
          writeFileSync(abs, r.out);
          const first = r.out.trimStart().slice(0, 1);
          const shape =
            first === "{" || first === "["
              ? summariseJson(r.out)
              : `${r.out.split("\n").length} lines`;
          return `exit code: ${r.code}\nwrote ${r.out.length} bytes to ${out} (${shape})\n\n${clip(r.out, 2000)}`;
        } catch (e) {
          return `exit code: ${r.code}\ncould not write ${out}: ${(e as Error).message}\n\n${clip(r.out)}`;
        }
      }
      return clip(`exit code: ${r.code}\n\n${r.out || "(no output)"}`);
    },
  });

  const files = tool({
    description:
      "Read, write and list files in the engagement directory. Findings go to " +
      "findings/<id>.md, the deliverable to report.md, notes anywhere else. Writing is how work " +
      "survives the end of a phase: the next phase starts with a clean context and reads these " +
      "files, so anything only said in conversation is lost.",
    inputSchema: z.object({
      action: z.enum(["read", "write", "append", "list"]),
      path: z.string().describe("relative to the engagement directory"),
      content: z.string().optional().describe("for write and append"),
    }),
    execute: async ({ action, path, content }) => {
      announce("files", `${action} ${path}`);
      try {
        const abs = inEngagement(ctx, path);
        if (action === "list") {
          const s = await stat(abs).catch(() => null);
          if (!s) return `${path} does not exist`;
          if (!s.isDirectory()) return `${path} is a file, ${s.size} bytes`;
          const entries = await readdir(abs, { withFileTypes: true });
          settle("files", true, `${entries.length} entries`);
          return entries.map((e) => (e.isDirectory() ? `${e.name}/` : e.name)).sort().join("\n") || "(empty)";
        }
        if (action === "read") {
          if (!existsSync(abs)) return `${path} does not exist`;
          const text = readFileSync(abs, "utf8");
          settle("files", true, `${text.length} bytes`);
          return clip(text, 40_000);
        }
        if (content === undefined) return "write and append need 'content'";
        mkdirSync(resolve(abs, ".."), { recursive: true });
        if (action === "append" && existsSync(abs)) {
          writeFileSync(abs, readFileSync(abs, "utf8") + content);
        } else {
          writeFileSync(abs, content);
        }
        settle("files", true, `wrote ${content.length} bytes to ${path}`);
        return `wrote ${content.length} bytes to ${path}`;
      } catch (e) {
        settle("files", false, (e as Error).message);
        return `error: ${(e as Error).message}`;
      }
    },
  });

  const reference = tool({
    description:
      "Read the project's own methodology: skills/<name>/SKILL.md for a phase or a class, " +
      "knowledge/ for per-class confirmation playbooks, AGENTS.md for the rules. Read the skill " +
      "for the phase you are in before you start, and the knowledge file a skill points you to.",
    inputSchema: z.object({
      path: z.string().describe("e.g. skills/exploit/SKILL.md, knowledge/web/ssrf.md, or a directory"),
    }),
    execute: async ({ path }) => {
      announce("reference", path);
      const abs = resolve(REPO, path);
      if (relative(REPO, abs).startsWith("..")) return "only paths inside the repository";
      if (!existsSync(abs)) {
        const dir = resolve(abs, "..");
        const near = existsSync(dir) ? (await readdir(dir)).join(", ") : "";
        return `${path} does not exist.${near ? ` Nearby: ${near}` : ""}`;
      }
      const s = await stat(abs);
      if (s.isDirectory()) {
        const e = await readdir(abs, { withFileTypes: true });
        return e.map((x) => (x.isDirectory() ? `${x.name}/` : x.name)).sort().join("\n");
      }
      const text = readFileSync(abs, "utf8");
      settle("reference", true, `${text.length} bytes`);
      return clip(text, 48_000);
    },
  });

  const browser = tool({
    description:
      "Drive a real Chromium against the target: navigate, click, type, read the rendered DOM, " +
      "run JavaScript in the page, read console messages and network requests. This is the only " +
      "way to reach a client-rendered surface, a DOM sink or a flow behind a login form that " +
      "curl cannot replay.\n" +
      "  init_script: register JavaScript (in 'value') that runs before any page script on every " +
      "navigation. A sink hook has to be installed this way or the page's own scripts run first; " +
      "it applies from the next navigation on.\n" +
      "  context: create or switch to a named browser context ('name'), optionally from a " +
      "Playwright storage state file ('storage_state'). Two contexts hold an attacker role and a " +
      "victim role at once, which is what a postMessage or stored-XSS proof needs.\n" +
      "  cdp: send a Chrome DevTools Protocol 'method' with 'params' and get the result, for " +
      "DOMDebugger.getEventListeners, a virtual authenticator or EventSource capture.\n" +
      "  websocket: the frames seen so far, per socket, sent and received.\n" +
      "  dialog: the alerts, confirms and prompts that fired; they are dismissed as they come, so " +
      "a payload's alert() is recorded instead of freezing the page.\n" +
      "  screenshot: writes a PNG under evidence/ in the engagement directory and returns the path.",
    inputSchema: z.object({
      action: z.enum([
        "goto",
        "click",
        "type",
        "text",
        "html",
        "eval",
        "init_script",
        "cdp",
        "context",
        "websocket",
        "dialog",
        "console",
        "requests",
        "screenshot",
        "close",
      ]),
      url: z.string().optional().describe("for goto"),
      selector: z.string().optional().describe("for click and type"),
      value: z
        .string()
        .optional()
        .describe("text to type, the expression to eval, or the script for init_script"),
      name: z.string().optional().describe("for context: which role to create or switch to"),
      storage_state: z
        .string()
        .optional()
        .describe("for context: a Playwright storage state file, as auth_login.py writes it"),
      method: z.string().optional().describe("for cdp, e.g. DOMDebugger.getEventListeners"),
      params: z.record(z.unknown()).optional().describe("for cdp: the method's parameters"),
      why: z.string(),
    }),
    execute: async ({ action, url, selector, value, name, storage_state, method, params, why }) => {
      announce("browser", `${why} — ${action} ${url ?? selector ?? name ?? method ?? ""}`.trim());
      try {
        if (action === "goto") {
          if (!url) return "goto needs a url";
          await ctx.guards.vet(`chromium ${url}`);
        }
        const out = await ctx.browser.run({
          action,
          url,
          selector,
          value,
          name,
          storage_state,
          method,
          params,
          dir: ctx.scope.dir,
        });
        settle("browser", true, clip(out, 160));
        return clip(out, 32_000);
      } catch (e) {
        if (e instanceof GuardRefusal) {
          settle("browser", false, "refused by the guard");
          return e.message;
        }
        settle("browser", false, (e as Error).message);
        return `error: ${(e as Error).message}`;
      }
    },
  });

  const rawWrite = z.object({
    bytes: z
      .string()
      .describe(
        "the bytes to send, with \\r, \\n, \\t, \\0 and \\xNN resolved. You write the whole " +
          "message: request line, every header, the body. Nothing is added for you, no " +
          "Content-Length, no Host, no trailing CRLF.",
      ),
    delay_ms: z.number().int().min(0).max(30_000).optional().describe("wait this long before sending it"),
  });

  const raw = tool({
    description:
      "Send bytes on a socket you frame yourself, for the attacks a library's writer will not " +
      "produce: 0.CL, CL.0, Expect-based desync, H2.TE, a deliberately ambiguous " +
      "Content-Length/Transfer-Encoding pair, an over-long or malformed request line. You control " +
      "the framing byte for byte and nothing is added for you.\n" +
      "Detection of these is a comparison, not a timing measurement, so send the pair in one " +
      "call: 'baseline' is the control and 'writes' is the trigger, each gets its own fresh " +
      "connection, and both responses come back together to be read against each other.\n" +
      "This bypasses the recording proxy, which is an HTTP/1.1 parser a 0.CL probe would deadlock, " +
      "and carries its own recorder instead: every call appends the exact bytes sent and received " +
      "to the engagement's traffic log. A connection is never reused, because a poisoned socket " +
      "answers the next request on it — possibly a real user's.",
    inputSchema: z.object({
      host: z.string().describe("the host to connect to; your scope must authorize it"),
      port: z.number().int().min(1).max(65_535),
      tls: z.boolean().default(false).describe("wrap the connection in TLS; the certificate is not verified"),
      writes: z.array(rawWrite).min(1).describe("the trigger, in order"),
      baseline: z.array(rawWrite).optional().describe("the control, sent first on its own connection"),
      half_close: z
        .boolean()
        .default(false)
        .describe("shut the sending half after the last write, which is what a CL.0 probe needs"),
      read_timeout_ms: z
        .number()
        .int()
        .min(100)
        .max(60_000)
        .default(10_000)
        .describe("how long to read after the last write before hanging up"),
      why: z.string().describe("one line: what this is meant to establish"),
    }),
    execute: async ({ host, port, tls, writes, baseline, half_close, read_timeout_ms, why }) => {
      announce("raw", `${why} — ${tls ? "https" : "http"}://${host}:${port}`);
      // Host and port are their own inputs so the guard has a real target to
      // vet before the socket opens, and the bytes go with them so the
      // destructive denylist sees the payload it is there to refuse.
      const sent = [...(baseline ?? []), ...writes].map((w) => w.bytes).join("\n");
      let notes: string;
      try {
        notes = await ctx.guards.vet(
          `raw ${tls ? "https" : "http"}://${host}:${port}/ ${sent.slice(0, 4000)}`,
        );
      } catch (e) {
        if (e instanceof GuardRefusal) {
          settle("raw", false, "refused by the guard");
          return e.message;
        }
        throw e;
      }
      try {
        const out = await sendRaw({
          host,
          port,
          tls,
          writes,
          baseline,
          half_close,
          read_timeout_ms,
          why,
          dir: ctx.scope.dir,
        });
        settle("raw", true, clip(out.split("\n")[0] ?? "", 160));
        return clip(`${notes}${out}`);
      } catch (e) {
        settle("raw", false, (e as Error).message);
        return `${notes}error: ${(e as Error).message}`;
      }
    },
  });

  return { shell, request, script: scriptTool, files, reference, browser, raw };
}

/** Top-level keys and how much is under each, so the agent can see the map's size. */
export function summariseJson(text: string): string {
  try {
    const v = JSON.parse(text) as unknown;
    if (Array.isArray(v)) return `array of ${v.length}`;
    if (v && typeof v === "object") {
      return Object.entries(v as Record<string, unknown>)
        .map(([k, x]) => `${k}: ${Array.isArray(x) ? x.length : typeof x}`)
        .join(", ");
    }
    return typeof v;
  } catch {
    return "not valid JSON";
  }
}

/** Single-quote for a POSIX shell, the way shlex.quote does. */
export function shq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
