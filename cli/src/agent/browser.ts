/**
 * One Chromium per phase, driven by the browser tool.
 *
 * Launched lazily: most phases never need it, and paying a browser start for a
 * recon run that only sends curl would be a waste of the budget. Console
 * messages and network requests are collected from the moment the page opens,
 * because a DOM XSS or a client-side redirect is usually visible in the console
 * and nowhere in the response body.
 *
 * It goes through the recording proxy when the engagement has one running. The
 * objection to that used to be the proxy's per-run CA, but every context here
 * is created with `ignoreHTTPSErrors`, so there is nothing to trust and no
 * profile to ship. Going through it matters more than it sounds: a DOM XSS is
 * proven in Chromium and cites no request, so `scripts/evidence check` — which
 * refuses a finding whose proof is not in the traffic store — blocked three
 * legitimate findings in a real engagement. Routed through the proxy, the
 * navigation that carried the payload is a record like any other, and a human
 * can replay it. When no proxy is running the browser falls back to reaching
 * the target directly, because a browserless run is worse than an unrecorded
 * one.
 *
 * The instrumentation beyond navigate-and-click exists because
 * `knowledge/web/client-side-dom.md` asks for it and could not be followed
 * without it: a sink hook has to be installed before the page's own scripts run
 * (`init_script`), a postMessage or a stored-XSS proof needs a second origin
 * acting as the victim role (`context`), listing message handlers needs CDP
 * (`cdp`), and a CSWSH check needs the frames (`websocket`). Dialogs are
 * recorded rather than awaited because an unanswered `alert()` blocks the page
 * for the rest of the run, and an `alert()` is the oracle for an XSS.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type {
  Browser as PwBrowser,
  BrowserContext,
  CDPSession,
  ConsoleMessage,
  Page,
} from "playwright-core";

export interface BrowserAction {
  action: string;
  url?: string;
  selector?: string;
  value?: string;
  /** Which browser context to act in, and the one `context` creates or switches to. */
  name?: string;
  /** Playwright storage state file for a new context, as `skills/auth-session` writes it. */
  storage_state?: string;
  /** CDP method, e.g. DOMDebugger.getEventListeners. */
  method?: string;
  params?: Record<string, unknown>;
  /** The engagement directory; a screenshot is evidence and belongs in it. */
  dir?: string;
}

interface Net {
  context: string;
  method: string;
  url: string;
  status?: number;
}

interface Socket {
  context: string;
  url: string;
  frames: string[];
}

/** A context and its page: one role, with its own cookies and storage. */
interface Role {
  context: BrowserContext;
  page: Page;
  cdp?: CDPSession;
}

const DEFAULT = "default";

export class Browser {
  private browser?: PwBrowser;
  private roles = new Map<string, Role>();
  private current = DEFAULT;
  /**
   * Replayed into every context created later. Playwright can only add an init
   * script to a context that exists, so a hook registered while the attacker
   * context is current would otherwise be missing from the victim context,
   * which is the one whose sinks the proof depends on.
   */
  private initScripts: string[] = [];
  private console: string[] = [];
  private net: Net[] = [];
  private sockets: Socket[] = [];
  private dialogs: string[] = [];

  constructor(private opts: { headless?: boolean; dir?: string } = {}) {}

  /**
   * The recording proxy's address, from the descriptor it writes when it
   * starts, or undefined when this engagement is not recording.
   *
   * Read per context rather than cached: the driver starts the proxy before the
   * phases but after the first Browser is constructed.
   */
  private proxyServer(): string | undefined {
    const dir = this.opts.dir;
    if (!dir) return undefined;
    try {
      const info = JSON.parse(readFileSync(join(dir, "traffic", "proxy.json"), "utf8")) as {
        port?: number;
      };
      return info.port ? `http://127.0.0.1:${info.port}` : undefined;
    } catch {
      return undefined;
    }
  }

  private async launch(): Promise<PwBrowser> {
    if (this.browser?.isConnected()) return this.browser;
    const { chromium } = await import("playwright-core");
    const launch: Parameters<typeof chromium.launch>[0] = {
      headless: this.opts.headless !== false,
      args: ["--no-sandbox", "--disable-dev-shm-usage"],
    };
    const exe = process.env.MYTHOS_CHROMIUM;
    if (exe && existsSync(exe)) launch.executablePath = exe;

    try {
      this.browser = await chromium.launch(launch);
    } catch (first) {
      // playwright-core ships no browser of its own. A system Chrome is the
      // common case on a workstation, and saying so beats a stack trace.
      try {
        this.browser = await chromium.launch({ ...launch, channel: "chrome" });
      } catch {
        throw new Error(
          `could not start Chromium: ${(first as Error).message.split("\n")[0]}. ` +
            `Install one with 'npx playwright install chromium', or point MYTHOS_CHROMIUM at a binary.`,
        );
      }
    }
    return this.browser;
  }

  /** The named role, created on first use. `storageState` only applies at creation. */
  private async role(name: string, storageState?: string): Promise<Role> {
    const have = this.roles.get(name);
    if (have && !have.page.isClosed()) return have;
    const browser = await this.launch();
    const server = this.proxyServer();
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      userAgent: "Mozilla/5.0 (X11; Linux x86_64) mythos/0.1 (authorized security testing)",
      ...(server ? { proxy: { server } } : {}),
      ...(storageState ? { storageState } : {}),
    });
    for (const script of this.initScripts) await context.addInitScript({ content: script });
    const page = await context.newPage();
    const tag = name === DEFAULT ? "" : `(${name}) `;
    page.on("console", (m: ConsoleMessage) => {
      this.console.push(`${tag}[${m.type()}] ${m.text()}`.slice(0, 2000));
      if (this.console.length > 400) this.console.shift();
    });
    page.on("request", (r) => {
      this.net.push({ context: name, method: r.method(), url: r.url() });
      if (this.net.length > 800) this.net.shift();
    });
    page.on("response", (r) => {
      const hit = this.net.find((n) => n.url === r.url() && n.status === undefined);
      if (hit) hit.status = r.status();
    });
    // A dialog nobody answers freezes the page, so it is logged and dismissed.
    // The log line is the evidence: `alert(token)` firing is the XSS oracle.
    page.on("dialog", (d) => {
      this.dialogs.push(`${tag}${d.type()}: ${d.message()}`.slice(0, 2000));
      void d.dismiss().catch(() => undefined);
      if (this.dialogs.length > 200) this.dialogs.shift();
    });
    page.on("websocket", (ws) => {
      const sock: Socket = { context: name, url: ws.url(), frames: [] };
      this.sockets.push(sock);
      if (this.sockets.length > 40) this.sockets.shift();
      const frame = (dir: string) => (f: { payload: string | Buffer }) => {
        const text = typeof f.payload === "string" ? f.payload : f.payload.toString("base64");
        sock.frames.push(`${dir} ${text}`.slice(0, 1000));
        if (sock.frames.length > 200) sock.frames.shift();
      };
      ws.on("framesent", frame("→"));
      ws.on("framereceived", frame("←"));
    });
    page.setDefaultTimeout(20_000);
    const role: Role = { context, page };
    this.roles.set(name, role);
    return role;
  }

  async run(a: BrowserAction): Promise<string> {
    if (a.action === "close") {
      await this.close();
      return "browser closed";
    }
    if (a.action === "context") {
      const name = a.name || DEFAULT;
      const fresh = !this.roles.has(name);
      await this.role(name, a.storage_state);
      this.current = name;
      const all = [...this.roles.keys()].map((n) => (n === name ? `${n} (current)` : n));
      return (
        `${fresh ? "created" : "switched to"} context ${name}` +
        `${a.storage_state && fresh ? ` with storage state ${a.storage_state}` : ""}\n` +
        `contexts: ${all.join(", ")}`
      );
    }
    const role = await this.role(this.current, a.storage_state);
    const page = role.page;
    switch (a.action) {
      case "goto": {
        const res = await page.goto(a.url!, { waitUntil: "domcontentloaded" });
        return `${res?.status() ?? "?"} ${page.url()}\ntitle: ${await page.title()}`;
      }
      case "click":
        await page.click(a.selector!);
        return `clicked ${a.selector}, now at ${page.url()}`;
      case "type":
        await page.fill(a.selector!, a.value ?? "");
        return `filled ${a.selector}`;
      case "text":
        return (await page.innerText("body")).trim();
      case "html":
        return await page.content();
      case "eval":
        return JSON.stringify(await page.evaluate(a.value ?? "null"), null, 1) ?? "undefined";
      case "init_script": {
        if (!a.value) return "init_script needs the JavaScript in 'value'";
        this.initScripts.push(a.value);
        await role.context.addInitScript({ content: a.value });
        return (
          `registered ${a.value.length} bytes to run before any page script, in context ` +
          `${this.current} and in every context created after this. It takes effect on the ` +
          `next navigation, so load the page again.`
        );
      }
      case "cdp": {
        if (!a.method) return "cdp needs a 'method', e.g. DOMDebugger.getEventListeners";
        role.cdp ??= await role.context.newCDPSession(page);
        // Playwright types `send` against the protocol's own method names, so a
        // method chosen at run time has to go through this shape.
        const session = role.cdp as unknown as {
          send(m: string, p?: Record<string, unknown>): Promise<unknown>;
        };
        const out = await session.send(a.method, a.params);
        return JSON.stringify(out, null, 1) ?? "undefined";
      }
      case "websocket":
        return (
          this.sockets
            .map((s) =>
              [`${s.url} (${s.context}, ${s.frames.length} frames)`, ...s.frames.map((f) => `  ${f}`)].join("\n"),
            )
            .join("\n") || "(no websockets seen)"
        );
      case "dialog":
        return this.dialogs.join("\n") || "(no dialogs)";
      case "console":
        return this.console.join("\n") || "(no console output)";
      case "requests":
        return (
          this.net
            .map(
              (n) =>
                `${n.status ?? "---"} ${n.method} ${n.context === DEFAULT ? "" : `(${n.context}) `}${n.url}`,
            )
            .join("\n") ||
          "(no requests)"
        );
      case "screenshot": {
        const buf = await page.screenshot({ fullPage: true });
        if (!a.dir) return `screenshot taken, ${buf.length} bytes, but no engagement directory to store it in`;
        const rel = `evidence/${shotName(page.url(), this.current)}`;
        const abs = resolve(a.dir, rel);
        mkdirSync(resolve(abs, ".."), { recursive: true });
        writeFileSync(abs, buf);
        return `wrote ${buf.length} bytes to ${rel} — cite that path in the finding`;
      }
      default:
        return `unknown browser action: ${a.action}`;
    }
  }

  async close() {
    await this.browser?.close().catch(() => undefined);
    this.browser = undefined;
    this.roles.clear();
    this.current = DEFAULT;
  }
}

/**
 * A file name a reader can place: the page it shows and when it was taken.
 * Everything outside the safe set goes, because this ends up in a report path.
 */
export function shotName(url: string, context: string, now = new Date()): string {
  const stamp = now.toISOString().replace(/[:.]/g, "-").slice(0, 19);
  let where = url;
  try {
    const u = new URL(url);
    where = `${u.host}${u.pathname}${u.search}`;
  } catch {
    // about:blank and the like: use it as it came.
  }
  const slug = where.replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60);
  return `${stamp}-${context}-${slug || "page"}.png`;
}
