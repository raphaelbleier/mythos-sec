/**
 * One Chromium per phase, driven by the browser tool.
 *
 * Launched lazily: most phases never need it, and paying a browser start for a
 * recon run that only sends curl would be a waste of the budget. Console
 * messages and network requests are collected from the moment the page opens,
 * because a DOM XSS or a client-side redirect is usually visible in the console
 * and nowhere in the response body.
 *
 * It reaches the target directly rather than through the recording proxy: the
 * proxy terminates TLS with a per-run CA, and teaching Chromium to trust it
 * would mean shipping a browser profile with an extra root. The requests the
 * browser makes are collected here instead and can be written into the
 * engagement directory.
 */
import { existsSync } from "node:fs";
import type { Browser as PwBrowser, ConsoleMessage, Page } from "playwright-core";

export interface BrowserAction {
  action: string;
  url?: string;
  selector?: string;
  value?: string;
}

interface Net {
  method: string;
  url: string;
  status?: number;
}

export class Browser {
  private browser?: PwBrowser;
  private page?: Page;
  private console: string[] = [];
  private net: Net[] = [];

  constructor(private opts: { headless?: boolean } = {}) {}

  private async ensure(): Promise<Page> {
    if (this.page && !this.page.isClosed()) return this.page;
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
    const context = await this.browser.newContext({
      ignoreHTTPSErrors: true,
      userAgent: "Mozilla/5.0 (X11; Linux x86_64) mythos/0.1 (authorized security testing)",
    });
    this.page = await context.newPage();
    this.page.on("console", (m: ConsoleMessage) => {
      this.console.push(`[${m.type()}] ${m.text()}`.slice(0, 2000));
      if (this.console.length > 400) this.console.shift();
    });
    this.page.on("request", (r) => {
      this.net.push({ method: r.method(), url: r.url() });
      if (this.net.length > 800) this.net.shift();
    });
    this.page.on("response", (r) => {
      const hit = this.net.find((n) => n.url === r.url() && n.status === undefined);
      if (hit) hit.status = r.status();
    });
    this.page.setDefaultTimeout(20_000);
    return this.page;
  }

  async run(a: BrowserAction): Promise<string> {
    if (a.action === "close") {
      await this.close();
      return "browser closed";
    }
    const page = await this.ensure();
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
      case "console":
        return this.console.join("\n") || "(no console output)";
      case "requests":
        return (
          this.net.map((n) => `${n.status ?? "---"} ${n.method} ${n.url}`).join("\n") ||
          "(no requests)"
        );
      case "screenshot": {
        const buf = await page.screenshot({ fullPage: true });
        return `screenshot taken, ${buf.length} bytes (not stored; use it for your own judgement)`;
      }
      default:
        return `unknown browser action: ${a.action}`;
    }
  }

  async close() {
    await this.browser?.close().catch(() => undefined);
    this.browser = undefined;
    this.page = undefined;
  }
}
