/**
 * `mythos web` — the command, separate from the server so `cli/src/index.ts`
 * needs three lines to wire it and nothing else about the web UI reaches the
 * rest of the CLI.
 *
 * It prints the URL with the token in it and then waits. There is nothing to
 * type: the page is read-only and the terminal view is still the place where a
 * run is driven.
 */
import { bannerLine } from "../tui/banner.js";
import { ENGAGEMENTS } from "../paths.js";
import { serve } from "./server.js";

export interface WebFlags {
  [k: string]: string | boolean | undefined;
}

const str = (v: string | boolean | undefined) => (typeof v === "string" ? v : undefined);
const num = (v: string | boolean | undefined) =>
  typeof v === "string" && v !== "" && !Number.isNaN(Number(v)) ? Number(v) : undefined;

export async function runWeb(flags: WebFlags, version = ""): Promise<number> {
  let web;
  try {
    web = await serve({
      root: str(flags.engagements) ?? ENGAGEMENTS,
      host: str(flags.host) ?? "127.0.0.1",
      port: num(flags.port) ?? 0,
      allowRemote: flags["allow-remote"] === true,
      allowActions: flags["allow-actions"] === true,
    });
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n`);
    return 2;
  }

  const lines = [
    bannerLine(version),
    "",
    `  ${web.url}`,
    "",
    "  Read-only. Nothing on that page can start, stop or modify an engagement,",
    "  send a request at a target, or edit scope.yaml.",
    "  The token is the only credential: anyone with that URL has the engagements,",
    "  so do not paste it into a ticket.",
    "",
    `  engagements  ${web.root}`,
    `  bound to     ${web.host}:${web.port}`,
  ];
  if (!web.host.startsWith("127.") && web.host !== "::1") {
    lines.push(
      "",
      "  WARNING: this is not a loopback address. Engagement data — credentials,",
      "  session cookies and proofs of exploitation — is now reachable from the network.",
    );
  }
  if (flags["allow-actions"] === true) {
    // The flag exists so the help text and the server agree on what it would
    // mean. No endpoint reads it yet, and saying so is better than implying one.
    lines.push("", "  --allow-actions was passed, but no action is implemented: the server stays read-only.");
  }
  lines.push("", "  ctrl-c to stop", "");
  process.stdout.write(lines.join("\n"));

  await new Promise<void>((done) => {
    const stop = () => {
      process.stdout.write("\n");
      void web.close().then(done);
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
  return 0;
}
