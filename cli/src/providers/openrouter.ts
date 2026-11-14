/**
 * OpenRouter's documented OAuth PKCE flow.
 *
 * This is the one subscription-style login in the package, and it is here
 * because OpenRouter publishes it for third-party clients: the flow hands back
 * a real API key scoped to the user's account, so afterwards nothing in this
 * tool holds a session it was not meant to have. One account then reaches most
 * of the models in the registry.
 *
 *   https://openrouter.ai/docs/use-cases/oauth-pkce
 *
 * The callback is a loopback HTTP server on an ephemeral port, bound to
 * 127.0.0.1: the code must not be reachable from the network, and a fixed port
 * would collide with whatever else the operator is running.
 */
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { AddressInfo } from "node:net";

const AUTH = "https://openrouter.ai/auth";
const KEYS = "https://openrouter.ai/api/v1/auth/keys";

const b64url = (b: Buffer) => b.toString("base64url");

function openBrowser(url: string) {
  const cmd =
    process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    spawn(cmd, args, { stdio: "ignore", detached: true }).unref();
    return true;
  } catch {
    return false;
  }
}

export interface LoginResult {
  key: string;
}

export async function login(opts: { timeoutMs?: number; print?: (s: string) => void } = {}): Promise<LoginResult> {
  const say = opts.print ?? ((s: string) => process.stderr.write(s + "\n"));
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());

  const code = await new Promise<string>((resolve, reject) => {
    const server = createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const got = url.searchParams.get("code");
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(
        `<!doctype html><meta charset=utf-8><title>mythos</title>` +
          `<body style="font:16px system-ui;padding:3rem;max-width:30rem">` +
          (got
            ? `<h1>Signed in</h1><p>You can close this tab and go back to the terminal.</p>`
            : `<h1>No code</h1><p>The provider did not return an authorization code.</p>`) +
          `</body>`,
      );
      server.close();
      got ? resolve(got) : reject(new Error("callback carried no ?code"));
    });

    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      const callback = `http://127.0.0.1:${port}/callback`;
      const url =
        `${AUTH}?callback_url=${encodeURIComponent(callback)}` +
        `&code_challenge=${challenge}&code_challenge_method=S256`;
      say("Opening OpenRouter in your browser. If nothing opens, visit:\n  " + url);
      openBrowser(url);
    });

    const ms = opts.timeoutMs ?? 300_000;
    setTimeout(() => {
      server.close();
      reject(new Error(`no callback within ${Math.round(ms / 1000)}s`));
    }, ms).unref();
  });

  const res = await fetch(KEYS, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ code, code_verifier: verifier, code_challenge_method: "S256" }),
  });
  if (!res.ok) throw new Error(`OpenRouter rejected the exchange: ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { key?: string };
  if (!body.key) throw new Error("OpenRouter returned no key");
  return { key: body.key };
}
