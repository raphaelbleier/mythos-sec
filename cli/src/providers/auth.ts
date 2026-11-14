/**
 * Where credentials live, and the one place they are read.
 *
 * Order: an explicit --api-key, then the provider's environment variable, then
 * the store this file writes. A key is never written to the engagement
 * directory, never to the repository and never into an event, because an
 * engagement directory gets zipped and sent to a triager, and a run log gets
 * pasted into a bug report.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { STATE } from "../paths.js";
import { byId, PROVIDERS, type Provider } from "./registry.js";

const FILE = join(STATE, "auth.json");

interface Credential {
  key: string;
  /** How it got here, for `mythos login --status`. */
  via: "paste" | "oauth";
  provider: string;
  created: string;
  label?: string;
}

type Store = Record<string, Credential>;

function load(): Store {
  if (!existsSync(FILE)) return {};
  try {
    return JSON.parse(readFileSync(FILE, "utf8")) as Store;
  } catch {
    return {};
  }
}

function save(s: Store) {
  mkdirSync(dirname(FILE), { recursive: true });
  writeFileSync(FILE, JSON.stringify(s, null, 1) + "\n", { mode: 0o600 });
  try {
    chmodSync(FILE, 0o600);
  } catch {
    /* a filesystem without modes (mounted share) cannot be fixed from here */
  }
}

export function store(provider: string, cred: Omit<Credential, "provider" | "created">) {
  const s = load();
  s[provider] = { ...cred, provider, created: new Date().toISOString() };
  save(s);
}

export function forget(provider: string): boolean {
  const s = load();
  if (!(provider in s)) return false;
  delete s[provider];
  save(s);
  return true;
}

export function stored(): Array<{ provider: string; via: string; created: string; hint: string }> {
  return Object.values(load()).map((c) => ({
    provider: c.provider,
    via: c.via,
    created: c.created,
    hint: hint(c.key),
  }));
}

/** First six characters and the length: enough to tell two keys apart, not enough to use one. */
export const hint = (key: string) => `${key.slice(0, 6)}…(${key.length})`;

export interface Resolved {
  provider: Provider;
  key?: string;
  baseURL?: string;
  source: string;
}

export function resolve(providerId: string, override?: { key?: string; baseURL?: string }): Resolved {
  const provider = byId(providerId);
  if (!provider) throw new Error(`unknown provider: ${providerId}. Try 'mythos providers'.`);
  const baseURL = override?.baseURL ?? process.env.MYTHOS_BASE_URL ?? provider.baseURL;

  if (provider.id === "custom" && !baseURL) {
    throw new Error("provider 'custom' needs --base-url or MYTHOS_BASE_URL");
  }
  if (override?.key) return { provider, key: override.key, baseURL, source: "--api-key" };

  for (const name of provider.envKeys) {
    const v = process.env[name];
    if (v) return { provider, key: v, baseURL, source: `$${name}` };
  }
  const saved = load()[provider.id];
  if (saved) return { provider, key: saved.key, baseURL, source: `stored (${saved.via})` };

  if (provider.local) return { provider, key: "local", baseURL, source: "local server" };

  const how = provider.oauth
    ? `mythos login ${provider.id}`
    : `mythos login ${provider.id} --api-key <key>  (get one at ${provider.docs})`;
  throw new Error(`no credential for ${provider.label}. Run:\n  ${how}`);
}

/** Which providers are usable right now, for the startup banner. */
export function available(): string[] {
  const s = load();
  return PROVIDERS.filter((p) => {
    if (p.local) return true;
    if (s[p.id]) return true;
    return p.envKeys.some((k) => Boolean(process.env[k]));
  }).map((p) => p.id);
}
