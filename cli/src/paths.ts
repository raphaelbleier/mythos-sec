/**
 * Where everything lives.
 *
 * The CLI ships inside the repository it drives: the Python scripts, the skills
 * and the knowledge base are the methodology, and this package is only the
 * agent that reads them. So the repo root is derived from this file's location
 * and not configured, which also means a user who clones the repo cannot end up
 * with a CLI pointing at somebody else's skills.
 */
import { existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

function findRepoRoot(): string {
  // dist/paths.js or src/paths.ts -> up until AGENTS.md + skills/ are both there
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    if (existsSync(join(dir, "skills")) && existsSync(join(dir, "scripts"))) return dir;
    dir = dirname(dir);
  }
  return resolve(process.cwd());
}

export const REPO = process.env.MYTHOS_REPO ? resolve(process.env.MYTHOS_REPO) : findRepoRoot();
export const SCRIPTS = join(REPO, "scripts");
export const HOOKS = join(REPO, "hooks");
export const SKILLS = join(REPO, "skills");
export const KNOWLEDGE = join(REPO, "knowledge");
export const ENGAGEMENTS = join(REPO, "engagements");

/** Per-user state: credentials, provider cache. Never inside the repo. */
export const STATE = process.env.MYTHOS_HOME
  ? resolve(process.env.MYTHOS_HOME)
  : join(process.env.XDG_STATE_HOME ?? join(homedir(), ".local", "state"), "mythos");

export function ensureDir(p: string): string {
  mkdirSync(p, { recursive: true });
  return p;
}

export const script = (name: string) => join(SCRIPTS, name);
export const hook = (name: string) => join(HOOKS, name);
