/**
 * Model selection per agent, and the one place a provider SDK is constructed.
 *
 * `models.json` at the repo root keeps the tier each agent runs at and what
 * each profile maps a tier to. Two things in it matter beyond cost:
 *
 *   The validator tier must differ from the strong tier. A model approves its
 *   own errors measurably more often when it wrote them, and that bias follows
 *   authorship rather than the context window, so re-asking the same model in a
 *   fresh conversation is not an independent check. Where a profile cannot
 *   offer a second model, `single_model_validation` says so and the finding has
 *   to carry that caveat.
 *
 *   The cheap tiers are not a compromise on the phases that matter. Recon and
 *   scanning drive deterministic tools and get checked by later phases; the
 *   orchestrator and the validator are where an error costs the run.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createAnthropic } from "@ai-sdk/anthropic";
import { createGoogleGenerativeAI } from "@ai-sdk/google";
import { createOpenAI } from "@ai-sdk/openai";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import type { LanguageModel } from "ai";
import { REPO } from "./paths.js";
import * as auth from "./providers/auth.js";
import { splitModel } from "./providers/registry.js";

export type Tier = "fast" | "mid" | "strong" | "validator";

interface ModelsFile {
  default_profile?: string;
  agents?: Record<string, { tier?: Tier }>;
  profiles?: Record<
    string,
    { models?: Partial<Record<Tier, string>>; single_model_validation?: boolean; label?: string }
  >;
}

function readModelsFile(): ModelsFile {
  const f = join(REPO, "models.json");
  if (!existsSync(f)) return {};
  try {
    return JSON.parse(readFileSync(f, "utf8")) as ModelsFile;
  } catch (e) {
    throw new Error(`models.json is not valid JSON: ${(e as Error).message}`);
  }
}

export interface Plan {
  profile: string;
  /** Model spec per tier, after the overrides. */
  tiers: Record<Tier, string>;
  singleModelValidation: boolean;
}

const FALLBACK: Record<Tier, string> = {
  fast: "openrouter/z-ai/glm-5.3-flash",
  mid: "openrouter/z-ai/glm-5.3",
  strong: "openrouter/z-ai/glm-5.3",
  validator: "openrouter/openai/gpt-5.2-mini",
};

export function plan(opts: { profile?: string; model?: string } = {}): Plan {
  const file = readModelsFile();
  const profile = opts.profile ?? process.env.MYTHOS_PROFILE ?? file.default_profile ?? "";
  const p = profile ? file.profiles?.[profile] : undefined;
  // A name nobody knows used to fall through to the built-in fallback tiers and
  // keep printing the name it did not use, so a typo in --profile ran the whole
  // engagement on a provider the operator never chose.
  if (profile && !p && !opts.model) {
    const have = Object.keys(file.profiles ?? {}).join(", ") || "none in models.json";
    throw new Error(`unknown profile '${profile}'. Available: ${have}`);
  }
  const tiers: Record<Tier, string> = {
    fast: p?.models?.fast ?? FALLBACK.fast,
    mid: p?.models?.mid ?? FALLBACK.mid,
    strong: p?.models?.strong ?? FALLBACK.strong,
    validator: p?.models?.validator ?? FALLBACK.validator,
  };
  // --model pins every tier but the validator: pinning that one too would make
  // the independent check a self-check without saying so.
  if (opts.model) {
    tiers.fast = tiers.mid = tiers.strong = opts.model;
    if (!p?.models?.validator) tiers.validator = opts.model;
  }
  const same = tiers.validator === tiers.strong;
  return {
    profile: profile || "fallback",
    tiers,
    singleModelValidation: p?.single_model_validation === true || same,
  };
}

export function tierFor(agent: string): Tier {
  const file = readModelsFile();
  return file.agents?.[agent]?.tier ?? "mid";
}

export interface Bound {
  model: LanguageModel;
  spec: string;
  provider: string;
  source: string;
}

/** Construct the SDK model for one spec, resolving its credential. */
export function bind(spec: string, override?: { key?: string; baseURL?: string }): Bound {
  const { provider, model } = splitModel(spec);
  const r = auth.resolve(provider, override);
  const key = r.key ?? "";
  const common = { apiKey: key, ...(r.baseURL ? { baseURL: r.baseURL } : {}) };

  let lm: LanguageModel;
  switch (r.provider.wire) {
    case "openai":
      lm = createOpenAI(common)(model);
      break;
    case "anthropic":
      lm = createAnthropic(common)(model);
      break;
    case "google":
      lm = createGoogleGenerativeAI(common)(model);
      break;
    default:
      lm = createOpenAICompatible({
        name: r.provider.id,
        baseURL: r.baseURL ?? "",
        apiKey: key,
        headers:
          r.provider.id === "openrouter"
            ? { "HTTP-Referer": "https://github.com/raphaelbleier/mythos-sec", "X-Title": "Mythos" }
            : undefined,
      })(model);
  }
  return { model: lm, spec: `${provider}/${model}`, provider, source: r.source };
}
