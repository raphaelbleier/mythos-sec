/**
 * Which model providers this CLI can talk to, and how each one is paid for.
 *
 * Two deliberate limits, both about other people's terms of service:
 *
 *   1. Every hosted provider here is reached the way that provider documents —
 *      an API key, or an OAuth flow the provider itself publishes. There is no
 *      path that borrows another client's OAuth credentials to put a consumer
 *      subscription (ChatGPT Plus, Claude Pro/Max, Copilot) behind this tool.
 *      Those flows exist in other projects and they work, but the providers
 *      either forbid them outright or merely tolerate them, and the cost of a
 *      revocation lands on the user's account, not on this repository.
 *   2. OpenRouter is the sanctioned way to get the same breadth from one login:
 *      its OAuth flow is documented, it mints a real key, and one account
 *      reaches most of the models below. `mythos login openrouter` uses it.
 *
 * A provider the list does not name is still reachable: `custom` takes any
 * OpenAI-compatible base URL, which covers vLLM, LiteLLM, a corporate gateway
 * and anything self-hosted.
 */
export type Wire = "openai" | "anthropic" | "google" | "openai-compatible";

export interface Provider {
  id: string;
  label: string;
  wire: Wire;
  baseURL?: string;
  /** Environment variables read for a key, in order. */
  envKeys: string[];
  /** No credential needed (a local server). */
  local?: boolean;
  /** Has an OAuth flow implemented in this package. */
  oauth?: "openrouter";
  docs: string;
  /** Example model ids, for `mythos providers`. */
  examples: string[];
}

export const PROVIDERS: Provider[] = [
  {
    id: "openai",
    label: "OpenAI",
    wire: "openai",
    envKeys: ["OPENAI_API_KEY"],
    docs: "https://platform.openai.com/api-keys",
    examples: ["gpt-5.2", "gpt-5.2-mini"],
  },
  {
    id: "anthropic",
    label: "Anthropic",
    wire: "anthropic",
    envKeys: ["ANTHROPIC_API_KEY"],
    docs: "https://console.anthropic.com/settings/keys",
    examples: ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"],
  },
  {
    id: "google",
    label: "Google Gemini",
    wire: "google",
    envKeys: ["GEMINI_API_KEY", "GOOGLE_GENERATIVE_AI_API_KEY"],
    docs: "https://aistudio.google.com/apikey",
    examples: ["gemini-3-pro", "gemini-3-flash"],
  },
  {
    id: "openrouter",
    label: "OpenRouter (one key, most models)",
    wire: "openai-compatible",
    baseURL: "https://openrouter.ai/api/v1",
    envKeys: ["OPENROUTER_API_KEY"],
    oauth: "openrouter",
    docs: "https://openrouter.ai/docs/use-cases/oauth-pkce",
    examples: ["z-ai/glm-5.3", "anthropic/claude-sonnet-5.5", "openai/gpt-5.2"],
  },
  {
    id: "zai",
    label: "Z.ai (GLM coding plan)",
    wire: "openai-compatible",
    baseURL: "https://api.z.ai/api/coding/paas/v4",
    // Deliberately no generic variable here. A generic $LLM_API_KEY read by a
    // named provider sends whatever key happens to be in the environment to
    // that vendor's endpoint: an OpenRouter key would be posted to api.z.ai by
    // a run that only meant to pick a model. The generic names belong to
    // `custom`, where the base URL is spelled out in the same breath.
    envKeys: ["ZAI_API_KEY", "GLM_API_KEY"],
    docs: "https://z.ai/manage-apikey/apikey-list",
    examples: ["glm-5.3", "glm-5.3-flash"],
  },
  {
    id: "moonshot",
    label: "Moonshot / Kimi",
    wire: "openai-compatible",
    baseURL: "https://api.moonshot.ai/v1",
    envKeys: ["MOONSHOT_API_KEY", "KIMI_API_KEY"],
    docs: "https://platform.moonshot.ai/console/api-keys",
    examples: ["kimi-k2.5", "kimi-k2.5-turbo"],
  },
  {
    id: "deepseek",
    label: "DeepSeek",
    wire: "openai-compatible",
    baseURL: "https://api.deepseek.com/v1",
    envKeys: ["DEEPSEEK_API_KEY"],
    docs: "https://platform.deepseek.com/api_keys",
    examples: ["deepseek-chat", "deepseek-reasoner"],
  },
  {
    id: "xai",
    label: "xAI Grok",
    wire: "openai-compatible",
    baseURL: "https://api.x.ai/v1",
    envKeys: ["XAI_API_KEY"],
    docs: "https://console.x.ai",
    examples: ["grok-5", "grok-5-mini"],
  },
  {
    id: "mistral",
    label: "Mistral",
    wire: "openai-compatible",
    baseURL: "https://api.mistral.ai/v1",
    envKeys: ["MISTRAL_API_KEY"],
    docs: "https://console.mistral.ai/api-keys",
    examples: ["mistral-large-latest"],
  },
  {
    id: "groq",
    label: "Groq",
    wire: "openai-compatible",
    baseURL: "https://api.groq.com/openai/v1",
    envKeys: ["GROQ_API_KEY"],
    docs: "https://console.groq.com/keys",
    examples: ["llama-4-70b", "qwen3-32b"],
  },
  {
    id: "cerebras",
    label: "Cerebras",
    wire: "openai-compatible",
    baseURL: "https://api.cerebras.ai/v1",
    envKeys: ["CEREBRAS_API_KEY"],
    docs: "https://cloud.cerebras.ai",
    examples: ["qwen-3-coder-480b"],
  },
  {
    id: "together",
    label: "Together AI",
    wire: "openai-compatible",
    baseURL: "https://api.together.xyz/v1",
    envKeys: ["TOGETHER_API_KEY"],
    docs: "https://api.together.ai/settings/api-keys",
    examples: ["Qwen/Qwen3-235B-A22B"],
  },
  {
    id: "nebius",
    label: "Nebius AI Studio",
    wire: "openai-compatible",
    baseURL: "https://api.studio.nebius.com/v1",
    envKeys: ["NEBIUS_API_KEY"],
    docs: "https://studio.nebius.com",
    examples: ["Qwen/Qwen3-235B-A22B"],
  },
  {
    id: "ollama",
    label: "Ollama (local)",
    wire: "openai-compatible",
    baseURL: "http://127.0.0.1:11434/v1",
    envKeys: [],
    local: true,
    docs: "https://ollama.com",
    examples: ["qwen3:32b", "llama4:latest"],
  },
  {
    id: "lmstudio",
    label: "LM Studio (local)",
    wire: "openai-compatible",
    baseURL: "http://127.0.0.1:1234/v1",
    envKeys: [],
    local: true,
    docs: "https://lmstudio.ai",
    examples: ["local-model"],
  },
  {
    id: "custom",
    label: "Any OpenAI-compatible endpoint",
    wire: "openai-compatible",
    envKeys: ["MYTHOS_API_KEY", "LLM_API_KEY"],
    docs: "set MYTHOS_BASE_URL (or --base-url) to the /v1 endpoint",
    examples: ["whatever the gateway serves"],
  },
];

export const byId = (id: string): Provider | undefined => PROVIDERS.find((p) => p.id === id);

/**
 * `provider/model` or a bare model id. A bare id is resolved against the
 * provider whose examples claim it, else against the default provider, because
 * a typo in a model name should not silently pick another vendor's billing.
 */
export function splitModel(spec: string): { provider: string; model: string } {
  const i = spec.indexOf("/");
  if (i > 0) {
    const head = spec.slice(0, i);
    if (byId(head)) return { provider: head, model: spec.slice(i + 1) };
  }
  const owner = PROVIDERS.find((p) => p.examples.includes(spec));
  return { provider: owner?.id ?? process.env.MYTHOS_PROVIDER ?? "openrouter", model: spec };
}
