# Models and providers

Mythos calls a model provider directly. There is no agent host in the middle any
more, so the model is whatever `models.json` and your credentials say it is, and
the same run behaves the same way on any machine that has the same two.

Two files decide it. `models.json` at the repository root holds the tier each
agent runs at and what each profile maps a tier to.
`cli/src/providers/registry.ts` holds the providers: the id, the wire format, the
base URL and the environment variables each one reads.

## Quick start

```bash
mythos login openrouter                 # OAuth, mints a real API key
mythos login anthropic --api-key sk-ant-...
mythos providers                        # what is reachable now, and how
mythos doctor                           # also says whether the validator is independent
mythos -t <url> --profile anthropic
mythos -t <url> --model openrouter/z-ai/glm-5.3
```

A run fails before its first request if the strong tier cannot be bound, rather
than three phases in: `cli/src/index.ts` resolves the plan and constructs that
model as a preflight.

## Tiers

Four tiers, `fast`, `mid`, `strong` and `validator`. An agent asks for a tier,
a profile says which model that tier is. The split is about where an error costs
the run rather than about price alone: recon and scanning drive deterministic
tools and get checked by the phases after them, while the exploit phase and the
validator decide what a report claims.

| Agent | Tier | Why, from `models.json` |
|---|---|---|
| `mythos-recon` | fast | drives httpx, katana and ffuf and summarises the surface; later phases check what it finds |
| `mythos-scanner` | fast | runs nuclei, dalfox and sqlmap and records candidates, which are unproven by definition |
| `mythos-exploiter` | strong | decides validated against unconfirmed under the exploit skill: exact request, negative control, validator pass |
| `mythos-reporter` | mid | turns validated findings into severity and CVSS and must not claim past the evidence |
| `mythos` | strong | the primary entry. The driver uses it for the run banner and the preflight bind |

An agent name that `models.json` does not list runs at `mid`. The validator pass
is not an agent in that table: it always runs on the `validator` tier
(`cli/src/driver.ts`, `Driver.validate`).

## Profiles

| Profile | fast / mid / strong | validator | Credential | Independent validator |
|---|---|---|---|---|
| `openrouter` (default) | `z-ai/glm-5.3-flash`, `z-ai/glm-5.3`, `z-ai/glm-5.3` | `openai/gpt-5.2-mini` | `mythos login openrouter` | yes, another vendor through one account |
| `anthropic` | Haiku 5.5, Sonnet 5.5, Opus 5.5 | Sonnet 5.5 | `ANTHROPIC_API_KEY` | a different model in the same family, which is weaker evidence than a different vendor but still not self-review |
| `openai` | `gpt-5.2-mini`, `gpt-5.2`, `gpt-5.2` | `gpt-5.2-mini` | `OPENAI_API_KEY` | yes, within one vendor |
| `zai` | `glm-5.3-flash`, `glm-5.3`, `glm-5.3` | `glm-5.3` | `ZAI_API_KEY` or `GLM_API_KEY` | **no.** `single_model_validation: true`, and every finding carries the limitation |
| `local` | `qwen3:8b`, `qwen3:32b`, `qwen3:32b` | `qwen3:32b` | `ollama serve`, models pulled | **no.** For a target whose traffic may not leave the network, not for independent validation |

`openrouter` is the default because one account reaches every model the profile
names, so the validator is a genuinely different model without a second
subscription.

Two things to know about resolution. `MYTHOS_PROFILE` selects a profile when
`--profile` is absent. A profile name that `models.json` does not contain is not
an error: the tiers fall back to `z-ai/glm-5.3-flash` and `z-ai/glm-5.3` through
OpenRouter with `openai/gpt-5.2-mini` as validator, and the run starts. Check
the profile name in the run banner if the models are not the ones you expected.

## `--model` and `--profile`

`--profile <name>` picks a row from the table above. `--model <spec>` pins the
`fast`, `mid` and `strong` tiers to one model.

`--model` deliberately does not override a profile's validator. Pinning one
model for everything would otherwise turn the independent check into a
self-check without telling anyone, which is exactly the failure the validator
tier exists to prevent. The validator moves only when the profile itself has no
validator entry, and then the run is marked as single-model validation and says
so in the report.

```bash
mythos -t <url> --profile anthropic --model openrouter/z-ai/glm-5.3
# hunts on GLM through OpenRouter, validates on Claude Sonnet 5.5
```

`mythos doctor` prints which model reviews which, and whether the pass is
independent at all.

## Why the validator must be a different model

A model approves its own errors 11.9 percentage points more often when it wrote
them, measured over 64,800 calls. The bias follows authorship, not the context
window, so re-asking the same model in a fresh conversation is not an
independent check. That is why the `validator` tier must differ from `strong`,
and why `--model` leaves it alone.

Where a profile cannot offer a second model it sets `single_model_validation`,
the driver writes `Independent: no` into `validation.md`, and
`skills/exploit/SKILL.md` requires the finding to carry the caveat. The second
measurement behind the same pass: about 44% of proofs of concept that pass
exit-code, marker and trace checks are invalid, so the validator assumes the
error is there and looks for it.

## Providers

A model spec is `provider/model`. The provider id comes from this table; a bare
model id is resolved against the provider whose examples claim it, else against
`MYTHOS_PROVIDER` or `openrouter`, so a typo in a model name cannot silently
pick another vendor's billing.

| id | Wire | Base URL | Credential |
|---|---|---|---|
| `openai` | openai | the SDK default | `OPENAI_API_KEY` |
| `anthropic` | anthropic | the SDK default | `ANTHROPIC_API_KEY` |
| `google` | google | the SDK default | `GEMINI_API_KEY`, `GOOGLE_GENERATIVE_AI_API_KEY` |
| `openrouter` | openai-compatible | `https://openrouter.ai/api/v1` | `OPENROUTER_API_KEY`, or `mythos login openrouter` |
| `zai` | openai-compatible | `https://api.z.ai/api/coding/paas/v4` | `ZAI_API_KEY`, `GLM_API_KEY`, `LLM_API_KEY` |
| `moonshot` | openai-compatible | `https://api.moonshot.ai/v1` | `MOONSHOT_API_KEY`, `KIMI_API_KEY` |
| `deepseek` | openai-compatible | `https://api.deepseek.com/v1` | `DEEPSEEK_API_KEY` |
| `xai` | openai-compatible | `https://api.x.ai/v1` | `XAI_API_KEY` |
| `mistral` | openai-compatible | `https://api.mistral.ai/v1` | `MISTRAL_API_KEY` |
| `groq` | openai-compatible | `https://api.groq.com/openai/v1` | `GROQ_API_KEY` |
| `cerebras` | openai-compatible | `https://api.cerebras.ai/v1` | `CEREBRAS_API_KEY` |
| `together` | openai-compatible | `https://api.together.xyz/v1` | `TOGETHER_API_KEY` |
| `nebius` | openai-compatible | `https://api.studio.nebius.com/v1` | `NEBIUS_API_KEY` |
| `ollama` | openai-compatible | `http://127.0.0.1:11434/v1` | none, a local server |
| `lmstudio` | openai-compatible | `http://127.0.0.1:1234/v1` | none, a local server |
| `custom` | openai-compatible | `MYTHOS_BASE_URL` | `MYTHOS_API_KEY`, `LLM_API_KEY` |

The wire format picks the SDK client: `@ai-sdk/openai`, `@ai-sdk/anthropic`,
`@ai-sdk/google`, or `@ai-sdk/openai-compatible` for the rest. OpenRouter also
gets the `HTTP-Referer` and `X-Title` headers it asks third-party clients for.
`MYTHOS_BASE_URL` overrides the base URL of any provider, which is how a
corporate gateway, LiteLLM or vLLM is reached; `custom` is the same thing with
no default, and it refuses to bind without a base URL.

Credentials resolve in one order, in `cli/src/providers/auth.ts`: an explicit
`--api-key`, then the provider's environment variables in the order above, then
the store that `mythos login` writes. That store is
`$XDG_STATE_HOME/mythos/auth.json` with mode 0600, never the repository and
never an engagement directory, because an engagement directory gets zipped and
sent to a triager. A key never appears in an event, a log line or
`run-events.jsonl`; `mythos providers` prints the first six characters and the
length, which is enough to tell two keys apart and not enough to use one. Note
that the two local providers are listed as usable whenever the CLI runs, because
nothing here probes whether the server is actually up. `mythos doctor` is the
command that tries.

## Subscription logins

OpenRouter's OAuth PKCE flow is implemented
([documentation](https://openrouter.ai/docs/use-cases/oauth-pkce)). OpenRouter
publishes that flow for third-party clients and it mints a real API key scoped
to the user's account, so afterwards the tool holds a credential it was meant to
have and nothing else. The callback is a loopback HTTP server on an ephemeral
port bound to `127.0.0.1`, so the authorization code is never reachable from the
network.

Consumer plan logins for ChatGPT, Claude and Copilot are not implemented and
will not be. Those flows work by presenting another client's OAuth credentials.
The providers either forbid that outright or merely tolerate it, and the account
that gets suspended belongs to the user, not to this repository. One OpenRouter
login reaches most of the models in the table above, which is the sanctioned way
to get the same breadth from one sign-in.

## Data handling

Engagement content goes to the provider: target responses, parameter values,
cookies, and any credential an identity in `scope.yaml` carries. What the terms
of the providers in the profiles state, as written, with the date on the
document or the date it was read:

| Provider | What the terms state | Source |
|---|---|---|
| Z.ai (Jingsheng Hengxing Technology Pte. Ltd., Singapore) | Data processing addendum, section 4(b): "The Company do not store any of the content the Customer or its End Users provide or generate while using our Services." Customer data is generally processed in Singapore. The consumer privacy policy, last updated 29 September 2025, also says data may be used "when we train and improve our models" and names no opt-out. Whether the coding plan falls under the addendum is not stated. | [privacy policy and DPA](https://docs.z.ai/legal-agreement/privacy-policy), read 13 Nov 2026 |
| Anthropic | Conversation content is not retained by default, and retained data is "never used for model training without your express permission". Some models are Covered Models that require 30-day retention, which is why the `anthropic` profile uses the 5.5 line. Content flagged by trust and safety systems may be kept up to 2 years even under zero data retention. | [API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention), read 13 Nov 2026 |
| OpenAI | Abuse-monitoring logs are retained up to 30 days. API data is not used for training unless you opt in. Zero data retention needs prior approval. | [your data](https://developers.openai.com/api/docs/guides/your-data), read 13 Nov 2026 |
| DeepSeek | Personal data is stored in the People's Republic of China and kept as long as the account exists. Inputs are used "to train and improve our technology". The policy lists a right to opt out of training, exercised by writing to the privacy contact. Last update 10 February 2026. | [privacy policy](https://cdn.deepseek.com/policies/en-US/deepseek-privacy-policy.html) |
| Moonshot | Privacy policy, last update 30 April 2025: servers in Singapore, input retained while the account is active, user content used to optimise models, API content not addressed explicitly. A separate page says the platform does not train on enterprise customer data by default and offers zero data retention to enterprise customers on request. | [privacy](https://platform.kimi.ai/docs/agreement/userprivacy), [ZDR](https://platform.kimi.ai/docs/guide/zero-data-retention), read 13 Nov 2026 |
| OpenRouter | Not checked here. OpenRouter forwards the request to an upstream provider, so the upstream terms apply on top of OpenRouter's own, and which providers may serve a model is an account setting. Read both before putting client data through it. | |

The `local` profile is the only one where nothing leaves the machine except what
the tools send to the target. Retention and training terms change, so read the
current text rather than this table before an engagement for a client.

## What is not measured here

The tier assignments are a judgement about where an error costs the run, not a
measured result. No model in any profile has been measured against the proof
standard in `skills/exploit/SKILL.md` on this CLI. The earlier benchmark that
tried to measure a predecessor of it is withdrawn: the guards it ran under were
inert, which `docs/architecture.md` describes. The market comparison and the
cost estimates that used to live in this file are dated notes and stayed in
`docs/research/`, which is kept as a historical record and not updated.

What is worth checking after a first run on a new model: the number of tool calls
with empty arguments in `engagements/audit.jsonl` and in `run-events.jsonl`. A
fast-tier model that announces a tool call and never emits it looks like a quiet
phase, not like an error, and the fix is to move `mythos-recon` and
`mythos-scanner` to `mid` in `models.json`.
