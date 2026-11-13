# models

Mythos has no model of its own. The host runs whatever model it is configured
with. This page says which model the OpenCode path uses by default, how each
agent gets its own model, how to switch provider, and what the evidence behind
the default is. Everything below was checked on 13 November 2026 unless a date
says otherwise. Where a figure comes from the vendor it says so.

## quick start

The default is GLM 5.3 on the Z.ai Coding Plan, through OpenCode's built-in
`zai-coding-plan` provider. There is no custom provider block for it.

```bash
export ZHIPU_API_KEY=...        # or: opencode auth login, then pick "Z.AI Coding Plan"
opencode run --agent mythos --auto "https://target.example --scope scope.yaml"
```

If your Z.ai key is in `LLM_API_KEY` (the name the benchmark harness and Strix
use), run `export ZHIPU_API_KEY="$LLM_API_KEY"` first.

Without a Z.ai key the default fails at the first model call with
`ProviderModelNotFoundError: Model not found: zai-coding-plan/glm-5.3`
(observed on OpenCode 1.18.31 with no credentials). Pick another profile:

```bash
export ANTHROPIC_API_KEY=...
OPENCODE_CONFIG_CONTENT="$(scripts/models anthropic)" opencode
```

`opencode run --model X` alone is not enough. It moves the orchestrator, but
six sub-agents carry their own model and keep it. The profiles are listed under
[providers](#providers).

## how the assignment works

Three files and one precedence rule.

| file | role |
|---|---|
| `models.json` | the source: which tier each agent needs, which model each profile gives each tier |
| `opencode.json` | the default profile written out as `model` plus `agent.<id>.model`, which is what OpenCode reads |
| `scripts/models` | prints a profile as a config fragment, copies the default profile into `opencode.json` (`--write`), fails if the two drifted (`--check`) |

Tiers describe the job, not the price:

| tier | job | agents |
|---|---|---|
| fast | runs tools and summarises their output, never decides what counts as proof | recon, scanner |
| mid | reads evidence and writes it up | planner, browser, reporter |
| strong | decides what counts as proof and what happens next | orchestrator, exploiter |

| agent | tier | reason |
|---|---|---|
| `mythos` | strong | longest prompt, runs the whole engagement unattended and owns scope and closure decisions, so an error here costs the run |
| `mythos-planner` | mid | one structured plan from scope and surface, no long tool loop |
| `mythos-recon` | fast | drives httpx, katana and ffuf and summarises the surface; later phases check what it finds |
| `mythos-scanner` | fast | runs nuclei, dalfox and sqlmap and records candidates, which are unproven by definition |
| `mythos-browser` | mid | long Playwright tool loops, and its verdict on a client-rendered finding is evidence |
| `mythos-exploiter` | strong | decides validated versus unconfirmed under the exploit skill: exact request, negative control, validator pass |
| `mythos-reporter` | mid | turns validated findings into severity and CVSS and must not claim past the evidence |

The orchestrator has no `agent` entry on purpose. It follows the top-level
`model`, so `--model` still moves it.

The default profile `zai` has two real models, so mid and strong coincide on
`glm-5.3`. The Z.ai catalogue has no model between Flash and the flagship:
`glm-5.3-flashx` is described by Z.ai as the speed-focused variant of Flash, not
a middle tier. The `anthropic` and `openai` profiles have three distinct models.

### which field a consumer reads

For OpenCode, read `agents.<id>.tier` in `models.json`, then
`profiles.<profile>.models.<tier>`. The result is a full `provider/model` string.
`profiles.<profile>.needs` and `agents.<id>.reason` are documentation.

For Claude Code, read `agents.<id>.tier`, then `claude_code.<tier>`, which is an
alias (`haiku`, `sonnet`, `opus`) for the `model:` frontmatter field. Nothing
consumes it yet: `scripts/build-hosts.py` still writes `model: inherit` and
`--check` is unaffected.

### precedence, tested on OpenCode 1.18.31

From weakest to strongest: `opencode.json` `agent.<id>.model`, then a `model:`
line in the agent's frontmatter, then `OPENCODE_CONFIG_CONTENT`. For that
reason the agent files under `.opencode/agent/` should not carry a `model:`
line. It would shadow `models.json`, and only the environment variable could
override it. A sub-agent without a model inherits the parent session's model
(OpenCode agents documentation).

### benchmarks

The benchmark compares arms on one model. The Mythos arm loads this repository's
`opencode.json`, so its sub-agents would use the per-agent models while the
control arm uses `--model`. Pin every agent to the model under test:

```bash
OPENCODE_CONFIG_CONTENT="$(scripts/models "$MODEL")" opencode run ...   # MODEL=provider/model
```

`bench/runners/mythos.py` does not do this yet.

### other versions

The keys used (`model`, `agent`, `provider`) are the ones OpenCode 1.x reads.
OpenCode 2.x documents `agents` and `providers` instead and marks the 1.x keys
deprecated in its published JSON schema. Only 1.18.31 is installed here, so
2.x is untested.

## providers

| profile | models (fast / mid / strong) | credential | notes |
|---|---|---|---|
| `zai` (default) | `zai-coding-plan/glm-5.3-flash`, `glm-5.3`, `glm-5.3` | `ZHIPU_API_KEY` | flat plan, credits per 5 hours and per week |
| `zai-api` | `zai/glm-5.3-flash`, `glm-5.3`, `glm-5.3` | `ZHIPU_API_KEY` | pay per token on `https://api.z.ai/api/paas/v4` |
| `zen` | `opencode/glm-5.3-flash`, `glm-5.3`, `glm-5.3` | `OPENCODE_API_KEY` | same models, hosted in the US and EU by OpenCode Zen |
| `anthropic` | `claude-haiku-5-5`, `claude-sonnet-5-5`, `claude-opus-5-5` | `ANTHROPIC_API_KEY` | avoids the Covered Models, see data handling |
| `openai` | `gpt-6-luna`, `gpt-6.1-terra`, `gpt-6.1-sol` | `OPENAI_API_KEY` | |

Any other model, for all agents at once: `scripts/models <provider>/<model>`.

### z.ai coding plan (default)

- Provider id `zai-coding-plan`, base URL `https://api.z.ai/api/coding/paas/v4`,
  OpenAI-compatible. Z.ai also serves an Anthropic-compatible endpoint at
  `https://api.z.ai/api/anthropic`.
- Plan: Lite from 18 USD per month, with 2,000 credits per 5 hours and 10,000
  per week. Pro is 12,000 and 60,000, Max is 28,000 and 140,000; the page gives
  no Pro or Max price. Use outside 14:00 to 18:00 UTC+8 on weekdays is charged
  at half the credits ([Z.ai devpack](https://docs.z.ai/devpack/overview)).
- Z.ai's usage policy says the plan "may only be used within officially
  supported tools and products". OpenCode is on the supported list. The page does
  not say whether unattended `opencode run --auto` sessions are covered. For
  benchmark sweeps use `zai-api`.
- Rate limits are not published on the pricing page. In the repo's GLM 5.3 sweep,
  2 of 12 cells per arm were rate limited.
- `opencode.json` still carries an older `zai` block that points the
  `zai` provider id at the coding endpoint and reads `LLM_API_KEY`. The
  benchmark's control arm and its `--model zai/glm-5.3` runs depend on it. Remove
  it once the harness uses `zai-coding-plan` or `zai-api`.

### z.ai pay per token

Same models on `zai/...`. Prices per million tokens: GLM 5.3 1.40 USD input,
0.26 cached input, 4.40 output; GLM 5.3 Flash 0.15, 0.03, 0.50
([Z.ai pricing](https://docs.z.ai/guides/overview/pricing)).

### opencode zen

Same GLM models at the same prices, hosted by OpenCode. Use it when the
provider's hosting matters, see data handling. Sign up at opencode.ai, then
`opencode auth login` and pick OpenCode Zen, or set `OPENCODE_API_KEY`.

### anthropic

`ANTHROPIC_API_KEY`. Prices per million tokens, input and output: Haiku 5.5
0.10 and 0.50, Sonnet 5.5 2 and 10, Opus 5.5 4 and 20 (models.dev). The repo's
Claude Code sweeps used Sonnet and cost 20.88 USD for 40 challenges
(`README.md`).

### openai

`OPENAI_API_KEY`. Prices, input and output: `gpt-6-luna` 0.10 and 0.50,
`gpt-6.1-terra` 1 and 5, `gpt-6.1-sol` 2 and 10 (models.dev). The tier names are
taken from price and release order, not from a vendor statement.

### other chinese providers

Built into OpenCode's registry, so a one-line `scripts/models` call is enough:

| provider id | credential | example model | endpoint in the registry |
|---|---|---|---|
| `moonshotai` | `MOONSHOT_API_KEY` | `moonshotai/kimi-k3.1-pro` | `https://api.moonshot.ai/v1` |
| `deepseek` | `DEEPSEEK_API_KEY` | `deepseek/deepseek-flash`, `deepseek/deepseek-v4-pro` | `https://api.deepseek.com` |
| `minimax` | `MINIMAX_API_KEY` | `minimax/MiniMax-M3.1-Flash` | `https://api.minimax.io/anthropic/v1` |
| `alibaba` | `DASHSCOPE_API_KEY` | `alibaba/qwen3.8-max` | `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` |

DeepSeek's own documentation lists `deepseek-flash` (DeepSeek-V4.1-Flash-1017)
and `deepseek-v4-pro` (0813) and also serves an Anthropic-format endpoint at
`https://api.deepseek.com/anthropic`. The older ids `deepseek-v4-flash` still
route to V4.1 Flash. Kimi's documentation names a provider "Kimi For Coding" in
`opencode auth login`; that id is not in the models.dev data I downloaded, so
use `moonshotai` unless you hold a Kimi Code plan. Tencent (`hy4`, API only) and ByteDance
(Doubao Seed, API only, via `volcengine`) are in the registry too and were not evaluated; I found no agentic or security evidence for either.

### local: ollama or vllm

Local models are not in the registry, so they need a provider block in your own
config (`~/.config/opencode/opencode.json`), not in the repo:

```json
{
  "provider": {
    "local": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Local",
      "options": { "baseURL": "http://localhost:11434/v1" },
      "models": {
        "<tag from ollama list>": { "name": "Local model", "tool_call": true,
          "limit": { "context": 65536, "output": 8192 } }
      }
    }
  }
}
```

Then `OPENCODE_CONFIG_CONTENT="$(scripts/models local/<tag>)" opencode`. vLLM
serves the same API on port 8000 by default; tool calling needs its auto tool
choice and a tool-call parser that matches the model, which I did not verify
for any specific model.

Ollama sets the default context length from VRAM: 4k under 24 GiB, 32k from 24 to
48 GiB, 256k above. Its documentation says agents and coding tools "should be set
to at least 64000 tokens" ([Ollama](https://docs.ollama.com/context-length)). At
4k the orchestrator prompt and one skill do not fit, so set
`OLLAMA_CONTEXT_LENGTH`.

Open-weight candidates, by Hugging Face metadata: GLM 5.3 (about 753 billion
parameters, license listed as "other"), GLM 5.3 Flash (about 321 billion, MIT),
DeepSeek V4.1 Flash (about 763 billion, MIT), MiniMax M3.1 Flash (about 220
billion, "other"), Kimi K3.1 Pro (about 2.8 trillion, "other"), Qwen3.6 27B and
35B-A3B (Apache 2.0). Only the two Qwen models are small enough for one machine,
and nothing measures whether they can run these skills.

## can the default run the skills

Short answer: the flagship can drive the flag-capture flow, the proof standard is
untested on any Chinese model, and the fast tier is not trusted with it.

What was measured in this repository: OpenCode with `zai/glm-5.3`, 12 XBEN
challenges, both arms solved all 10 scored cells (2 per arm were rate limited).
That is a ceiling with ten cells and no test, and it was scored by flag capture.
It shows that GLM 5.3 can run the OpenCode tool loop against the toolbox. It says
nothing about the exploit skill's rules: exact request and response excerpt, a
negative control, and a validator pass in a fresh context. Every flagless
measurement in the repo (VAmPI, DVGA, Vuln Bank) ran on Claude Sonnet and is
withdrawn or under re-measurement. No run of the full orchestrator, planner,
exploiter and reporter chain on GLM exists.

Why the strong tier is a judgement and not a result: the skills are long and the
exploit skill sets a proof standard that a model can quietly fail. Independent
work finds that models claim success they did not earn. The Dreadnode study of 22
models on 23 Cybench tasks found cheating in 37.1 percent of passes at baseline
and 21 of 22 models cheating at least once; GLM-5.1 had a baseline cheat
propensity of 34.8 percent and DeepSeek-V4 Pro 21.7 percent, falling to 4.3 and
17.4 under a standard anti-cheat prompt (arXiv 2607.21763, 15 October 2026;
older model versions than the current ones). Semgrep's June 2026 write-up
reports that Z.ai says GLM 5.2 shows more reward hacking than 5.1. The
exploit skill's rules are the countermeasure; whether GLM 5.3 follows them has
not been measured here.

The fast tier (GLM 5.3 Flash, recon and scanner) cannot be shown to hold the
proof standard and is not given the chance: `models.json` keeps it out of the
exploit and validator phases. For recon and scanning it only has to run tools
and report what they print. There are public reports of GLM 5.3 Flash announcing
a tool call and never emitting it, or emitting it as plain text: Kilo Code issue
14475 (22 September 2026, more than 10 sessions), the sparkglm and ds4 issue
trackers, and a Cursor forum thread. They come from other harnesses and
gateways, and one Ollama Cloud report (issue 18193, September 2026) says the same
client works normally against Z.ai's own API. I found no report for OpenCode on
the Z.ai endpoint and no measurement of a failure rate. After a first run, count
tool calls with empty arguments in `engagements/audit.jsonl` and in the OpenCode
session export before trusting the fast tier on a long engagement. If it drops
calls, move recon and scanner to `mid` in `models.json`.

The validator pass runs a stored PoC in a fresh context. With one model, the
hunt and the validation share blind spots. Putting the exploiter on another
vendor's model, for example `moonshotai/kimi-k3.1-pro`, is the cheapest way to
get independence. Nothing here measures whether it helps.

## chinese models, november 2026

Registry data is from models.dev, which OpenCode's built-in providers are
generated from. Prices are USD per million tokens, input and output, list price,
no caching. "Open" means weights are published on Hugging Face (checked through
its API).

| model (OpenCode id) | open | context | price | flat plan | endpoints |
|---|---|---|---|---|---|
| GLM 5.3 (`glm-5.3`, 14 Aug 2026) | yes, license "other" | 1M, 128K out | 1.40 / 4.40 | Z.ai Coding Plan from 18 USD per month | OpenAI and Anthropic compatible |
| GLM 5.3 Flash (`glm-5.3-flash`, 26 Aug 2026) | yes, MIT | 1M | 0.15 / 0.50 | same plan | same |
| Kimi K3.1 Pro (`kimi-k3.1-pro`, 23 Oct 2026) | yes, license "other", weights on Hugging Face since 2 Nov 2026 | 1,048,576 | 2 / 10 | Kimi plans 19 to 199 USD per month (secondary source) | OpenAI compatible; Anthropic endpoint not confirmed |
| DeepSeek V4.1 Flash (`deepseek-flash`, 17 Oct 2026) | yes, MIT | 1M, 384K out | 0.30 / 1.20 peak, 0.15 / 0.60 off-peak | none found | OpenAI and Anthropic compatible |
| DeepSeek V4 Pro (`deepseek-v4-pro`, build 0813) | yes, MIT | 1M | 1.32 / 3.96 peak, 0.66 / 1.98 off-peak | none found | same |
| MiniMax M3.1 Flash (`MiniMax-M3.1-Flash`, 19 Oct 2026) | yes, license "other" | 1M | 0.15 / 0.60 | MiniMax Token Plan exists, price not checked | Anthropic style in the registry |
| Qwen3.8 Max (`qwen3.8-max`, 3 Aug 2026) | no | 1M | 2 / 6 | Alibaba Coding Plan exists, price not checked | OpenAI compatible |

Peak for DeepSeek is 01:00 to 04:00 and 06:00 to 10:00 UTC on weekdays
([DeepSeek pricing](https://api-docs.deepseek.com/quick_start/pricing)).

Evidence, with who produced it.

| model | independent | vendor |
|---|---|---|
| GLM 5.3 | Artificial Analysis Intelligence Index v5: 32 at max effort, 28 for Flash, cost per task 5.01 and 0.58 USD. Semgrep, 22 June 2026, IDOR detection: GLM 5.2 scored 39 percent F1, the best of the open models tested (MiniMax M3 23, Kimi K2.7 Code 22, DeepSeek V4 17). UK AISI and US CAISI, preliminary, July 2026: GLM-5.2 24.4 percent on ExploitBench. Practitioner reports of dropped tool calls, above. | Terminal-Bench 3.0 28.3 (GLM 5.2: 4.6), DeepSWE v1.1 66.9, CyberGym 84.5 percent, ExploitBench 54.4 percent, ExploitGym 130 tasks in 6 hours against 247 for Mythos 5. No SWE-bench Verified score published. |
| Kimi K3.1 Pro | Artificial Analysis Intelligence Index v5: 46, the highest open-weight score; cost per task 3.68 USD; output about 50 tokens per second; rated very verbose. Terminal-Bench 4.0: 67.2 percent (Artificial Analysis), 63.6 percent (Vals AI). UK AISI and US CAISI on the previous Kimi K3: ExploitBench 32.2 percent, reached step 17 of 32 on average in a simulated network attack and completed it once in ten attempts, and no jailbreak was needed. No offensive-security evaluation of K3.1 Pro found. Early Kimi Code users reported exhausting the 5-hour limit in under an hour (secondary source). | Terminal-Bench 4.0 65.7, run in the Claude Code harness at max effort. Thinking is always on; requests with thinking disabled are rejected. |
| DeepSeek V4.1 Flash | Artificial Analysis Intelligence Index v5: 33 at max effort, cost per task 0.60 USD. No independent offensive-security or agentic result found. V4 Pro 0813 scores 23 on the same index. | Terminal-Bench 2.1 90.6 (a review site) and DeepSWE v1.1 74.2 percent (DeepSeek's arXiv paper 2609.19969), both from DeepSeek's own harness. V4 Pro model card: CyberGym 83.3. |
| MiniMax M3.1 Flash | Artificial Analysis Intelligence Index v5: 29. | none read |
| Qwen3.8 Max | Artificial Analysis Intelligence Index v5: 34 (build 0902), cost per task 10.02 USD. | none read |

Artificial Analysis rebuilt its index (v5) and an older mirror shows higher
values (55.1 for K3.1 Pro, 44.8 for GLM 5.3). The order is the same under both.
The index measures general ability, not agentic tool use or exploitation, and the
page I read gave no index version in the table itself.

I could not find SWE-bench Verified, Cybench, CVE-Bench or XBEN results for any
of the current models from an independent source. The repo's own XBEN runs are
contaminated by public write-ups (see `bench/METHODOLOGY.md`).

## recommendation

GLM 5.3 as the strong and mid tier and GLM 5.3 Flash as the fast tier, on the
Z.ai Coding Plan. The reasons, in order of weight:

1. It is the only model measured in this repository under this harness, on
   OpenCode against the real toolbox.
2. One credential covers both tiers, and OpenCode ships the provider, so no
   custom block, no endpoint to maintain.
3. Z.ai lists OpenCode as a supported tool for the flat plan.
4. The published offensive-security figures are the strongest for an open model,
   but they are the vendor's. The independent security data on this model line
   are for GLM 5.2 and are mixed: best of the open models on IDOR detection, below
   Kimi K3 on ExploitBench.

The strongest challenger is Kimi K3.1 Pro. It leads every independent general
index I found and has the higher agentic score, at a lower cost per task than
GLM 5.3 at max effort. It is slower and more verbose, and nobody has measured it
on offensive tasks. If you can afford one comparison, run the exploiter on it.
DeepSeek V4.1 Flash is the cheap-tier candidate: it matches GLM 5.3 on the
general index at about an eighth of the cost per task (0.60 against 5.01 USD), but no tool-calling or security
evidence exists for it yet. This is a recommendation to measure, not a result.

## what you gain and give up by switching

| | Chinese default (GLM 5.3) | Anthropic | OpenAI | local |
|---|---|---|---|---|
| cost per run | about 1 USD per challenge at list price for GLM 5.3 and 0.10 USD for Flash, uncached, at a Strix-like 668K input and 6.5K output tokens (`docs/research/notes-2026-11/benchmark_methodology.md`); a flat plan caps spend | about 1.40 USD for Sonnet 5.5 and 2.80 USD for Opus 5.5 under the same assumption; measured 0.52 USD per cell for the scaffolded arm on Sonnet in this repo | about 1.40 USD for `gpt-6.1-sol` under the same assumption | hardware only |
| evidence in this repo | 10 of 10 scored XBEN cells, flag capture only | 40-challenge sweeps and the flagless runs, under re-measurement | none | none |
| refusals on offensive tasks | SaferAI found GLM-5.2 refused none of its offensive cyber and biology tasks; AISI and CAISI found Kimi K3 attempted exploit development without a jailbreak | SaferAI could not finish CyberGym on Claude Opus 4.7 because it refused so consistently (TechCrunch, 4 August 2026) | not tested here | depends on the model |
| long-run behaviour | reports of dropped calls and endless reasoning, mostly on third-party hosting | no reports gathered | no reports gathered | depends on quantisation and context length |
| data handling | see below | see below | see below | nothing leaves the machine except what the tools send to the target |

Refusals matter for this tool in both directions. A model that refuses stalls an
authorized engagement, and a model that does not refuse will also run against a
target you should not touch. Scope enforcement does not come from the model, see
`AGENTS.md`.

## data handling

Engagement content goes to the provider: target responses, tokens, cookies and
any credentials in `scope.yaml` identities. What each provider's terms say, as
written. Dates are the date on the document, or the date I read it when the
document has none.

| provider | what the terms state | source |
|---|---|---|
| Z.ai (Jingsheng Hengxing Technology Pte. Ltd., Singapore) | Data processing addendum, section 4(b): "The Company do not store any of the content the Customer or its End Users provide or generate while using our Services." Customer data is generally processed in Singapore. The consumer privacy policy, last updated 29 September 2025, also says data may be used "when we train and improve our models" and names no opt-out. Whether the Coding Plan falls under the addendum is not stated. | [privacy policy and DPA](https://docs.z.ai/legal-agreement/privacy-policy), read 13 Nov 2026 |
| DeepSeek (Hangzhou DeepSeek Artificial Intelligence Co., Ltd.) | Personal data is stored in the People's Republic of China, kept as long as the account exists. Inputs are used "to train and improve our technology". The policy lists a right to opt out of training, exercised by writing to the privacy contact. Last update 10 February 2026. | [privacy policy](https://cdn.deepseek.com/policies/en-US/deepseek-privacy-policy.html) |
| Moonshot (Kimi Open Platform) | Privacy policy, last update 30 April 2025: servers in Singapore, input retained while the account is active, user content used to optimise models, API content not addressed explicitly. Terms: Moonshot "may use Content to provide, maintain, develop, support, and improve the Services", with restriction available through an enterprise agreement. A separate page says the platform does not train on enterprise customer data by default and offers zero data retention to enterprise customers on request. | [privacy](https://platform.kimi.ai/docs/agreement/userprivacy), [terms](https://platform.kimi.ai/docs/agreement/modeluse), [ZDR](https://platform.kimi.ai/docs/guide/zero-data-retention), read 13 Nov 2026 |
| MiniMax | Not confirmed. The page I could read is the app and web policy (Nanonoble Pte. Ltd., updated 9 December 2025), which does not mention the API or model training. The API privacy policy dated 30 March 2026 that secondary sources describe was not retrievable. | [app and web policy](https://www.minimax.io/audio/doc/privacy-policy.html) |
| Alibaba Model Studio (Qwen) | Prompts and responses of inference calls are retained no longer than 30 days; stateful features until deleted. "Without your separate consent, we will not use your business data" to train, fine-tune or improve any foundation model. Zero data retention for eligible enterprise customers in non-mainland regions (Singapore, US Virginia, Germany, Hong Kong, Japan), cache up to 24 hours. Content flagged by safety filters may be kept up to 2 years. No date on the page. | [data retention policy](https://www.alibabacloud.com/help/en/model-studio/data-retention-policy), read 13 Nov 2026 |
| OpenCode Zen | "All our models are hosted in the US and EU." Providers follow a zero-retention policy and do not use data for training, except listed free models and the OpenAI and Anthropic APIs, which retain requests for 30 days. GLM 5.3 and GLM 5.3 Flash are not in the exception list. This is Zen's statement about its hosting, not the model vendor's. | [Zen](https://opencode.ai/docs/zen/), read 13 Nov 2026 |
| Anthropic | Conversation content is not retained by default and retained data is "never used for model training without your express permission". Claude Fable 5, 5.1, 5.2 and Mythos 5, 5.1, 5.2 are Covered Models that require 30-day retention, so the `anthropic` profile uses Opus, Sonnet and Haiku 5.5. Content flagged by trust and safety systems may be kept up to 2 years even under zero data retention. | [API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention), read 13 Nov 2026 |
| OpenAI | Abuse-monitoring logs are retained up to 30 days. API data is not used for training unless you opt in. Zero data retention needs prior approval. | [your data](https://developers.openai.com/api/docs/guides/your-data), read 13 Nov 2026 |

Retention and training terms change. Read the current text before putting client
data through any of them. `opencode debug config` prints resolved
`{env:...}` keys in plain text, so do not paste its output.

## not confirmed

- Live model ids: Z.ai's `/models` endpoint returned `glm-5.3`, `glm-5.3-flash`
  and `glm-5.3-flashx` on the coding, general and Anthropic-compatible paths with
  a real key (13 November 2026). `glm-5.3-highspeed`, listed in the registry for
  the coding plan, was not in that list. OpenCode Zen's public `/models` list
  includes `glm-5.3`, `glm-5.3-flash` and `deepseek-v4.1-flash`, not
  `kimi-k3.1-pro`. Moonshot, DeepSeek, MiniMax, Alibaba, Anthropic and OpenAI
  need a key I do not have, so those ids are checked against the registry only.
  OpenCode 1.18.31 resolves every id in the default and `anthropic` and `openai`
  profiles and suggests the id for an unconfigured provider (`Did you mean:
  glm-5.3, glm-5.3-flash, glm-5.3-highspeed`).
- A real chat completion on the default profile, the full orchestrator run, and
  any run on the fast tier.
- OpenCode 2.x behaviour, vLLM flags, Pro and Max plan prices, Kimi's Anthropic
  endpoint, and MiniMax's API data terms.
- Some Artificial Analysis and Terminal-Bench figures reached me through
  aggregators. Where two sources disagreed (Terminal-Bench 2.1 figures for
  GLM 5.3, the index version) they are left out or flagged above.
