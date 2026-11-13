# AI-driven web pentest / red-team agents: landscape as of November 2026

> **Working notes, not documentation.** This file belongs to the research
> trail behind Mythos. It records what was true when it was written and is not
> kept in sync with the code. For maintained documentation see `README.md`,
> `AGENTS.md` and `docs/architecture.md`.

Scope note: ~17 tool calls; mostly READMEs (fetched via summarizer, so wording is paraphrase) plus secondary blogs. Many headline numbers are vendor/maintainer-reported. Dates marked where known. Model names (GLM-5.3, DeepSeek V4, Kimi K3.1, Opus 5.5, GPT-6.1, Gemini 4) are as listed in the READMEs fetched.

## Q1. Which frameworks are actively maintained in 2026 and what are their headline results on XBOW validation-benchmarks or similar?

### Takeaway
Active: Strix (Apache-2.0), Shannon Lite (AGPL-3.0, 51k stars), PentestGPT v1.0 (MIT), PentAGI (MIT), XBOW (commercial, $120M Series C Mar 2026). CAI was ARCHIVED 28 Aug 2026. Headline XBEN numbers (Strix 96%, Shannon 96.15%, PentestGPT 86.5%) are all self/community-reported, not independently replicated, and the benchmark itself is partly broken upstream, so cross-framework comparison is unreliable.

### Cited Findings
Comparison table (condensed from sources below):

| Tool | Architecture | Models | Benchmark (reported) | License / status |
|---|---|---|---|---|
| Strix | "Graph of Agents": specialised recon/exploit/post-exploit agents sharing discoveries; Caido proxy, browser automation, shell, Python runtime, Docker sandbox; PoC validation | GLM-5.3, DeepSeek V4/V4.1 Flash, Kimi K3.1 Pro, GPT-6.1, Opus 5.5, Gemini 4, Bedrock/Vertex/Azure, local via LLM_API_BASE | 100/104 XBEN (96%), ~$3.37/challenge, vendor/community-reported | Apache-2.0; 961 commits, active 2026 |
| Shannon Lite (Keygraph) | Staged pipeline: recon + code analysis -> reconciliation into exploit queue -> exploitation agents -> validation -> report; white-box (repo mounted read-only), ephemeral Docker | Anthropic, OpenAI, xAI, Bedrock, any gateway, Ollama/vLLM via custom config | 96.15% (100/104) on "hint-free" XBEN, white-box | AGPL-3.0, 51.1k stars, no external code contributions, 316 commits |
| PentestGPT v1.0 | Staged autonomous pipeline driving Claude Code or Codex CLI (CTF: recon->exploit->walkthrough; pentest: asset discovery->vuln id->report); legacy mode = 3 LLM sessions + Pentesting Task Tree | Autonomous: Claude Code / Codex only; legacy: OpenAI, Anthropic, Gemini, DeepSeek, Grok, Qwen, Kimi, Ollama | 86.5% (90/104) XBOW, Dec 2025, $1.11 avg; README calls it historical | MIT; 307 commits |
| CAI (Alias Robotics) | openai-agents-python derived: agents, handoffs, patterns, HITL, tracing; LiteLLM 300+ models; 4-layer prompt-injection guardrails | any via LiteLLM; `alias` models paid only | CTF: #1 Neurogrid CTF (41/45 flags, $50k); Dragos OT CTF 2025 32/34; HTB AI vs Humans top AI | MIT parts + research-only proprietary parts; ARCHIVED 2026-08-28, no fixes, known prompt-injection holes unpatched |
| XBOW | Coordinator + many parallel solver agents, validators (LLM or programmatic), OAST servers | proprietary | #1 US HackerOne leaderboard 2025; 85% on its own benchmark equal to principal pentester | Commercial; $75M B (Jun 2025), $120M C (Mar 2026, >$1B valuation) |
| PentAGI (vxcontrol) | Go backend, multi-agent, PostgreSQL+pgvector, Graphiti/Neo4j knowledge graph | multi | none found | MIT; version/star counts conflict between sources |
| Vulnhuntr (ProtectAI) | Python static analysis + LLM, chunked call-chain tracing, confidence + PoC | Claude recommended; Ollama poor | >12 zero-days in Python projects (2024 era) | last commit ~1 year old per aggregator (unverified) |
| HexStrike-AI | MCP server exposing 150+ tools to Claude/GPT/Copilot | any MCP client | none found | Abused for Citrix exploitation (Check Point), Sept 2025 |

- Strix: Apache-2.0, Graph of Agents, Docker sandbox, Caido proxy, browser automation; recommended models GLM-5.3, DeepSeek V4/V4.1 Flash, Kimi K3.1 Pro — [Strix repo](https://github.com/usestrix/strix)
- Strix 100/104 XBEN, ~$3.37/challenge measured with GPT-5.4; "vendor and community-reported", no independent replication as of Aug 2026, 4 unsolved not named — [DEV: Strix claims 96%](https://dev.to/creeta/strix-claims-96-on-xben-that-number-is-vendor-reported-3en8)
- Strix benchmark repo exists (black-box, gemini-3-pro-preview per one mirror, unconfirmed) — [mirror](https://gh.ali360.cloudns.ch/usestrix/benchmarks/blob/main/XBEN); search summary at [WebSearch result above, see 0.security post]
- Shannon pipeline, "No exploit, no report", AGPL-3.0, 51.1k stars — [Shannon repo](https://github.com/KeygraphHQ/shannon)
- Shannon 96.15% (100/104) on hint-free XBEN (names/comments stripped) — secondary only: [besthub](https://www.besthub.dev/articles/shannon-ai-penetration-tester-delivers-96-exploit-success-rate-b5a7955d7da8); my fetch of the repo benchmark path returned 404, so primary not verified
- Shannon March 2026 issue: container runs seccomp:unconfined, ipc:host, hardcoded router key (resolution not checked) — [pinggy summary](https://pinggy.io/blog/automate_penetration_testing_with_ai/)
- PentestGPT 86.5% / 90 of 104, Dec 2025, historical, XBOW harness not in product repo; MIT — [PentestGPT repo](https://github.com/GreyDGL/PentestGPT); maintainer-reported per [Penligent](https://www.penligent.ai/hackinglabs/de/pentest-gpt-in-2026-from-clever-prompts-to-verified-findings/)
- CAI archived 2026-08-28, successor commercial CSI; CTF results above — [CAI repo](https://github.com/aliasrobotics/cai)
- XBOW: #1 US HackerOne, $75M B — [XBOW Series B](https://xbow.com/blog/series-b); $120M C Mar 2026 — [BusinessWire](https://www.businesswire.com/news/home/20260318258057/en/XBOW-Raises-$120M-to-Scale-its-Autonomous-Hacker)
- XBOW vs principal pentester: both 85%, 28 min vs 40 h — [XBOW blog via search](https://xbow.com/blog/xbow-vs-humans)
- XBOW HackerOne stats (~1,060 submitted; 54 crit/242 high/524 med/65 low over 90 days; 208 dups, 209 informative; ~45% still unresolved; totals do not reconcile) — [XBOW top-1 post](https://xbow.com/blog/top-1-how-xbow-did-it/)
- Benchmark rot: clean clone fails to build 39/104; one cold run 45/104 (43.3%) overall, 69.2% of 65 buildable; 87.5% on community-patched fork was best-of-N over 74 runs; a 103/104 aggregate was withdrawn as misleading; XBEN-079 accepted a flag-shaped dummy value (checker inflates) — [0.security: the unsolved nine](https://0.security/blog/2026-04-07-the-unsolved-nine) (vendor with own agent, self-interested)
- Red-MIRROR with DeepSeek-V3.2: 21/22 L1 (95.45%), 19/23 L2 (82.6%) — [Wizwand L1/L2 leaderboards via search](https://www.wizwand.com/sota/automated-penetration-testing-on-xbow-level-2-medium)
- PentAGI: Graphiti+Neo4j graph, pgvector, group IDs per flow, MIT — [Mintlify docs](https://www.mintlify.com/vxcontrol/pentagi/concepts/knowledge-graph)
- Vulnhuntr: >12 zero-days (gpt_academic, FastChat, Ragflow) — [ProtectAI](https://protectai.com/threat-research/vulnhuntr-first-0-day-vulnerabilities)
- HexStrike-AI: 150+ tools via MCP, used by criminals vs Citrix NetScaler flaws — [The Hacker News](https://thehackernews.com/2025/09/threat-actors-weaponize-hexstrike-ai-to.html)
- 2026 Claude-Code/OpenCode-based entrants: Pencheff (MCP + Claude Code plugin, masks secrets), hardw00t AI Security Arsenal (OpenCode-compatible skills), Transilience communitytools (26 skills), pentest-ai-agents (31-35 subagents, MIT), Trail of Bits skills (Apache-2.0, not pentest-specific); Strix itself ships 9 SKILL.md skills (`npx skills add usestrix/strix`) — [PyPI pencheff](https://pypi.org/project/pencheff/), [vibed-lab](https://vibed-lab-agents.pages.dev/agent/hardw00t-ai-security-arsenal), [vpncentral](https://vpncentral.com/?p=249278), [Strix repo](https://github.com/usestrix/strix)

### Inferences
- Shannon's 96% is white-box (source access) while PentestGPT/Strix are mostly black-box; not like-for-like. The trend: pentest agents are converging onto "skill + coding-agent harness" (PentestGPT drives Claude Code/Codex; Strix and others ship SKILL.md), which matches the mythos-sec skill-driven pivot.
- All three 86-96% claims should be treated as ~"mid-80s to mid-90s on a leaky benchmark"; report single-attempt, build-verified, hint-free numbers only if reproducing.

### Gaps
- Primary Shannon benchmark document (404) and Strix benchmarks repo contents not read; model behind each score unconfirmed.
- No independent replication of any 2026 XBEN claim found.
- Nebula (Beryllium), RapidPen, AutoPenBench agents: not researched in this pass; only uncited memory (AutoPenBench = 33 tasks, 2024 paper; RapidPen = IP-to-shell, 2025; Nebula = CLI assistant) - treat as unverified.
- Exact release versions/dates for Strix, PentestGPT, PentAGI (Releases pages empty or conflicting).

## Q2. Which design patterns (validation subagents, closure states, coverage matrices, evidence rules, memory/task trees) are best practice?

### Takeaway
Convergent best practice: separate hypothesis generation from exploitation, then an independent validator/proof stage with an "exploit or it does not count" rule; shared graph/task state across agents; parallel solvers with iteration budgets under a coordinator; deduplication. Coverage matrices and explicit closure states were not documented in the sources I read.

### Cited Findings
- Validators = automated peer reviewers, LLM-based or programmatic; headless browser confirms XSS payload executed — [XBOW top-1](https://xbow.com/blog/top-1-how-xbow-did-it/)
- XBOW coordinator + solvers + out-of-band interaction servers; Learn/Map/Coordinate/Attack/Prove stage naming is third-party — [XBOW podcast](https://xbow.com/podcasts/ai-hacking-agent-and-human-in-the-loop-with-diego-jurado), [codeant](https://codeant.ai/blogs/xbow-features)
- Capped iterations per solver, budget reallocation by coordinator — third-party only, unconfirmed: [vmsoit](https://vmsoit.blogspot.com/2026/04/xbow-air-benchmark-vs-human-red-teams-in-pentesting.html?hl=ar)
- Shannon: candidate -> reconciliation/dedup -> exploit queue -> validation; CI gates count only `status: exploited`; hypotheses from code analysis never fail pipelines; still "requires human review" — [Shannon repo](https://github.com/KeygraphHQ/shannon)
- XBOW dedup of cloned/staging environments via content + visual similarity — [XBOW top-1](https://xbow.com/blog/top-1-how-xbow-did-it/)
- PentestGPT legacy: Pentesting Task Tree across reasoning/generation/parsing sessions; v1.0 session save/resume — [PentestGPT repo](https://github.com/GreyDGL/PentestGPT)
- PentAGI: Graphiti knowledge graph + pgvector, per-flow group IDs — [Mintlify](https://www.mintlify.com/vxcontrol/pentagi/concepts/knowledge-graph)
- CAI: handoffs, HITL, tracing, `/compact`, `/memory`, 4-layer prompt-injection guardrail — [CAI repo](https://github.com/aliasrobotics/cai)
- Evaluation should score validated findings (precision, recall, duplicates) not task completion — [arXiv 2605.xxxxx via search result](https://arxiv.org/pdf/2605.10834) (title not verified)
- SoK taxonomy of 6 dimensions (architecture, plan, memory, execution, external knowledge, benchmarks); 13 open-source frameworks + 2 baselines, >10B tokens, 1,500+ logs reviewed manually — [arXiv 2604.05719](https://arxiv.org/abs/2604.05719)
- Benchmark checkers must validate flag provenance (dummy flag accepted in XBEN-079) — [0.security](https://0.security/blog/2026-04-07-the-unsolved-nine)

### Inferences
- Worth adopting: evidence-gated status enum (candidate/exploited/refuted), dedup stage, reconciliation queue, programmatic + LLM validator pair, per-finding provenance for flags/OAST callbacks.
- Closure states and coverage matrices appear to be gaps the community has not published; a Mythos differentiator.

### Gaps
- SoK 2604.05719 full text (which frameworks, per-framework results, failure taxonomy) not read.
- No source describing explicit coverage matrices or closure states.

## Q3. How do they handle authenticated testing, multi-account BOLA, stored-XSS proof (admin bots / OAST), and race conditions?

### Takeaway
Auth is supported mostly as configured credentials/login flows (Shannon: credentials, login flows, TOTP, email auth; Strix: grey-box session credentials). I found no published, specific multi-account BOLA/IDOR methodology, admin-bot XSS handling, or race-condition technique in any framework.

### Cited Findings
- Shannon config: credentials, login flows, TOTP, email authentication, focus areas, rules of engagement — [Shannon repo](https://github.com/KeygraphHQ/shannon)
- Strix `--target` modes: directory (code), URL (black-box), session credentials (grey-box authenticated) — [DEV article](https://dev.to/creeta/strix-claims-96-on-xben-that-number-is-vendor-reported-3en8)
- XBOW: headless browser confirms XSS executes; OAST/out-of-band servers used by solvers (podcast summary); XBOW auth handling not described in its blog — [XBOW top-1](https://xbow.com/blog/top-1-how-xbow-did-it/)
- Pencheff masks secrets so credentials do not leak into logs/findings — [PyPI](https://pypi.org/project/pencheff/)
- Evaluation of "Evaluating key functional properties of LLM architectures in pentesting" (2509.14289) exists but not read — [arXiv](https://arxiv.org/abs/2509.14289)

### Inferences
- Multi-account BOLA, admin-bot stored-XSS and race conditions are open niches: sources show no framework claiming first-class support. Build-yourself items for Mythos (two-session state diffing, own OAST + bot trigger, single-packet/parallel-request harness).

### Gaps
- Search for BOLA/IDOR/race in LLM pentest agents returned nothing specific; Shannon configuration guide and Strix docs not read in depth.

## Q4. Which frameworks run on free/open-weight Chinese models (GLM, Qwen, DeepSeek, Kimi) and with what degradation?

### Takeaway
Strix explicitly recommends GLM-5.3, DeepSeek V4/V4.1 Flash, Kimi K3.1 Pro; Shannon demonstrates DeepSeek v4 Flash sample reports; PentestGPT legacy supports DeepSeek/Qwen/Kimi/Ollama; Red-MIRROR scored well with DeepSeek-V3.2 on XBEN L1/L2. No quantified degradation versus frontier models was found.

### Cited Findings
- Strix recommended list incl. GLM-5.3 via OpenRouter/Vercel gateway, DeepSeek V4/V4.1 Flash, Kimi K3.1 Pro; local via `LLM_API_BASE` — [Strix repo](https://github.com/usestrix/strix)
- Shannon sample reports with DeepSeek v4 Flash, Grok 4.6, Claude Opus 5 on Photoview 2.4.0; warns weaker instruction/tool-use models give weaker results; Ollama/vLLM via custom model file — [Shannon repo](https://github.com/KeygraphHQ/shannon)
- PentestGPT legacy: DeepSeek, Qwen, Kimi, Ollama (`ollama:qwen3`); autonomous v1.0 is Claude Code/Codex only — [PentestGPT repo](https://github.com/GreyDGL/PentestGPT)
- Vulnhuntr: Ollama models "have not worked well", Claude recommended — [Vulnhuntr wiki search](https://github.com/protectai/vulnhuntr)
- Red-MIRROR + DeepSeek-V3.2: 95.45% L1, 82.61% L2 — [Wizwand](https://www.wizwand.com/sota/automated-penetration-testing-on-xbow-level-2-medium)
- Anthropic/OpenAI cyber safeguards can interrupt scans (an advantage of open-weights: no refusals) — [Shannon repo](https://github.com/KeygraphHQ/shannon)

### Inferences
- Open-weight models are viable for the mid-tier challenges; degradation likely concentrates in L3/hard multi-step chains and tool-call reliability, but no cited data.

### Gaps
- No ablation of open vs closed models on the same harness found; Red-MIRROR is a different agent from the others and levels 3 not retrieved.

## Q5. Known failure modes and critiques

### Takeaway
Documented issues: hallucinated commands/findings, tool misuse, loops, state fragmentation; benchmark inflation; vendor-reported numbers; scope/policy violations; agent-framework security holes (prompt injection, weak container isolation); dual-use abuse.

### Cited Findings
- Recurring errors: hallucinated commands, tool misuse, redundant looping, state fragmentation, context drift — [arXiv 2509.14289](https://arxiv.org/html/2509.14289v2)
- APT-Agent rectification module for hallucinated entities (wrong Metasploit paths), 84.29% on 70 trials, Metasploitable 2 only — [Moonlight review](https://www.themoonlight.io/tw/review/apt-agent-automated-penetration-testing-using-large-language-models)
- PentestEval: end-to-end pipelines about 31% success; agents nearly fail fully end-to-end (secondhand via Penligent) — [Penligent](https://www.penligent.ai/hackinglabs/de/pentest-gpt-in-2026-from-clever-prompts-to-verified-findings/)
- Survey 2607.02605 (Jul 2026, 81 papers): open challenges = evaluation reliability, limited multi-stage performance, scarce high-quality training data; RLVR as newest phase; frameworks specialise narrowly — [arXiv](https://arxiv.org/abs/2607.02605)
- Third-party view that agents are "single-host exploiters" not end-to-end pentesters — [llm-pentest-papers](https://llm-pentest-papers.pages.dev/)
- XBOW: removed from a program that disallowed automated scanners; scope documents not machine-readable; many findings informative/duplicate; human review before submit — [XBOW top-1](https://xbow.com/blog/top-1-how-xbow-did-it/)
- Shannon: LLM reports may contain weakly supported details; March 2026 isolation issue — [Shannon repo](https://github.com/KeygraphHQ/shannon), [pinggy](https://pinggy.io/blog/automate_penetration_testing_with_ai/)
- CAI: prompt-injection weaknesses acknowledged, will not be fixed (archived) — [CAI repo](https://github.com/aliasrobotics/cai)
- Benchmark inflation (best-of-N, flag checker flaws, unbuildable challenges) — [0.security](https://0.security/blog/2026-04-07-the-unsolved-nine)
- HexStrike-AI weaponization — [The Hacker News](https://thehackernews.com/2025/09/threat-actors-weaponize-hexstrike-ai-to.html)

### Inferences
- Mythos should: log provenance of every flag/callback, enforce scope allow-list in the tool layer (not prompt), treat tool output as untrusted (prompt injection), and report single-attempt rebuilt-benchmark numbers.

### Gaps
- Per-framework false-positive rates not found; SoK full text would likely supply them.
- Academic items not covered in this pass: PentestGPT (USENIX Sec 2024), AutoPenBench, CAI paper (arXiv 2504.06017 per memory), CAIBench, "What makes a good LLM agent for real-world pentesting" - only noted by title in search results; unverified here.
