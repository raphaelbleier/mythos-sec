# Prompt injection as a security vulnerability class: measurement, adaptive attacks, and evidence standards (as of 2026-11-13)

Scope note. Tiering used throughout: [PR] = peer-reviewed venue stated on the arXiv page; [PP] = arXiv preprint, no venue stated; [WS] = workshop paper; [VENDOR] = vendor or company blog/system card; [STD] = standards body or practitioner framework; [PRESS] = secondary press/aggregator (not trusted for numbers). Venue status was read from the arXiv "comments" field; a missing venue means "none listed on the page", not "rejected". Several 2026 arXiv ids below (26xx.xxxxx) were fetched successfully from arxiv.org but I read abstracts and metadata only, not full texts, unless stated. A WebFetch summariser model produced the per-defense table from 2510.09023; numbers from it should be spot-checked against the PDF before quotation. Any attack success rate (ASR) lacking n, model and threat model is marked UNINTERPRETABLE.

---

## 1. Benchmark landscape: AgentDojo, AutoDojo, InjecAgent, 2026 successors

### Takeaway
AgentDojo (97 user tasks, 629 security cases) and InjecAgent (1,054 cases, single-turn) are static benchmarks with deterministic or parsed-output checks. 2026 work (AgentDyn, AutoDojo, Adaptive Adversaries, IPI Bench) was built specifically because static pools saturate near 0% for modern defenses while adaptive attackers recover double-digit to majority ASR.

### Cited Findings
- AgentDojo: 97 realistic tasks and 629 security test cases; authors say state-of-the-art LLMs fail many tasks even without attack and that existing attacks break some but not all security properties. arXiv preprint, no venue on the arXiv page (v3 24 Nov 2024) [PP] — [arXiv 2406.13352 abs](https://arxiv.org/abs/2406.13352)
- AgentDojo detail from the full text: 97 user tasks and 27 injection tasks over four suites (Workspace 40/6, Slack 21/5, Travel 20/7, Banking 16/9); 629 security cases = user tasks x injection tasks per suite (240+105+140+144). Tool count is inconsistent in the paper (70 in abstract/Table 1, 74 in text and per-suite sum) — [arXiv 2406.13352 html](https://arxiv.org/html/2406.13352)
- AgentDojo threat model: attacker plants injections in untrusted tool outputs (e.g. an email, a web page); attacker knowledge of user name and model name studied as ablation. Metrics: benign utility, utility under attack, targeted ASR. Injection success is checked by deterministic security functions over environment state, not an LLM judge, so a successful injection cannot also fool the evaluator — [arXiv 2406.13352 html](https://arxiv.org/html/2406.13352)
- AgentDojo headline numbers with the "Important message" attack (n = 629 security cases per cell): GPT-4o benign utility 69.00%, utility under attack 50.08%, targeted ASR 47.69% (Table 3); Claude 3.5 Sonnet 78.22% / 51.19% / 33.86%. Internal inconsistency: Tables 4 and 5 give GPT-4o undefended ASR as 57.7% versus 47.69% in Table 3 — [arXiv 2406.13352 html](https://arxiv.org/html/2406.13352)
- AgentDojo defenses on GPT-4o (static attack, Table 5): spotlighting/data delimiting ASR 41.65% (from 57.69%); PI detector 7.95% but benign utility falls to 41.49%; prompt repetition (sandwiching) 27.82%; tool filter 6.84%. Authors' limitations: tool filter fails when needed tools cannot be planned ahead or when the task's own tools can carry the attack (17% of cases); detector has high false positives; repeat-prompt "unlikely to withstand adaptive attacks"; attacks are relatively simple; task spec and utility checks manual; no multimodal coverage — [arXiv 2406.13352 html](https://arxiv.org/html/2406.13352)
- AgentDojo reports 95% CIs via statsmodels `proportion_confint`; the text does not describe repeated seeds — [arXiv 2406.13352 html](https://arxiv.org/html/2406.13352)
- InjecAgent: 1,054 test cases, 17 user tools, 62 attacker tools, two attacker intents (direct harm, data exfiltration), 30 agents evaluated, ACL 2024 Findings [PR] — [arXiv 2403.02691 abs](https://arxiv.org/abs/2403.02691)
- InjecAgent ASR: ReAct-prompted GPT-4 total ASR-valid 23.6% base (direct harm 14.7%, data stealing 31.9%), 47.0% with the "enhanced" hacking prompt (direct harm 33.3%, data stealing 59.9%); ASR-all 23.3% / 46.8%. Model-specific, single fixed prompt; per-cell n is the 1,054-case set split by intent — [arXiv 2403.02691 html](https://arxiv.org/html/2403.02691)
- InjecAgent limitations stated: one fixed hacking prompt ("point-in-time", easily filtered); attacker instructions are the only content in the external source (no benign mixing); single-turn, attacker steps capped at two; only two fine-tuned agents; assumes the user tool was executed correctly beforehand — [arXiv 2403.02691 html](https://arxiv.org/html/2403.02691)
- InjecAgent scoring is on parsed model output, not real execution: "tool execution is identified through the parsed outputs." For data stealing, step S1 (extraction call) and S2 (send call) are scored separately, but the data-stealing total counts only full S1+S2 chains; S1 results are simulated by GPT-4 — [arXiv 2403.02691 html](https://arxiv.org/html/2403.02691)
- AgentDyn: 60 open-ended tasks and 560 injection test cases across Shopping, GitHub, Daily Life; ten defenses tested; abstract concludes nearly all are either not secure enough or over-defend. Authors argue existing benchmarks lack dynamic open-ended tasks, helpful third-party instructions, and non-trivial user tasks. Preprint, v3 May 2026 [PP] — [arXiv 2602.03117](https://arxiv.org/abs/2602.03117). Per-defense ASR not read.
- AutoDojo (arXiv 2606.15057, Ma, Li, Xiao, Yu, Zhang, Vorobeychik; v1 13 Jun 2026, v3 28 Sep 2026) [PP]: generative benchmark on AgentDojo + AgentDyn, six suites (banking, communication, travel, shopping, coding, everyday assistance), strict black-box (attacker observes only success/fail), ten defenses x five target models, finding static benchmarks "often significantly overestimate defense efficacy"; most defenses lose considerable utility or stay insecure; under-specified tasks especially vulnerable — [arXiv 2606.15057](https://arxiv.org/abs/2606.15057)
- AutoDojo numbers from a search-engine summary of an earlier version (title differs: "Adaptive Black-Box Attacks Reveal the Limits of IPI Defenses..."): against a filter with 0% static ASR, adaptive recovered 28% overall and 64% on "action-open" tasks (user delegates the action to external content); overall ASR 26.0% at k=2 iterations to 30.8% at k=12. Not verified against full text; n and models not read, so these are UNINTERPRETABLE until checked — [search summary of 2606.15057](https://arxiv.org/pdf/2606.15057)
- Adaptive Adversaries (arXiv 2607.18063, Jain, Hartmann, Li; v1 20 Jul 2026, v2 11 Sep 2026; workshop "Agents in the Wild") [WS]: 21 scenarios, 3 attacker LLMs x 3 defender models = 945 battles, competition of 18,422 held-out battles on gpt-oss-20b. First-round-only ASR 0-1%; up to 15 adaptive rounds 7.9-16.8% (v2 abstract; a search-snippet gave 5.4-14.0%, likely v1). One provenance paragraph in the prompt cut successful attacks from 110/270 (~41%) to 70/270 (~26%) in six scenarios. Pooling three attacker LLMs found 1.7-2.2x as many unique successes at 3x budget — [arXiv 2607.18063](https://arxiv.org/abs/2607.18063)
- IPI Bench (General Analysis) [VENDOR, sells AI red-teaming; not independently audited]: 34 tasks in an emulated company ("Madrigal Dynamics", 11 services), attacker adds 1-3 records (about 0.5% of text the agent reads), rollouts of 50-130 tool calls. ASR with 95% intervals for three settings (one query / 11 independent queries / iteration up to 16 rounds, 176 queries): e.g. Claude Opus 5.5 4.8%±1.7 / 17.6%±4.9 / 41.2%±5.7; GPT-6 Astra 7.5 / 20.6 / 50.0; Gemini 4 Argon 12.6 / 38.2 / 70.6; DeepSeek V4.1 Flash 35.3 / 79.4 / 97.1. Review "upheld" 271 sampled successful attacks (50 per model sampled), reviewer procedure not described — [General Analysis IPI Bench](https://generalanalysis.com/blog/ipi-bench). Model names are as the page states them; I could not independently confirm them.
- Assessing Automated Prompt Injection Attacks in Agentic Environments (Hofer, Debenedetti, Tramèr; arXiv 2606.10525, 9 Jun 2026) [PP]: GCG and TAP adapted to AgentDojo over 80 task pairs in four domains; black-box optimisation substantially outperforms gradient methods (GCG unstable under reasonable compute); safety-tuned attacker models may refuse; universal attacks transfer across tasks, but attacks optimised on small open models do not transfer to frontier models such as GPT-5. A search summary gives universal TAP 45.2% ASR on Qwen (unverified, n not read) — [arXiv 2606.10525](https://arxiv.org/abs/2606.10525)
- AgentPI (arXiv 2602.10453, tracks security, utility and cost together) and "The Landscape of Prompt Injection Threats in LLM Agents" appear in search results; abstract-level claims only, not fetched — [alphaxiv 2602.10453](https://www.alphaxiv.org/abs/2602.10453.md)

### Inferences
- AgentDojo's check-by-state design is the right oracle shape for a red-team framework (see Q5), but its fixed injection pool is exactly the "static eval" the 2026 papers attack.
- The ~0-1% first-round vs 8-17% after-15-rounds split (Adaptive Adversaries) and the 4.8% / 17.6% / 41.2% ladder (IPI Bench) show that ASR is a function of attacker budget; a single ASR number is only meaningful with budget stated.

### Gaps
- Per-defense static vs adaptive ASR and n for AutoDojo not read (only abstract). The two titles/versions of 2606.15057 should be reconciled before citing numbers.
- AgentDyn per-defense ASR, AgentPI, and the 2606.10525 ASR tables not read.
- Model names in IPI Bench could not be cross-checked against a primary model vendor.

---

## 2. "The Attacker Moves Second" (arXiv 2510.09023) and the adaptive-attack critique

### Takeaway
Nasr, Carlini, Tramèr et al. (14 authors, Oct 2025) bypassed 12 published jailbreak/prompt-injection defenses with adaptive optimisation and a 500+ person human red-team, reaching ASR above 90% for most defenses that had originally reported near-zero. This repeats the 2018-2020 adversarial-examples history and the authors state that empirical evaluation cannot prove robustness.

### Cited Findings
- Paper: "The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections", cs.LG cross-list cs.CR, submitted 10 Oct 2025; authors Nasr, Carlini, Sitawarin, Schulhoff, Hayes, Ilie, Pluto, Song, Chaudhari, Shumailov, Thakurta, Xiao, Terzis, Tramèr. No venue on the arXiv page [PP] — [arXiv 2510.09023](https://arxiv.org/abs/2510.09023)
- Claim: defenses were tested against fixed attack strings or weak optimisation not designed against the defense. By tuning and scaling gradient descent, RL, random search and human-guided exploration they bypass 12 defenses, ASR above 90% for most; the majority had originally reported near-zero ASR — [arXiv 2510.09023](https://arxiv.org/abs/2510.09023)
- Per-defense table as extracted from the full text (verify against PDF): Spotlighting (AgentDojo) static as low as ~1%, adaptive >95%; Prompt Sandwiching ~1% -> >95%; RPO (HarmBench) 98% via RL, 96% via GCG; Circuit Breakers 100% (RL); StruQ succeeded in every case tested; MetaSecAlign (AgentDojo) 2% -> 96% (search); Protect AI detector, PromptGuard, Model Armor >90%; PIGuard 71%; Data Sentinel bypassed in every case; MELON 76% (no defense knowledge, Llama-3.3-70B) to 95% (full knowledge). n per cell and exact original ASRs are not recoverable from my extraction — [arXiv 2510.09023 html](https://arxiv.org/html/2510.09023)
- Attack budgets: RL attacker with 5 rounds per session, 32 sessions per sample, GRPO updates; search attack with Gemini-2.5 Pro mutator, 8 candidates per iteration, MAP-Elites controller; gradient attack GCG (500 steps, 512 queries per step cited from the GCG paper) — [arXiv 2510.09023 html](https://arxiv.org/html/2510.09023)
- Human red-teaming: over 500 participants, 40 challenges, $20,000 in prizes; humans defeated every challenge; on a selected subset, search succeeded 69% versus 100% for humans collectively; 123 human-collected successes against the detector defenses "even under the strictest setting" — [arXiv 2510.09023 html](https://arxiv.org/html/2510.09023)
- Authors' evaluation guidance: "Small static evals can be misleading"; "empirical evaluations cannot prove that a defense is robust"; ASRs "not necessarily comparable across defenses" because benchmarks differ; auto-raters can be reward-hacked; both human and automated red-teaming matter; detector defenses cost substantial utility; prompting defenses keep utility but add little robustness — [arXiv 2510.09023 html](https://arxiv.org/html/2510.09023)
- Authors' own limitations: human skill varies; attempt counts not comparable across methods; the human-vs-search comparison covers 29 scenarios with uneven effort per scenario; the search attack was a single run without restarts with high run-to-run variance and plateaued after ~100-200 queries; the search found no new attack strategy beyond the literature — [arXiv 2510.09023 html](https://arxiv.org/html/2510.09023)
- Plan-then-execute defenses (Tool Filter, CaMeL, IPIGuard) were NOT attacked: control flow is independent of data so attacks fail in most selected scenarios; authors say these are no cure-all, apply to limited tasks and reduce utility, and should be evaluated on scenarios where control flow depends on data — [arXiv 2510.09023 html](https://arxiv.org/html/2510.09023)
- Earlier adaptive-attack work on IPI defenses: Zhan, Fang, Panchal, Kang, "Adaptive Attacks Break Defenses Against Indirect Prompt Injection Attacks on LLM Agents", NAACL 2025 Findings [PR]: eight defenses evaluated and all bypassed, ASR over 50% (benchmark and n not on abstract page) — [arXiv 2503.00061](https://arxiv.org/abs/2503.00061)
- History in adversarial ML: Carlini, Athalye, Papernot, Brendel, Rauber, Tsipras, Goodfellow, Madry, Kurakin, "On Evaluating Adversarial Robustness" (2019): "few have succeeded; most papers that propose defenses are quickly shown to be incorrect" [PP] — [arXiv 1902.06705](https://arxiv.org/abs/1902.06705). Tramèr, Carlini, Brendel, Madry, "On Adaptive Attacks to Adversarial Example Defenses": thirteen defenses published at ICLR, ICML and NeurIPS circumvented even though their authors attempted adaptive evaluations (NeurIPS 2020; venue not on the page I read) — [arXiv 2002.08347](https://arxiv.org/abs/2002.08347). Athalye et al., obfuscated gradients (arXiv 1802.00420, ICML 2018) is the third canonical reference; I did not fetch it.
- Independent reproduction on out-of-band defenses: Narisetty et al. (arXiv 2606.26479, Jun 2026) [PP] argue CaMeL, FIDES, Progent, RTBAS, FORGE are validated only on static benchmarks; on AgentDojo with self-hosted Qwen2.5-7B, 3 runs, Progent cut mean ASR 25.8% -> 4.2%, a hand-crafted adaptive attack reached 2.6%. They call it "one small-scale data point on a weak model", single black-box template, no GCG — [arXiv 2606.26479](https://arxiv.org/abs/2606.26479)

### Inferences
- The strongest version of the paper's lesson for a practitioner is epistemic: absence of a successful attack in a fixed pool is not evidence of safety, and "defense bypassed" claims must report attacker budget.
- Note that the paper's own gradient and RL evidence lies mostly on jailbreak benchmarks (HarmBench), while only the search/human parts map onto AgentDojo-style injection.

### Gaps
- n per defense for the adaptive results, and the original claimed ASR per defense, were not recoverable from my extraction.
- I did not read the Athalye obfuscated-gradients paper directly.

---

## 3. Measured defense efficacy: static versus adaptive

### Takeaway
Prompt-level and detector defenses show 0-10% ASR on static pools but >70-95% under adaptive attack; system-level capability separation (CaMeL, tool filtering, planner/reader splits) holds by construction against the control-flow attacks it targets but costs utility and does not address data-flow or "action-open" attacks.

### Cited Findings
- Spotlighting (Hines et al., Microsoft): GPT-family models, ASR from above 50% to below 2%, minimal task impact (abstract; model variant and n not stated) [PP] — [arXiv 2403.14720](https://arxiv.org/abs/2403.14720). Adaptive: >95% on AgentDojo per 2510.09023 (static ~1%). On AgentDojo GPT-4o with a static attack, delimiting only reduces ASR from 57.69% to 41.65% — [arXiv 2406.13352 html](https://arxiv.org/html/2406.13352)
- Instruction hierarchy (Wallace et al., OpenAI): applied to GPT-3.5, "drastically increases robustness", minimal capability degradation; no numbers in abstract [PP] — [arXiv 2404.13208](https://arxiv.org/abs/2404.13208)
- SecAlign (preference optimisation), ACM CCS 2025 [PR]: reduces success rates of various prompt injections to <10% — [arXiv 2410.05451](https://arxiv.org/abs/2410.05451). Meta-SecAlign preprint v4 28 Sep 2026: keeps almost all utility (abstract gives no ASR) [PP] — [arXiv 2507.02735](https://arxiv.org/abs/2507.02735). Adaptive: MetaSecAlign 2% -> 96% on AgentDojo (search attack); StruQ broken in every tested case — [arXiv 2510.09023 html](https://arxiv.org/html/2510.09023)
- Classifier/detector filters: PI detector on AgentDojo GPT-4o static ASR 7.95% but benign utility 41.49% — [arXiv 2406.13352 html](https://arxiv.org/html/2406.13352). Adaptive: Protect AI, PromptGuard, Model Armor >90%, PIGuard 71% — [arXiv 2510.09023 html](https://arxiv.org/html/2510.09023). AutoDojo: a filter at 0% static ASR recovered to 28% overall / 64% on action-open tasks (unverified summary, see Q1) — [AutoDojo summary](https://arxiv.org/pdf/2606.15057). EchoLeak evaded Microsoft's XPIA classifier in production — [arXiv 2509.10540](https://arxiv.org/abs/2509.10540)
- CaMeL (Debenedetti et al. line; "Defeating Prompt Injections by Design"): solves 77% of AgentDojo tasks with provable security vs 84% undefended (about 7 points utility cost; my arithmetic) [PP] — [arXiv 2503.18813](https://arxiv.org/abs/2503.18813). Not attacked in 2510.09023 (see Q2). Design Patterns for Securing LLM Agents against Prompt Injections (Beurer-Kellner et al., 14 authors incl. Tramèr): set of patterns with provable resistance, utility-security trade-offs, case studies; pattern names not on the abstract page [PP] — [arXiv 2506.08837](https://arxiv.org/abs/2506.08837)
- Architecting Secure AI Agents (NVIDIA, arXiv 2603.30016, March 2026) [PP]: argues LLM-as-judge security layers can themselves be prompt-injected (from a secondary summary; paper not fetched) — [alphaxiv 2603.30016](https://www.alphaxiv.org/abs/2603.30016.md)
- The Framing Gap (arXiv 2608.27092, Rahman and Kim, 27 Aug 2026) [PP], synthetic lab with canary secret, mock tools, six models: overt injection classes 0% on gpt-4o, reframing as "mandatory integrity signature"/config field/look-alike trusted host raised gpt-4o from 0% to 100%; fresh page around a new mechanism succeeded 0/130; destination allow-list and planner/reader capability split each reduced ASR to 0%; "in any form" policy clause 0% but 48.8% once the catch-all dropped; SecAlign 32.5%, channel separation 38.8%; ROT13 beat an output-normalising guard (100%). n per condition, other five models, CIs not on the page; treat as indicative — [arXiv 2608.27092](https://arxiv.org/abs/2608.27092)
- Dual-LLM / quarantined-LLM pattern: appears as a named pattern in the Design Patterns paper family; I found no independent adaptive-attack measurement of a dual-LLM deployment. (Gap.)
- Prompt-based provenance help: one provenance paragraph cut successful attacks 41% -> 26% (110/270 -> 70/270) in six scenarios, effect varied by task — [arXiv 2607.18063](https://arxiv.org/abs/2607.18063)
- Vendor adaptive-RL claims: OpenAI says it uses an RL-trained automated attacker to harden Atlas; per press, a spokesperson declined to say whether the update measurably reduced successful injections [PRESS] — [TechCrunch 2025-12-22](https://techcrunch.com/2025/12/22/openai-says-ai-browsers-may-always-be-vulnerable-to-prompt-injection-attacks/)

### Inferences
- Rough pattern across sources: static ASR 0-10% for prompt/detector/fine-tuned defenses collapses to 70-98% under optimisation; deterministic out-of-band enforcement (capabilities, allow-lists) is the only class where adaptive evidence so far shows 0-4%, but those results are small-n and on weak models (2606.26479, 2608.27092), or the defense was excluded from attack (CaMeL in 2510.09023).
- Capability separation limits impact (what a hijacked model can do) rather than preventing hijack; AutoDojo's "action-open" finding suggests data can pose as the instruction the user delegated, which a control-flow split cannot see.

### Gaps
- No peer-reviewed adaptive attack against CaMeL found in my searches (not exhaustive).
- No measured adaptive efficacy found for a dual-LLM deployment, or for instruction-hierarchy models with n and model stated.

---

## 4. Reproducibility: stochasticity, trial counts, confidence intervals

### Takeaway
There is no published universal threshold ("N trials at X%") for calling an injection real. Practice has converged on reporting ASR with binomial or bootstrap intervals and, increasingly, on "at least one success in N independent attempts" (Success@N), which makes single-run numbers fragile.

### Cited Findings
- OWASP states it is unclear whether fool-proof prevention exists, citing the stochastic nature of the models [STD] — [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- AgentDojo reports 95% CIs with `proportion_confint` (statsmodels) over 629 cases per cell; no repeated-seed description — [arXiv 2406.13352 html](https://arxiv.org/html/2406.13352)
- Attacker Moves Second: the search attack "uses a single run without restarts and its results vary a lot between runs"; authors believe parallel trials would raise ASR against a robust model — [arXiv 2510.09023 html](https://arxiv.org/html/2510.09023)
- IPI Bench: one query 4.8%±1.7 vs 11 independent queries 17.6%±4.9 for the same model; "success in any rollout" is the stated criterion for the multi-query setting [VENDOR] — [General Analysis](https://generalanalysis.com/blog/ipi-bench)
- A search summary (not verified against papers) reports another study using 20 matched trials per cell at temperature 0.7 with 95% Wilson intervals and declining to rank conditions within run-to-run variation; a bootstrap study with B=200; Success@N defined as the fraction of cases where at least one attack succeeds within N separate attempts — [search results incl. arXiv 2606.10525](https://arxiv.org/pdf/2606.10525). Treat as leads, not citations.
- The Framing Gap reports counts such as 0/130 for a fresh mechanism; a 0/130 result bounds the true rate (rule of three: 95% upper bound about 3/130 = 2.3%, my arithmetic) — [arXiv 2608.27092](https://arxiv.org/abs/2608.27092)
- Adaptive Adversaries reports ASR as a function of rounds (0-1% first round, 7.9-16.8% over 15 rounds) — [arXiv 2607.18063](https://arxiv.org/abs/2607.18063)

### Inferences
- A defensible evidence standard assembled from these practices (my synthesis, not a published standard): report k/n per condition at fixed temperature and model version, Wilson or Clopper-Pearson interval, state whether n is independent fresh sessions, state attacker budget (queries, rounds), and for a vulnerability claim give a reproduction rate over fresh sessions rather than one transcript. With n = 10 and 10/10 successes the Wilson 95% lower bound is about 72%; with 3/3 it is about 44% (my arithmetic).
- Success@N is appropriate for a security claim (attacker only needs one success) but must be disclosed as such; per-attempt ASR is what governs defender expected loss.

### Gaps
- I found no standards-body or peer-reviewed guidance giving a required trial count or minimum success rate for a prompt-injection finding.
- The sources for repeated-trial practice (20 trials, bootstrap B=200) came only through search summaries; original papers not fetched.
- Variance across repeated attempts of the same payload on the same model with the same temperature is not isolated in anything I read in full.

---

## 5. Oracle design: how papers prove an injection succeeded

### Takeaway
The more rigorous benchmarks use deterministic state checks over the environment (AgentDojo) or planted canary secrets with matched clean-vs-poisoned runs; the weaker ones score parsed model output (InjecAgent) or LLM judges. A common outcome ladder is: model complies in text, attempts the tool call, side effect occurs.

### Cited Findings
- AgentDojo: success decided by deterministic security functions over environment state, explicitly not an LLM judge — [arXiv 2406.13352 html](https://arxiv.org/html/2406.13352)
- InjecAgent: success from parsed output showing the tool invocation, with simulated tool results; separate S1 (extract) and S2 (send) stages; invalid outputs excluded in ASR-valid, included in ASR-all — [arXiv 2403.02691 html](https://arxiv.org/html/2403.02691)
- WASP separates partial ("attack partially succeeds in up to 86% of the cases") from end-to-end completion; agents often fail to complete the attacker goal. Models, n and exact definitions not on the abstract page [PP] — [arXiv 2504.18575](https://arxiv.org/abs/2504.18575). A secondary summary gives intermediate 17-86% vs end-to-end 0-17% [PRESS/aggregator] — [alphaxiv WASP](https://www.alphaxiv.org/overview/2504.18575v1)
- The Framing Gap uses a canary secret with mock tools and a matched clean-vs-poisoned metric; oracle definition not on the abstract page — [arXiv 2608.27092](https://arxiv.org/abs/2608.27092)
- Attacker Moves Second warns model-based auto-raters are unreliable and vulnerable to reward hacking — [arXiv 2510.09023 html](https://arxiv.org/html/2510.09023)
- IPI Bench: a manual review of 50 sampled successful attacks per model, "upheld" 271; judging method otherwise not described [VENDOR] — [General Analysis](https://generalanalysis.com/blog/ipi-bench)
- Greshake et al. (2023) give the original impact taxonomy from a security perspective (data theft, worming, information-ecosystem contamination), demonstrated against Bing Chat and code-completion engines; arXiv preprint [PP] — [arXiv 2302.12173](https://arxiv.org/abs/2302.12173)
- Out-of-band confirmation (OAST/DNS callbacks) is standard in web red-teaming; I found no paper in this search that formalises OAST callbacks as the oracle for prompt injection specifically. EchoLeak-class exfiltration (auto-fetched image to attacker-reachable host) is the in-the-wild instance where the attacker-side request log is the proof — [arXiv 2509.10540](https://arxiv.org/abs/2509.10540)

### Inferences
- A three-level outcome taxonomy that the sources support but none states as a standard: L0 compliant-sounding text only; L1 tool call attempted (InjecAgent-level evidence, parsed output); L2 verifiable side effect (state change or attacker-observed callback; AgentDojo-level). For a bug-bounty-grade claim only L2 should count; L1/L0 should be labelled "unconfirmed".
- A canary must be unique per trial, planted only in the privileged context, and observed on an attacker-controlled sink; a clean (no-injection) control run rules out the model emitting the canary unprompted (that is the point of the Framing Gap's matched metric).

### Gaps
- No formal, cross-paper taxonomy of injection outcomes found; the ladder above is my synthesis.
- WASP and Framing Gap oracle definitions not read beyond abstracts.

---

## 6. Lethal trifecta, impact classification, and the jailbreak vs vulnerability line

### Takeaway
The trifecta (Willison, June 2025) and Meta's Rule of Two (Oct 2025) are practitioner frameworks, not peer-reviewed. Bug-bounty programmes have settled on: indirect injection with a concrete security impact is in scope; jailbreaks and direct self-targeted injection are out.

### Cited Findings
- Lethal trifecta: access to private data, exposure to untrusted content, ability to communicate externally; 16 June 2025; Willison also states guardrail vendors' "95% of attacks" is "very much a failing grade" in web security terms [practitioner blog, not research] — [Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
- Meta's Agents Rule of Two (31 Oct 2025): within a session, an agent should have at most two of the three properties and adds "changing state"; per secondary coverage only [VENDOR/PRESS] — [Willison on the Meta post, as listed by search](https://simonwillison.net/2025/nov/2/new-prompt-injection-papers). I did not read Meta's primary post.
- Academic impact taxonomy: Greshake et al. (above) [PP]. Abdelnabi and Bagdasarian recast injection through Contextual Integrity: flows can be misrepresented, norms manipulated, or multiple flows mixed — [arXiv 2605.17634](https://arxiv.org/abs/2605.17634)
- OWASP: jailbreaking "is a form of prompt injection"; direct vs indirect; the page notes terms are often used interchangeably; lists mitigations including least privilege and human approval of high-risk actions [STD, not research] — [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- Bug-bounty line: Google's AI VRP (launched Oct 2025) excludes direct prompt injection, jailbreaks and alignment issues, and includes indirect prompt injection with harm (examples: Google Home lock unlock, summariser forwarding email to an attacker), cross-user persistent HTML injection used for phishing, data/account modification, sensitive data leak, model-parameter exfiltration; top base reward $20,000, up to $30,000 with multipliers; stated rationale: jailbreaks typically affect the user's own session, so user impact is hard to assess [VENDOR via news coverage; official rules page not read] — [SecurityWeek via search results](https://www.securityweek.com/google-offers-up-to-20000-in-new-ai-bug-bounty-program/)
- Attacker Moves Second evaluates "jailbreaks and prompt injections" together as one adaptive-attack problem — [arXiv 2510.09023](https://arxiv.org/abs/2510.09023)

### Inferences
- The operative boundary in programmes is not the technique but the victim and the consequence: injection is a vulnerability when the attacker is a third party who is not the session user and a real boundary (data, account, action) is crossed. A jailbreak harms the same user who typed it or yields only content policy output.
- That aligns with the trifecta as an impact checklist: a finding with all three legs, demonstrated at L2 (Q5), is reportable; one with only a model saying something is not.

### Gaps
- No peer-reviewed treatment of severity scoring (CVSS-style) for injection found beyond Greshake's taxonomy.
- Meta and OpenAI/Anthropic bounty primary pages not read.

---

## 7. In-the-wild indirect injection: EchoLeak and chain analysis

### Takeaway
EchoLeak (CVE-2025-32711, Microsoft 365 Copilot) is the best documented production zero-click chain: one inbound email, classifier evasion, link-redaction bypass, auto-fetched image, and a CSP-allowed Teams proxy as exfiltration path. Each step defeats a distinct control, so the chain illustrates why single-layer evaluation misleads.

### Cited Findings
- Reddy and Gujral, "EchoLeak: The First Real-World Zero-Click Prompt Injection Exploit in a Production LLM System" [PP, no venue on page]: single crafted email gives remote unauthenticated data exfiltration; chain = (1) delivery by email without user interaction, (2) evades Microsoft's XPIA (Cross Prompt Injection Attempt) classifier, (3) reference-style Markdown circumvents link redaction, (4) auto-fetched images carry data out, (5) a Microsoft Teams proxy allowed by CSP is the exfil path, (6) privilege escalation across LLM trust boundaries. Proposed mitigations: prompt partitioning, input/output filtering, provenance-based access control, strict CSP — [arXiv 2509.10540](https://arxiv.org/abs/2509.10540)
- Preconditions as implied by the abstract: attacker can send mail to the victim; Copilot ingests it with access to internal data; CSP permits the Teams proxy. The page gave no further precondition detail — [arXiv 2509.10540](https://arxiv.org/abs/2509.10540)
- CVE-2025-32711 existence is stated in the paper abstract above. I could not fetch the NVD or MSRC records (the pages returned only shell content), so CVSS score, publication date and CWE are unverified here. Aim Labs' original write-up returned HTTP 403.
- Greshake et al. 2023 demonstrated the class against Bing Chat's retrieval, an early primary demonstration — [arXiv 2302.12173](https://arxiv.org/abs/2302.12173)

### Inferences
- Preconditions to record for a finding: ingestion path reaches the model without user action; sensitive context is co-resident in the same prompt (trifecta leg 1); an egress that the platform itself fetches (image, link prefetch, proxy) is allowed by policy (leg 3); and a content classifier is not decisive.
- The chain is a good template for a red-team report: list each control bypassed separately with its own evidence.

### Gaps
- CVSS, dates and Microsoft's advisory text not verified; no peer-reviewed venue for the EchoLeak paper; no other systematically analysed in-the-wild incidents retrieved in this pass.

---

## 8. Agentic browser and computer-use injection: systematic evaluation

### Takeaway
There are systematic benchmarks (WASP, VPI-Bench, StakeBench, TRAP, plus vendor system-card numbers), but reported ASR varies from 0% to ~70% depending on success definition (partial vs end-to-end), attacker (templated vs RL-optimised) and domain; most are preprints and vendor numbers are unauditable.

### Cited Findings
- WASP (Meta FAIR, arXiv 2504.18575) [PP]: web-agent benchmark; attacks partially succeed up to 86% but agents often fail to fully complete attacker goals; code and data public — [arXiv 2504.18575](https://arxiv.org/abs/2504.18575)
- VPI-Bench, ICLR 2026 [PR]: 306 test cases across five platforms, visual prompt injection; system-prompt defenses largely ineffective (search summary) — [arXiv 2506.02456](https://arxiv.org/html/2506.02456v2)
- StakeBench (arXiv 2606.13385) [PP]: indirect injection succeeded 41.67-68.16% across configurations (search summary; models, n not read) — [arXiv 2606.13385](https://arxiv.org/html/2606.13385)
- TRAP (arXiv 2512.23128) [PP]: persuasion-based injection on realistic web clones, six frontier models, susceptible in about 25% of tasks on average (search summary) — [arXiv 2512.23128](https://arxiv.org/pdf/2512.23128v1)
- A 2026 single-author preprint (arXiv 2606.05233, "Domain-Conditioned Safety in Frontier...") reports 0/140 multi-step attack successes against Claude Sonnet 4.6 and GPT-5.4 on a 793-episode browser benchmark, attributes high published rates largely to RL-optimised injection text, and finds the same weights fell to skill injection in a coding benchmark; it also relays vendor figures (Anthropic Sonnet 4.6 system card 1.29% scenario ASR under best-of-N browser injection vs 49.36% for Sonnet 4.5). Those vendor figures are second-hand [PP + VENDOR via secondary] — [alphaxiv 2606.05233](https://www.alphaxiv.org/abs/2606.05233.md)
- A separate press-derived figure (31.5% raw hijack falling to 0.5% with safeguards, attributed to a Claude Opus 4.8 system card) conflicts with the above and could not be verified; treat as unconfirmed [PRESS] — [pulse.bot summary](https://www.pulse.bot/ai/news/anthropics-browser-agent-got-hijacked-315-of-the-time-before-safeguards-engaged-08ce0929-21bd-42f1-ab59-1f78400b4f7f/)
- OpenAI on Atlas (Dec 2025, press): prompt injection "unlikely to ever be fully 'solved'", agent mode expands attack surface; UK NCSC reported saying such attacks "may never be totally mitigated" [PRESS] — [TechCrunch](https://techcrunch.com/2025/12/22/openai-says-ai-browsers-may-always-be-vulnerable-to-prompt-injection-attacks/)

### Inferences
- Rates from different browser benchmarks are not comparable: success definition (intermediate vs end-to-end), attacker (hand template vs optimiser), and per-attempt vs best-of-N all differ. Most should be treated as UNINTERPRETABLE for cross-paper comparison until n and model are checked.

### Gaps
- None of the browser numbers above were read from full text; models, n and CI mostly unknown. No primary vendor system-card pages were fetched.

---

## 9. Negative and contested results

### Takeaway
Three distinct negative claims exist: (a) static evaluations mislead (Attacker Moves Second, AutoDojo, AgentDyn, Zhan et al.); (b) prompt injection may be unsolvable in principle (Abdelnabi and Bagdasarian, 2026; informal argument, not a formal theorem on the abstract page); (c) the opposite worry, that high published rates are inflated by optimised attack text (single-author 2026 preprint).

### Cited Findings
- "AI Agents May Always Fall for Prompt Injections" (Abdelnabi, Bagdasarian; arXiv 2605.17634; 17 May 2026) [PP]: data-instruction separation both misses contextual-manipulation attacks and degrades legitimate behaviour; reframes via Contextual Integrity; states informally: "an adversary can always construct a context under which a blocked flow appears legitimate, or a defender who tightens norms will block genuinely legitimate flows." No formal theorem or assumptions on the abstract page — [arXiv 2605.17634](https://arxiv.org/abs/2605.17634)
- Attacker Moves Second: "empirical evaluations cannot prove that a defense is robust" — [arXiv 2510.09023 html](https://arxiv.org/html/2510.09023)
- AutoDojo and AgentDyn: static benchmarks overestimate defenses; defenses largely trade utility for security — [arXiv 2606.15057](https://arxiv.org/abs/2606.15057), [arXiv 2602.03117](https://arxiv.org/abs/2602.03117)
- Counter-view: 0/140 multi-step successes on frontier models in one browser benchmark and the claim that RL-optimised text inflates literature rates (single-author preprint; domain-conditioned) — [alphaxiv 2606.05233](https://www.alphaxiv.org/abs/2606.05233.md)
- "Prompt Injection as Role Confusion" (ICML) is reported by press as arguing models struggle to distinguish trusted instruction, user request, external data and own reasoning; I only saw a news summary [PRESS] — [ProPakistani via search](https://propakistani.pk/2026/07/30/researchers-say-llms-can-never-be-fully-secure-against-prompt-injection/)
- Hofer, Debenedetti, Tramèr: attacks optimised on small open models do not transfer to GPT-5, a counterpoint to claims that transferable attacks make everything fragile — [arXiv 2606.10525](https://arxiv.org/abs/2606.10525)

### Inferences
- Reading 2605.17634 with 2510.09023: the community position by late 2026 is that vulnerability reduction is by architecture (capability limits, trifecta avoidance) rather than detection, and that any reported robustness number is conditional on attacker budget and benchmark.

### Gaps
- Role Confusion paper itself not located; formal statement in 2605.17634 not read.
- No Hacker-News-level debate or rebuttal papers collected against Attacker Moves Second.

---

## Evidence-standard checklist for a reported injection finding (synthesis, my own; each item traces to a source above)

1. Name the target model/version, temperature, harness, and attacker budget (queries or rounds); without these an ASR is UNINTERPRETABLE (Q2, Q4).
2. Report k/n with a binomial interval; say whether trials are independent fresh sessions; say whether the claim is per-attempt or Success@N (Q4).
3. Include a clean control run (no injection) to show the effect is caused by the payload, plus an attacker-unique canary (Q5).
4. Prove at the strongest outcome level: verified side effect or attacker-side callback, not model text or a parsed tool-call intent (Q5).
5. State the trifecta legs and who the victim is; a third-party attacker crossing a data/action boundary is reportable, a self-inflicted jailbreak is not under current bounty norms (Q6).
6. Break multi-step chains into per-control bypasses (Q7).
7. Do not generalise a static-pool negative result into "defended" (Q2, Q3).
