# Verifying LLM security-agent findings: oracles, PoC replay, false-positive control, LLM-as-judge (state as of 2026-11-13)

Evidence-class tags used below: [PEER] = peer-reviewed venue stated on the paper or venue page; [PRE] = arXiv preprint, no venue stated; [WS] = workshop poster; [VENDOR] = company self-report; [SEC] = I only saw a search-engine summary or a third-party page, not the primary text (treat as unverified). "Read" means I extracted text from the primary PDF/HTML/abstract page.

All three named arXiv ids resolve: 2604.06618 = PoC-Adapt (submitted 2026-04-08, v2 2026-04-09); 2608.12996 = ATOBench (submitted 2026-08-13, v1); 2601.22952 = "Sifting the Noise" (v1 2026-01-30, v3 2026-07-23, ISSTA 2026).

## 1. What does the literature measure about agents hallucinating success (exit codes, status codes, console output, narration)?

### Takeaway
Only one paper I found directly counts how often a cheap success signal is wrong: PoC-Gym (n=338 runs) found about 44% of PoCs that passed an exit-code-plus-printed-marker check never reached the real vulnerable location. PoC-Adapt asserts surface signals are unreliable but does not quantify it, and its headline "25% improvement" is a relative success-rate gain over one baseline (15/100 vs 12/100), not a measured false-positive reduction. ATOBench measures a different thing (target-side deception, not agent fabrication). The wider evidence that agent self-reports are uninformative comes from non-security agent-loop studies.

### Cited Findings
**PoC-Gym (arXiv 2602.04165, Gezgin et al., v1 2026-02-04, v3 2026-09-02) [PRE]**
- Corpus: 20 Java CVEs (CWE-Bench-Java), 338 PoC-generation runs. 116 candidates (34.3%) passed "runtime validation"; 65 (19.2%) passed "post-hoc validation" against ground-truth vulnerable locations; post-hoc-valid PoCs cover 12 of 20 CVEs. Hence 51 of 116 runtime-valid PoCs (about 44%) were not real. — [abs](https://arxiv.org/abs/2602.04165), [html v3](https://arxiv.org/html/2602.04165v3)
- Runtime validation = PoC exits 0, prints a `[VULN]` marker, and its trace reaches the sink of the selected static trace (without trace info: only exit code + marker). Post-hoc validation additionally requires the dynamic trace to hit the ground-truth vulnerable location (`File.java:line` matched against the vulnerable method's line range). — [html v3](https://arxiv.org/html/2602.04165v3)
- Per-configuration CVE counts out of 20, no-trace setting (runtime-valid / post-hoc-valid): Claude Code+Sonnet 4: 17/8; Codex+GPT-5 Medium: 17/9; Codex+gpt-oss-20b: 18/5. Multi-trace: 13/9, 13/8, 5/4. (Extracted by a fetch model from the HTML; the tool's extra "aggregate multi-trace 23.0%/15.5%" line did not reconcile with the table, so I do not use it.) — [html v3](https://arxiv.org/html/2602.04165v3)
- Failure taxonomy of runtime-valid-but-post-hoc-invalid PoCs: hardcoded outcomes, simulated vulnerability logic, "not malicious" (benign API use), force-try (reflection brute force), CVE-prompt construction error, irrelevant selected trace, and bad validation. Fooling signals named: a printed `[VULN]` marker including unconditional success messages, expected artifacts created through benign API calls, fixed outcomes, self-implemented simulations that never reach target code. Per-category counts are only in a figure I could not read. — [html v3](https://arxiv.org/html/2602.04165v3)
- On the 14-CVE overlap with FaultLine: PoC-Gym's strongest configuration post-hoc valid for 8; FaultLine reported success for 5 under its own criterion. — [abs](https://arxiv.org/abs/2602.04165)
- Manual analysis only inspected runtime-valid PoCs that failed post-hoc validation; no annotator count or inter-rater agreement stated. — [html v3](https://arxiv.org/html/2602.04165v3)

**PoC-Adapt (arXiv 2604.06618, Duy et al., 2026-04-08) [PRE]**
- States that "program exit codes, network response statuses, or raw console outputs" are "highly prone to false positives, often resulting from LLM hallucinations where the model incorrectly assumes success". This is a motivating assertion; I found no measurement of that rate and no ablation of the semantic oracle against a surface-signal oracle in the text I read (Table 12 ablates the RL policy, +16.7% relative SR 15.0 to 17.5). — [PDF](https://arxiv.org/pdf/2604.06618)
- The "25%" is: FL-Bench-100 (100 confirmed vulns from CWE-Bench-Java and PrimeVul, 4 CWEs: CWE-22/78/79/94) SR 15/100 vs FaultLine 12/100, "25% relative improvement", under $1 budget, 60 min, max 3 refinement loops. — [PDF](https://arxiv.org/pdf/2604.06618)
- GHSA-Real80 (80 GitHub advisories, 73 repos, 7 languages, mostly 2025): 12/80 reproduced (15%). Planner stage conditional failure 60.76% (48/79); Exploiter failure 12.90%; "Validator filters out 55.56% of candidates, reducing false positives" (denominator not stated in the text I read). — [PDF](https://arxiv.org/pdf/2604.06618)
- Authors' own limitation: the oracle "performs well on high-signal, direct-impact vulnerabilities" (CWE-78 23.1% SR, CWE-79 22.2%, CWE-22 16.7%) but yields 0% on CWE-502 deserialization and 4.3% on Medium severity, and risks "overly conservative filtering and potential false negatives". — [PDF](https://arxiv.org/pdf/2604.06618)
- Validity threats section: temperature 0.0, still residual non-determinism; "multiple independent runs" used without stating how many. — [PDF](https://arxiv.org/pdf/2604.06618)

**ATOBench (arXiv 2608.12996, Chen et al., 2026-08-13) [PRE]**
- Design: five model routes (DeepSeek-V4-Pro, GLM-5.2, Kimi-K2.6, Qwen3.7-Max, GPT-5.5) run through Claude Code 2.1.156 against OWASP Juice Shop 20.1.1 behind a mitmproxy that rewrites selected responses ("Adversarial Target Observation"). 450 episodes = 225 matched Native/ATO pairs = 3 contracts (SQLi proof, Basket ownership/IDOR, JWT reusable artifact) x 5 models x 15 pairs. Budgets: 40 tool calls/2,400 s (SQLi, JWT), 70 calls/3,000 s (Basket). — [PDF](https://arxiv.org/pdf/2608.12996)
- Primary endpoint "grounded verification" G = registered primary evidence AND report closes the finding AND claim is supported by the trace. Pooled Native to ATO: Basket 45.3% to 40.0%; JWT 84.0% to 58.7%; SQLi 44.0% to 0.0% (paired difference -44.0 pp, bootstrap 95% CI [-54.7, -33.3], n=75 pairs). Per-cell n is only 15. — [PDF](https://arxiv.org/pdf/2608.12996)
- Retention given Native capability and ATO contact: Basket 13/21 (61.9%), JWT 38/48 (79.2%), SQLi 0/22 (0%, exact CI [0, 15.4]). — [PDF](https://arxiv.org/pdf/2608.12996)
- "More activity can hide a broken verification chain": under SQLi ATO the median trajectory adds 14 actions (IQR 3.5-31) and 9 repeated actions; 64 of 75 pairs have more actions; 19 of 75 ATO episodes tried an alternate strategy, 0 of 19 recovered proof. Doubling the time budget (18 pairs): closure yes/no/uncertain 15/2/1 Native vs 0/15/3 ATO. — [PDF](https://arxiv.org/pdf/2608.12996)
- Taxonomy per episode: grounded verification / unsupported closure / unreported verification / unresolved verification. One worked SQLi case shows an 85-action episode whose final report labels a percent-wildcard result "verified SQLi" despite unresolved proof (classified unsupported). I did not extract a pooled unsupported-closure rate. JWT: 44 of 45 evidence-positive ATO episodes carried the evidence into a supported report (97.8%). — [PDF](https://arxiv.org/pdf/2608.12996)

**Agent self-report in non-security loops**
- "Progress mirage" (arXiv 2607.25152, Park & Choi, v1 2026-07-27, v2 2026-09-29, preregistered pilot, cs.AI) [PRE]: across 54 cycles the frontier agent claimed improvement every time while 56% of cycles had measured delta of zero or below; self-verdict gate became accept-all and eroded best deployed state by 19%. Checked by a world-state oracle enforced by container/network isolation. — [abs](https://arxiv.org/abs/2607.25152)
- Agreement bias (arXiv 2507.11662, Andrade et al., ICLR 2026) [PEER]: MLLM verifiers of agent trajectories over-validate; tested 13 models and 28 judge designs; persists under test-time scaling. Its exact over-validation rates were not on the abstract page. — [abs](https://arxiv.org/abs/2507.11662)

**Vendor statements [VENDOR]**
- XBOW (Ziegler, 2026-01-15): validation "can't live inside the model"; deterministic checks on observable effects, e.g. whether the server makes an outbound request, timing differences versus known-safe inputs for blind injection; no numbers given. — [XBOW](https://xbow.com/blog/why-llms-hallucinate-vulnerabilities)

### Inferences
- The only measured surface-signal false-positive figure (about 44% in PoC-Gym) comes from Java library PoCs with a trace-based reference; it is not a web-app number and its "ground truth" (trace reaches vulnerable line) is itself a proxy. Treat it as an order of magnitude, not a constant.
- PoC-Adapt's "verification reliability +25%" should not be cited as a false-positive reduction; it is a success-rate delta on n=100 against one baseline, and I found no oracle ablation.
- ATOBench's finding is the mirror image of hallucinated success: deceptive or absent evidence leads to long unproductive activity and, in some episodes, claims the trace does not support. It supports counting evidence-to-report linkage, not action volume.

### Gaps
- No paper found that reports, for web-application exploits, the share of agent-claimed successes that are wrong when judged by HTTP status code or response text alone.
- ATOBench pooled unsupported-closure rate, and the human-expert audit's agreement with the LLM judges, not extracted (human audit is described; its agreement statistic was not found).
- PoC-Adapt: whether any of the 12 verified PoCs were independently confirmed by a human; not found in the text I read.
- Huang et al. (arXiv 2509.14289, failure modes of LLM pentest agents: hallucinated commands, looping) and APT-Agent (arXiv 2605.24949, 84.29% end-to-end exploitation) appeared in search only [SEC]; not opened.

## 2. Oracle design: which oracle types are published, with measured reliability, and what is recommended for web apps?

### Takeaway
No paper I found benchmarks oracle types head-to-head, and no peer-reviewed paper measures OAST/interactsh-style confirmation or formal/property-based oracles for agents. What exists: (a) state-delta oracles (PoC-Adapt, asserted not ablated), (b) patched-vs-unpatched differentials (BountyBench; CyberGym pre/post patch), (c) sanitizer oracles for memory-safety bugs (CyberGym, SEC-bench, ARVO), (d) environment-side graders with attack-goal checks including outbound requests (CVE-Bench), (e) trace-to-ground-truth checks (PoC-Gym). The consistent message across the grounding literature is that the verifier must read a signal that lives outside the model's transcript.

### Cited Findings
**Exit-code / marker / status oracles**
- Measured weak: ~44% of marker+exit-code+trace-valid PoCs were wrong in PoC-Gym (see Q1). — [html v3](https://arxiv.org/html/2602.04165v3) [PRE]

**State-delta / semantic oracle**
- PoC-Adapt "Semantic State Differencing Oracle": an LLM Validator agent profiles structured system state before the PoC (Phase 1), runs it, recaptures the same metrics (Phase 3), computes delta = Analyze(S_post, S_pre), and accepts only if the delta "strictly match[es]" the Exploiter's impact hypothesis H; refinement loop capped at B=3. Claimed to "eliminate" hallucinations, but the comparison is asserted, and the paper itself reports conservatism and false-negative risk, 0% on CWE-502. The Validator is still an LLM judging a diff against another LLM's hypothesis. — [PDF](https://arxiv.org/pdf/2604.06618) [PRE]
- "Progress mirage": a world-state oracle with real-world access was needed; a strong in-band judge reading the full artifact, the diff and verdict history accepted real-world regressions 44% of the time and rejected 38% of real improvements. Where success was verifiable from the artifact itself, the judge's mirage fell to zero. — [abs](https://arxiv.org/abs/2607.25152) [PRE, not security]

**Differential / negative control**
- BountyBench (Stanford): exploit tasks pass only if the verifier succeeds on the current snapshot and fails on the patched snapshot; 25 systems and 40 bug bounties, 9 of OWASP Top 10 [SEC: from the Stanford blog summary]. — [Stanford AI Lab blog](https://ai.stanford.edu/blog/bountybench)
- CyberGym (1,507 vulnerabilities, 188 projects): PoC counts if it triggers a sanitizer crash pre-patch but not post-patch [SEC: from Berkeley RDI/third-party summaries; the arXiv abstract page does not state the judge]. — [RDI blog](https://rdi.berkeley.edu/blog/cybergym/), [arXiv abs](https://arxiv.org/abs/2506.02548)
- XBOW describes timing differentials against known-safe inputs and requires consistent, reproducible timing before reporting; no metrics [VENDOR]. — [XBOW](https://xbow.com/blog/why-llms-hallucinate-vulnerabilities)

**Out-of-band confirmation**
- CVE-Bench (ICML 2025) [PEER]: a grader container monitors the target environment and checks standardized attack goals, including making the web app send a GET request to a prohibited host (an outbound-callback check); application-specific graders added; top agent resolved up to 13%. — [arXiv 2503.17332](https://arxiv.org/abs/2503.17332), [ICML page](https://icml.cc/virtual/2025/poster/46522) [details SEC: via search-result summary]
- XBOW cites "whether a server makes an outbound request" as a deterministic check [VENDOR]. No measured reliability for any OAST/interactsh oracle found.

**Sanitizer oracles**
- SEC-bench (NeurIPS 2025) [PEER]: PoC generation up to 18.0% and patching up to 34.0% success at best; per-instance construction cost $0.87; reproduces vulnerabilities in isolated environments with gold patches. ASan/UBSan as verification stated in a search summary [SEC]. — [arXiv 2506.11791](https://arxiv.org/abs/2506.11791), [NeurIPS](https://proceedings.neurips.cc/paper_files/paper/2025/hash/a9168f1c54e5147027f1e8cf83e1a775-Abstract-Conference.html)
- CyberGym: led to 34 zero-day vulnerabilities and 18 historically incomplete patches (abstract). — [abs](https://arxiv.org/abs/2506.02548) [PRE; a third-party page lists it under ICLR 2026, not verified]
- ARVO (EuroS&P 2026) [PEER]: 6,100+ OSS-Fuzz vulnerabilities, 311 projects; 81% reproduce; located patches 89.4% accurate. Abstract does not describe a determinism test. — [abs](https://arxiv.org/abs/2408.02153)
- No FP rate for sanitizer oracles as agent-PoC judges was reported in anything I read. They only apply to memory-safety classes.

**Refute-or-Promote "mandatory empirical gate"**
- Ten dedicated reviewers unanimously endorsed a non-existent Bleichenbacher padding oracle in OpenSSL's CMS module; a single empirical test killed it. — [arXiv 2604.19049](https://arxiv.org/abs/2604.19049) [PRE, single author]

**Cross-cutting grounding result**
- NeurIPS 2026 workshop poster (Kozman et al.): "the binding constraint on agent verification is the signal the environment can supply, not the model reading it"; when an environment signal existed, judges overrode it on roughly 1 call in 10 and independent differential testing confirmed fewer than 8% of overrides as justified; larger panels did not help where no executable check existed. n=64,800 verification calls, 4 models, 3 domains (not security-specific). — [NeurIPS page](https://neurips.cc/virtual/2026/178251) [WS]

### Inferences
- For web findings, the best-supported pattern is: oracle reads state the agent cannot write (server-side state, canary/OAST receiver, patched-vs-unpatched differential), the LLM only interprets, and an LLM verdict never overrides a failing deterministic signal (the 1-in-10 override result argues for that).
- State-delta and OAST are consistent with the literature's direction but unproven by head-to-head measurement; any claim of a specific reliability figure for them would be invented.
- Differential testing (exploit works on vulnerable build, fails on fixed build) is the only oracle design used by more than one benchmark family (BountyBench, CyberGym), but both are benchmark-time designs that need a patched build, which a live bug-bounty target lacks. Live-target analog is the negative control (same request, benign payload, or authorisation-removed request).

### Gaps
- No peer-reviewed measurement of OAST/interactsh, formal, or property-based oracles for agent findings.
- No head-to-head oracle-type comparison on web apps.
- PoC-Adapt oracle ablation absent; CVE-Genie "CTF Verifier" internals not retrieved (a second fetch of the full paper was blocked by a cyber safeguard on the fetch model).
- BountyBench and CVE-Bench grader details are from search summaries; primary papers not read.

## 3. Automated PoC generation from a description and deterministic replay: success rates and costs

### Takeaway
Regenerating a working PoC from a text description succeeds roughly 15-20% of the time on hard open benchmarks (CyberGym ~20%, SEC-bench 18.0%, PoC-Adapt 15%, CVE-Bench 13%) and up to ~51% on a curated CVE-reproduction pipeline with environment building (CVE-Genie), at about $0.4-$2.8 per CVE. No paper I found measures deterministic replay of a stored agent PoC against a web target; the nearest is ARVO's 81% reproduction of OSS-Fuzz crashes.

### Cited Findings
- CVE-Genie (arXiv 2509.01835, Ullah et al., v1 2025-09-01, v2 2026-02-12) [PRE]: reproduced about 51% (428 of 841) of CVEs published 2024-2025, average $2.77 per CVE. — [abs](https://arxiv.org/abs/2509.01835). Extra figures (pilot 38/60 = 63.3%, median 18 min, $5/45 min cap, o3 reproducing none without the framework) are [SEC] from Emergent Mind/search snippets: [Emergent Mind](https://www.emergentmind.com/topics/cve-genie).
- PoC-Adapt: FL-Bench-100 15/100 (FaultLine 12/100); GHSA-Real80 12/80. Cost on GHSA-Real80 (Gemini-2.5-Pro): successes avg 7.14 min, $0.42, 320.2k tokens; failures 13.87 min, $0.64, 499.2k tokens; all-attempt average $0.61, 12.86 min, 472.4k tokens. DeepSeek-V3: SR 6.25%, $0.07, 3.59 min; Qwen-3: SR 11.25%, $0.13, 15.65 min. Time-to-exploit 16.33 vs 35.92 steps (FaultLine). — [PDF](https://arxiv.org/pdf/2604.06618) [PRE]
- PoC-Gym: post-hoc-valid PoCs for 12 of 20 Java CVEs over 338 runs (19.2% of runs). — [abs](https://arxiv.org/abs/2602.04165) [PRE]
- CyberGym: top combinations ~20%; OpenHands+Claude-Sonnet-4 17.9% [SEC]. Berkeley RDI write-up (benchmark authors' own blog): Claude-Sonnet-4.5 28.9% single run, 66.7% with 30 trials; GPT-5 7.7% at minimal reasoning vs 22.0% at high [SEC]. — [arXiv abs](https://arxiv.org/abs/2506.02548), [RDI blog](https://rdi.berkeley.edu/blog/cybergym/)
- SEC-bench: PoC generation at most 18.0%; construction $0.87/instance. — [abs](https://arxiv.org/abs/2506.11791) [PEER NeurIPS 2025]
- CVE-Bench: top agent framework resolves up to 13% of real web-app CVEs (ICML 2025). — [abs](https://arxiv.org/abs/2503.17332) [PEER]
- ARVO: 81% of 6,100+ OSS-Fuzz vulnerabilities reproduce in the packaged environment; patch location 89.4% accurate (EuroS&P 2026). — [abs](https://arxiv.org/abs/2408.02153) [PEER]
- Environment build is the dominant failure: PoC-Adapt Planner stage fails 60.76% (48/79) of the time on real advisories. — [PDF](https://arxiv.org/pdf/2604.06618)

### Inferences
- The single-run vs 30-trial CyberGym gap (28.9% vs 66.7%, RDI blog) implies that "found in some trial" and "reproducible on demand" are different quantities; the replay step must be a separate measured gate.
- Success rates are benchmark- and harness-specific and cannot be pooled; costs are not comparable (different budgets, models, success definitions).

### Gaps
- No published rate of deterministic replay of a stored LLM-generated PoC (rerun N times, fraction that reproduce) for web targets.
- CVE-Genie verification accuracy/false-positive audit not retrieved.
- PatchEval: search returned nothing; not assessed.

## 4. LLM-as-judge for security: agreement with experts, biases, can it score a security benchmark?

### Takeaway
Agreement ranges widely: kappa about 0.4-0.64 against human specialists for matching vulnerability leads to ground truth (eyeballvul, n=100), but 0.90 for two LLM judges on constrained report-closure rubrics with deterministic evidence underneath (ATOBench, n=450). General-purpose evidence says judges are biased toward their own errors (+11.9 pp approval, workshop result) and over-validate agent trajectories (ICLR 2026). A judge is usable only on narrow rubrics with deterministic evidence and a human audit; nothing supports using it alone on open-ended exploit claims.

### Cited Findings
- MT-Bench / Chatbot Arena (Zheng et al., NeurIPS 2023 D&B) [PEER]: GPT-4 reaches "over 80% agreement" with humans, similar to human-human; documents position, verbosity and self-enhancement biases. Not security. — [abs](https://arxiv.org/abs/2306.05685)
- eyeballvul (arXiv 2407.08708) [PRE; venue not verified]: LLM scorer (Claude 3.5 Sonnet, temp 0.1, 6 few-shot examples) vs three human cybersecurity specialists on 100 random leads: Cohen's kappa 0.64, 0.46, 0.40 (avg 0.50). Human-human kappa 0.59, 0.36, 0.47 (avg 0.48). The scorer rated 6 of 100 positive; disagreements 5 (one LLM-positive, 4 LLM-negative) and 12 (1 LLM-positive, 11 LLM-negative); one human revised one of 5 disagreements after seeing the LLM's answer. Authors name the scorer plus vague CVE descriptions (~30% lack detail) as the main weakness. — [PDF](https://arxiv.org/pdf/2407.08708)
- ATOBench [PRE]: two identity-blinded LLM judges on all 450 reports agreed on 416 (92.4% joint); pre-adjudication agreement 96.0% for report closure (kappa .905), 93.6% for trace support (kappa .904), kappa .747 for "registered finding mentioned"; an adjudicator resolved the other 34; a human cybersecurity expert separately audited all 450 records and the reconciled human record supplies the final labels. The judge never decides whether the exploit worked; that comes from deterministic evidence reconstruction from proxy logs. — [PDF](https://arxiv.org/pdf/2608.12996)
- Kozman et al. (NeurIPS 2026 workshop) [WS]: n=64,800 calls, 4 models x 3 authorship frames x 3 strategies x 3 domains: model approved its own errors 11.9 pp more often when it truly wrote the answer; merely telling it so shifted approval by under 1 pp (effect tied to actual authorship, not belief); errors from stronger generators were harder to catch; no strategy closed the gap; panels did not help. — [page](https://neurips.cc/virtual/2026/178251)
- Quantifying and Mitigating Self-Preference Bias (arXiv 2604.22891) [PRE]: 20 LLMs; advanced capability "often uncorrelated or even negatively correlated" with low self-preference; a cognitive-load-decomposition scoring strategy lowers it 31.5% on average. — [abs](https://arxiv.org/abs/2604.22891)
- Agreement bias (ICLR 2026) [PEER]: verifiers over-validate flawed agent behaviour across 13 models and 28 judge designs; Self-Grounded Verification (priors first, then judge) improves failure detection up to 25 pp and accuracy up to 14 pp. — [abs](https://arxiv.org/abs/2507.11662)
- CIPHER (arXiv 2602.01438) [PRE]: LLM-judge audit of 210 generations kappa 0.772, accuracy 85.65% [SEC: from a search snippet; the abstract page I read does not contain this]. — [abs](https://arxiv.org/abs/2602.01438)
- Sifting the Noise: human ground truth itself is noisy; two raters on n=50 OSS-Fuzz alerts: 86.0% raw agreement (43/50), kappa 0.725; the Vul4J subset labelled by one annotator (n=50, 31 FP / 19 TP, about 20 hours). — [PDF](https://arxiv.org/pdf/2601.22952) [PEER ISSTA 2026]

### Inferences
- eyeballvul's human-human kappa (avg 0.48) is a ceiling: when experts disagree this much, LLM-vs-human kappa of 0.5 is not evidence of a bad judge but of an ambiguous target. ATOBench's 0.90 reflects a rubric tightly bound to source-linked evidence.
- Self-preference results (Kozman, SPB) concern judging text answers; I found no study that measures self-preference specifically for an agent grading its own exploit claim. The mechanism is plausible but unmeasured for security.
- Position and verbosity biases for security judges: only generic MT-Bench evidence; nothing security-specific retrieved.

### Gaps
- No kappa or correlation for an LLM judge deciding "is this exploit real" against human experts with n and corpus.
- Human-vs-LLM-judge agreement inside ATOBench not found.
- SecRespond (arXiv 2607.26791, weighted kappa 0.94, n=60 checkpoints) seen only in a search summary [SEC] and concerns incident response, not finding verification.

## 5. False-positive rates of agent-based triage; multi-agent / adversarial verification gains

### Takeaway
Static-analysis triage is the only area with solid measured rates: agentic FP filtering cut OWASP Benchmark false-positive rate from 98.3% to as low as 6.3%, but suppressed 22.25% of true positives, and results are backbone- and CWE-dependent. Adversarial multi-agent designs report high kill rates (about 79-83%) but those are not false-positive rates against ground truth. All of this is static triage, not exploit verification.

### Cited Findings (all static-analysis triage unless stated) 
**Sifting the Noise (arXiv 2601.22952; ISSTA 2026, PACMSE vol 3, Oct 2026, doi 10.1145/3832100) [PEER]**
- OWASP Benchmark v1.2: 1,325 non-vulnerable and 1,415 vulnerable cases; four SAST tools unioned flag 1,303 of 1,325 non-vulnerable (98.3% baseline FP rate). CodeQL FPR 68.2%, Semgrep 74.8%, Joern 7.2% (recall 8.2%); 36 FP instances flagged by all four tools. — [PDF](https://arxiv.org/pdf/2601.22952)
- Residual FPR after filtering, Claude Sonnet 4: Aider 14.3%, OpenHands 14.9%, SWE-agent 6.3%, vanilla LLM 23.0%. DeepSeek Chat: 13.2% / 15.8% / 13.1% / vanilla 11.2% (vanilla best). GPT-5: 20.3% / 16.3% / 14.1% / vanilla 20.4%. — [PDF](https://arxiv.org/pdf/2601.22952)
- True-positive retention, SWE-agent+Sonnet 4, 1,411 completed runs of 1,415 vulnerable cases: 314 true vulnerabilities labelled FP, retention 77.7%, miss rate 22.25%. Miss rate by CWE: 0.41% (CWE-79), 1.10% (CWE-89), 2.38% (CWE-78), but 77.17% (CWE-327 weak crypto), 84.50% (CWE-328 weak hash), 77.11% (CWE-501), 50.00% (CWE-614). — [PDF](https://arxiv.org/pdf/2601.22952)
- Real-world Java (Vul4J, 79 project versions, 6.79M LOC, 3,426 CodeQL alerts; random sample n=50: 31 FP / 19 TP, initial precision 62%, single annotator): best configuration identifies up to 93.3% of FPs. — [PDF](https://arxiv.org/pdf/2601.22952)
- Post-cutoff OSS-Fuzz C/C++ (n=50: 22 FP / 28 TP; two raters kappa 0.725): SWE-agent+Sonnet 4 identifies 95.5% of FPs at 95.5% precision vs vanilla 36.4%. Ablations: no cross-file navigation accuracy 96.0% to 44.0%, F1 95.5% to 62.5%; no multi-turn F1 56.3%; no tool verification F1 88.9%; LLM4SA-style prompt 77.3% FP recall, F1 70.8%; context-augmented prompt 54.5% recall, F1 66.7%. — [PDF](https://arxiv.org/pdf/2601.22952)
- Contamination probe: filename-only prediction on OWASP at chance (Claude 51.6%, GPT-5 51.0%, DeepSeek 49.8%). — [PDF](https://arxiv.org/pdf/2601.22952)
- Cost "varies widely across frameworks" (abstract); the table figures were not extracted. — [abs](https://arxiv.org/abs/2601.22952)

**Refute-or-Promote (arXiv 2604.19049, Agarwal, 2026-04-21) [PRE, single author]**
- 31-day campaign, 7 targets (security libraries, ISO C++ standard, compilers): about 79% of 171 candidates killed before disclosure; prospective consolidated-protocol subset (lcms2, wolfSSL; n=30) 83%. Outcomes: 4 CVEs (3 public, 1 embargoed) plus other merged fixes; "no vulnerability was discovered autonomously". Judged by external acceptance, not a benchmark; kill rate is not a ground-truth FP rate. — [abs](https://arxiv.org/abs/2604.19049)

**Others, abstract-level only [SEC]**
- Heterogeneous 3+1 multi-agent design with a local adversarial verifier (arXiv 2604.21282): verifier improves precision but FP rate on benign code "remains substantial"; evaluation on real datasets left to future work. — [PDF](https://arxiv.org/pdf/2604.21282)
- VulAgent (arXiv 2509.11523, ACL Findings 2026) hypothesis-validation multi-agent: reports fewer false positives across backbones; numbers not retrieved. — [PDF](https://arxiv.org/pdf/2509.11523)
- eyeballvul (LLM vulnerability detection in the wild, not triage): best precision 19.6% (80.4% of reported vulnerabilities false positives), best recall 14.1%, best F1 14.1% (Claude 3 Opus); 4.1 to higher FP per TP across models; at $100/h triage time FP cost dominates. — [PDF](https://arxiv.org/pdf/2407.08708)

**Human base rate and vendor claims**
- curl (primary, Stenberg 2026-01-26): confirmed-vulnerability rate "north of 15%" before 2025, below 5% from 2025; 87 confirmed vulnerabilities and >$100,000 paid; bounty ended 2026-01-31; AI slop count not given. — [daniel.haxx.se](https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/)
- Ethiack Verifier (2025-08-07) [VENDOR]: hackbot FP "below 1%" on command injection and path traversal, 0.0% on path traversal, on OWASP Benchmark; no n, no independent replication; the Verifier-specific FP number is not given. — [Ethiack](https://ethiack.com/news/product/introducing-verifier)

### Inferences
- The OWASP Benchmark is synthetic servlets; FP-reduction numbers there overstate real-world performance. The OSS-Fuzz and Vul4J subsets have n=50 each, so confidence intervals are wide (e.g., 21/22 has an interval spanning roughly 77-100%).
- Reduction in FP and increase in missed true positives are the same dial; the 22.25% suppression figure shows that any verification layer must report both.
- "Kill rate" numbers (79%, 83%) are rejections of candidates, not measured precision.

### Gaps
- No measured FP rate for agent-claimed exploits on live web applications with independent human re-verification.
- No numbers retrieved for VulAgent, the 3+1 architecture, MultiVer (arXiv 2602.17875) or the ICPC '26 exploit-validation paper (arXiv 2604.05130); search summary only.

## 6. Stochasticity: k repeated trials for probabilistic findings; bug-bounty reproducibility bars

### Takeaway
I found no published or proposed k threshold for confirming a probabilistic security finding, and no bug-bounty programme text requiring k trials. The reliability literature gives the framework (pass^k vs pass@k) but nothing security-specific. Evidence that single runs mislead: pass@10 78% vs all-10 36% in a computer-use agent study; CyberGym 28.9% single run vs 66.7% at 30 trials.

### Cited Findings
- pass^k (probability of succeeding on all k runs) introduced by tau-bench as a reliability metric; in a computer-use agent study Pass@10 reached 78% while success on all 10 attempts was 36% [SEC: search summary]. — [arXiv 2604.17849](https://arxiv.org/pdf/2604.17849)
- Repeated agent runs share latent conditions (prompt template, cache state, task difficulty), so correlation makes pass^k exceed the independent estimate (p^k) [SEC: search summary; paper not identified with certainty]. — [search listing](https://arxiv.org/pdf/2604.24579)
- PoC-Adapt fixes temperature at 0.0 and uses "multiple independent runs" but acknowledges residual stochasticity and API-level non-determinism; no k stated. — [PDF](https://arxiv.org/pdf/2604.06618)
- CyberGym single run vs 30 trials (above) [SEC]. — [RDI blog](https://rdi.berkeley.edu/blog/cybergym/)
- ATOBench doubling the time budget (18 pairs) did not restore closure; it controls for budget but is not a repeated-trial reliability study (15 pairs per cell). — [PDF](https://arxiv.org/pdf/2608.12996)
- XBOW reports a SQLi hypothesis only after timing behaviour was "consistent and reproducible"; no k given [VENDOR]. — [XBOW](https://xbow.com/blog/why-llms-hallucinate-vulnerabilities)
- Bug-bounty side: curl's own post states reasons for ending the bounty (slop volume, bad-faith reports) and contains no PoC or reproducibility requirement. — [daniel.haxx.se](https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/). A Penligent vendor blog (secondary) says GitHub updated its bounty standards on 2026-05-15 to require validated output, a demonstrated security-boundary crossing and concrete impact, and ends its evidence ladder at independent reproducibility; I could not confirm this against GitHub or HackerOne primary text [SEC, weak source]. — [Penligent](https://www.penligent.ai/hackinglabs/bug-bounty-after-gpt-5-6/)

### Inferences
- A defensible rule from the metrics literature, not from a security paper: separate "exploit-found-at-least-once" (pass@k) from "exploit replays deterministically against a fresh target" (all-k). Any k chosen (for example 3 or 5) would be a design decision, not a published threshold.
- If the oracle is deterministic and state-based, the finding is a property of the target, not of the model, so repeated model trials add less than repeated replay of the stored PoC against reset targets.

### Gaps
- No bug-bounty programme text (HackerOne, Bugcrowd, GitHub, Google VRP) retrieved that states a reproducibility bar for AI-assisted reports; HackerOne policy page not found.
- No security paper proposing k repeated trials as a verification rule.
- Primary tau-bench paper not opened.

## 7. Negative results: verification layers that did not help or introduced errors

### Takeaway
Several results cut against "add a verifier". LLM verifiers over-validate, approve their own errors, override correct environment signals, filter out real vulnerabilities, and unanimous reviewers confirmed a non-existent flaw. The only reliable corrective reported is an empirical check outside the model.

### Cited Findings
- Verification layer suppressed real findings: SWE-agent+Sonnet 4 mislabelled 314 of 1,411 true vulnerabilities (22.25%) as FPs; miss rates 77-85% for CWE-327/328/501. — [PDF](https://arxiv.org/pdf/2601.22952) [PEER]
- Agents did not beat vanilla prompting for DeepSeek Chat on OWASP (vanilla FPR 11.2% vs 13.1-15.8% for agents); gains for weaker backbones "limited or inconsistent". — [PDF](https://arxiv.org/pdf/2601.22952) [PEER]
- Judges overrode a correct environment signal on about 1 in 10 calls; <8% of those overrides justified; larger judge panels failed together. — [NeurIPS page](https://neurips.cc/virtual/2026/178251) [WS]
- Stronger in-band judge did not close the self-evaluation gap (preregistered hypothesis rejected): accepted real regressions 44% of the time, rejected 38% of real improvements. — [abs](https://arxiv.org/abs/2607.25152) [PRE]
- Agreement bias persists under test-time scaling and across 28 judge designs. — [abs](https://arxiv.org/abs/2507.11662) [PEER]
- Ten reviewers unanimously endorsed a non-existent OpenSSL CMS Bleichenbacher padding oracle; "adversarial framing alone is insufficient" (search-summary paraphrase; the abstract confirms the unanimous endorsement and the single killing empirical test). — [abs](https://arxiv.org/abs/2604.19049) [PRE]
- Oracle too strict: PoC-Adapt's validator rejects 55.56% of candidates, 0% SR on CWE-502, Medium severity 4.3% (by the authors' admission possible false negatives). — [PDF](https://arxiv.org/pdf/2604.06618) [PRE]
- Even a "post-hoc" validation can be a proxy: PoC-Gym's ground truth is a dynamic trace reaching the vulnerable location, not proof of exploitation. — [html v3](https://arxiv.org/html/2602.04165v3) [PRE]
- Stronger generators' errors were harder to catch; no verification strategy narrowed this. — [NeurIPS page](https://neurips.cc/virtual/2026/178251) [WS]

### Inferences
- Reduction of FPs by an LLM layer without a ground-truth-backed recall check is not a safe metric; report TP retention alongside FP reduction.
- Grounded evidence beats extra judges: the strongest consistent pattern across Refute-or-Promote, Kozman et al. and the progress-mirage study.

### Gaps
- No security-specific study of self-preference when the generating agent is also the verifier of its own exploit claim.
- Whether adversarial critics reduce or add false negatives on exploit claims has no measurement beyond the static-triage TP-retention result.

## Not verified / could not resolve (consolidated)
- All three named arXiv ids resolve and were read in full text via local PDF extraction (PoC-Adapt v2, ATOBench v1, Sifting v3).
- Seen only as search-summary text, not opened: PatchEval (no results), Huang et al. 2509.14289, APT-Agent 2605.24949, Automation-Exploit 2604.22427, 2604.21282, VulAgent 2509.11523, MultiVer 2602.17875, ICPC '26 paper 2604.05130, SecRespond 2607.26791, TAU-bench primary, 2604.17849's exact numbers, CyberGym sanitizer definition and ICLR venue, BountyBench/CVE-Bench grader details, GitHub 2026-05-15 bounty standards, HackerOne policy.
- eyeballvul peer-review venue not verified. Ethiack n not stated. CVE-Genie full-paper verifier details not retrieved.
- Date discrepancy for curl closure: primary post says bounty ends 2026-01-31; some secondary sources say 2026-02-01.
