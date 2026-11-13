# Designing and reporting a small-n paired comparison of two LLM-agent configurations on security tasks (state of the literature, 13 Nov 2026)

Scope: two arms (A, B) run on the same N = 26-40 challenges, K repeats per cell, binary success per run. All "Computed" numbers below were produced in this session with plain-Python exact enumeration (no scipy); scripts were not saved to the repo. Formulas I wrote from memory are flagged "from memory" and are not backed by a URL; treat them as needing a check against the primary source before they go in a paper. Source reliability notes are inline.

---

## 1. Paired design: McNemar, its variants, and what the discordant count means for power

### Takeaway
The analysis unit is the challenge, and only the discordant challenges (A solved / B failed, and vice versa) carry information. With N = 26-40 and the discordance one realistically sees (about 20-40% of challenges), only very large effects (net 7-9 challenges in favour of one arm, roughly 25-30 percentage points) are detectable at 80% power. Anything smaller must be reported as an estimate with an interval, not as a significant or null result. The exact conditional McNemar test is conservative; mid-p is the better-performing default, but the choice must be fixed before looking because it can flip the verdict at these sizes.

### Cited Findings
- Fagerland, Lydersen, Laake (2013) compared the asymptotic McNemar test (with and without continuity correction), exact conditional, mid-p, and exact unconditional. Mid-p performed well and almost as well as the much more complex exact unconditional test, and did not violate the nominal level in any of 9,595 scenarios (not guaranteed to preserve it). The exact conditional test and the continuity-corrected asymptotic test performed poorly (conservative) in all considered scenarios. — [Fagerland et al., BMC Med Res Methodol 2013](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC3716987/) (via search summary, abstract level; full text not read)
- Miller (Anthropic, 2024), "Adding Error Bars to Evals": run inference on question-level paired differences, not on the two summary scores; paired differences are a "free" variance reduction when the models' conditional means per question are correlated; use clustered SEs when questions come in related groups; use power analysis. Sample size for a paired analysis with K resamples per arm (Eq. 9): n = (z_{alpha/2} + z_beta)^2 (omega^2 + sigma_A^2/K_A + sigma_B^2/K_B) / delta^2, where omega^2 is the variance of the question-level difference in conditional means and sigma^2 the mean within-question (run-to-run) variance. Example in the paper: omega^2 = 1/9, delta = 0.03, 80% power, alpha 0.05 gives n of about 969 questions. Also: pooled SE across all K*N answers is inconsistent because answers to the same question are not independent. — [Miller 2024, arXiv 2411.00640](https://arxiv.org/abs/2411.00640) (read from the PDF text in this session)
- Bowyer, Aitchison, Ivanova (ICML 2025 position paper): CLT-based error bars are too narrow at small N; in the paired setting, simulations show all non-Bayesian methods "severely underperform" in coverage at small N; they recommend paired Bayesian intervals (unpaired Bayes as an easier alternative) for the difference or odds ratio, and Wilson or Bayesian intervals for a single accuracy. Simulated N values included 3, 10, 30, 100. — [Bowyer et al. 2025, arXiv 2503.01747](https://arxiv.org/abs/2503.01747) (PDF text read in this session)
- Security-domain precedent: a 2026 study of LLM security-tool orchestration ran 774 trials over 86 picoCTF challenges, used paired McNemar tests (p < 0.001) for before/after tool fixes, and itself lists as limitations that the fixes were tuned on the same challenges used for evaluation and that the benchmark is single. — [Gerard et al., arXiv 2607.02873](https://arxiv.org/abs/2607.02873)

### Inferences
(Computed here unless stated; all use two-sided alpha = 0.05; psi = p10 + p01 is the discordant-pair probability, delta = p10 - p01 the true difference in success rates; b, c = observed discordant counts.)

**Test and conditions.**
- Conditional on n = b + c discordant pairs, under H0 b ~ Binomial(n, 0.5). Exact: p = 2 * P(X <= min(b,c)), capped at 1. Mid-p: p = 2 * [P(X < min(b,c)) + 0.5 * P(X = min(b,c))]. Asymptotic: (b - c)^2 / (b + c) ~ chi-square(1). (Original test: McNemar 1947, Psychometrika 12:153-157, from memory, not re-verified.)
- Conditions: (i) one binary outcome per pair, (ii) pairs independent of each other, (iii) the same units under both arms, (iv) the test addresses the marginal difference of the two success rates, not agreement.
- Conditions (i)-(ii) are what K > 1 repeats violate. Do not pool the K runs and run McNemar on N*K pairs; that inflates n and manufactures significance (Miller says the pooled SE is inconsistent). Valid options: (a) collapse each challenge to one binary per arm (e.g. majority or pass@K; the estimand then changes, declare it); (b) per-challenge difference d_i = (successes_A - successes_B)/K, then a paired permutation or sign-flip test or paired bootstrap resampling challenges (not runs); (c) mixed-effects logistic regression, success ~ arm + (1 | challenge) (+ (arm | challenge) if feasible); or (d) the paired Bayesian model of Bowyer et al. Challenges from the same family or application should be treated as clusters (Miller's clustered SE).
- Fixed vs random challenges: if the claim is only "on these 30 challenges", the only randomness is run-to-run, and generalization to other targets is an argument, not a statistic. If the claim is about a population of challenges, the 30 are a sample and omega^2 enters the variance. Say which.

**Discordant pairs needed (exact conditional, two-sided 0.05).** Smallest majority m out of n discordant giving p < 0.05:

| n discordant | min split | p |
|---|---|---|
| 5 | impossible (5-0 gives 0.0625) | - |
| 6 | 6-0 | 0.031 |
| 7 | 7-0 | 0.016 |
| 8 | 8-0 | 0.0078 |
| 9 | 8-1 | 0.039 |
| 10 | 9-1 | 0.021 |
| 12 | 10-2 | 0.039 |
| 14 | 12-2 | 0.013 |
| 16 | 13-3 | 0.021 |
| 20 | 15-5 | 0.041 |
| 25 | 18-7 | 0.043 |

- Rule of thumb: at least 6 discordant pairs, all in one direction, before exact McNemar can reject at all; with 9-12 discordant, a split of at most 1-2 on the minority side. If the observed discordant count is below 6, the test has no power by construction; report the counts and the interval, and say the design could not have detected anything.
- With an unlucky-but-realistic outcome such as b = 9, c = 2 (n = 11): exact p = 0.065, mid-p = 0.039. The verdict flips on test choice. Pre-specify one.

**Power at N = 26-40 (exact conditional test, enumerating over the binomial number of discordant pairs).** Minimum true delta with at least 80% power:

| N | psi = 0.30 | psi = 0.40 | psi = 0.50 | psi <= 0.20 |
|---|---|---|---|---|
| 26 | 0.295 | 0.345 | 0.39 | never reaches 80% |
| 30 | 0.275 | 0.325 | 0.365 | never reaches 80% |
| 40 | 0.245 | 0.285 | 0.32 | never reaches 80% |

- "Never reaches 80%" means even delta = psi (all discordant pairs favour one arm) leaves power under 80%, because the expected number of discordant pairs (N*psi = 5-8) is too small.
- Same thing as power at fixed effect: N = 30, psi = 0.3, delta = 0.2 (p10 = 0.25, p01 = 0.05): power 0.40 exact, 0.52 mid-p. N = 40: 0.57 exact, 0.66 mid-p. N = 26: 0.33 exact. N needed for 80% at psi = 0.3, delta = 0.2: about 60 (exact test, power 0.797 at N = 60), 56 per Connor's approximation (below).
- Mid-p minimum delta at psi = 0.3: 0.275 (N = 26), 0.26 (N = 30), 0.23 (N = 40); actual type I error of mid-p at N = 30 is 0.040, of exact 0.021 (computed), i.e. exact wastes about half the nominal alpha.
- Closed-form sample size (normal approximation, Connor 1987 Biometrics 43:207-211, formula from memory, cross-checked against the enumeration above): N = [z_{a/2} sqrt(psi) + z_b sqrt(psi - delta^2)]^2 / delta^2. Example psi = 0.3, delta = 0.2: (1.96*0.548 + 0.842*0.469)^2 / 0.04 = 56.4. psi = 0.3, delta = 0.1: 233. psi = 0.4, delta = 0.2: 76.
- Equivalent in discordant pairs only: n_disc = [z_{a/2}*0.5 + z_b sqrt(pi(1-pi))]^2 / (pi - 0.5)^2 with pi = p10/psi (proportion of discordants favouring A). pi = 0.8: about 19 discordant; pi = 0.75: 29; pi = 0.7: 47; pi = 0.9: 10. In words: a 75/25 split needs about 29 discordant challenges, which you cannot get from 30-40 challenges unless almost half are discordant.
- Miller Eq. 9 version with K repeats (normal approximation, optimistic at this N per Bowyer), MDE = 2.80 * sqrt((omega^2 + 2 sigma^2/K)/n), with illustrative sigma^2 = 0.10 per arm:

| N | omega | K=1 | K=3 | K=5 | K=10 |
|---|---|---|---|---|---|
| 30 | 0.25 | 0.26 | 0.18 | 0.16 | 0.15 |
| 30 | 0.33 | 0.285 | 0.22 | 0.20 | 0.185 |
| 40 | 0.25 | 0.23 | 0.16 | 0.14 | 0.13 |
| 26 | 0.33 | 0.31 | 0.23 | 0.21 | 0.20 |

  Repeats shrink only the within-challenge term; the omega floor (difference in true per-challenge solve probabilities) does not shrink with K. Going from K=3 to K=10 buys roughly 3 percentage points of MDE at N = 30. More challenges beat more repeats.
- Practical reading: a single developer at N = 30 can detect a net swing of about 8-9 challenges (roughly 27-30 points) with 80% power; a 10-point difference needs several hundred paired challenges (Connor, psi = 0.3: 233). Say this in the paper: "the study was powered only for differences of at least X; smaller differences are reported as estimates."
- Two-sided vs one-sided: a pre-registered directional hypothesis ("B does not do worse") halves p-values but is contested for comparing configurations; reviewers usually expect two-sided.
- Report effect as a paired difference with CI (Section 2) and the 2x2 table (both / A only / B only / neither), not a p-value alone.

### Gaps
- I could not read Fagerland et al. full text, so the exact simulation scenarios (psi, N ranges) are not verified; the summary comes from the abstract and search summary.
- McNemar 1947 and Connor 1987 were not retrieved this session; the Connor formula is from memory and was only cross-checked numerically.
- No source found that gives psi (discordance rate) for LLM security agents. The 0.2-0.5 range is my assumption; measure psi from a pilot and recompute.

---

## 2. Confidence intervals for proportions at small n

### Takeaway
Use the Wilson score interval as the default for per-arm success rates (recommended by Brown, Cai, DasGupta for n <= 40 and confirmed in LLM-eval simulations), report Clopper-Pearson only where guaranteed coverage is demanded, and do not use Wald/CLT intervals. For the paired difference use a method built for paired data (Newcombe paired score interval, or the paired Bayesian/bootstrap-over-challenges alternative), not two independent Wilson intervals subtracted.

### Cited Findings
- Brown, Cai, DasGupta (2001, Statistical Science 16(2)): for n <= 40 use the Wilson or the equal-tailed Jeffreys prior interval; for larger n Wilson, Jeffreys and Agresti-Coull are similar, and Agresti-Coull is suggested; the Wald interval is in near-universal use despite poor behaviour; the score interval originates with Wilson (1927). — [Euclid](https://projecteuclid.org/euclid.ss/1009213286); [search summary](https://asaip.psu.edu/?p=677)
- Agresti and Coull (1998, American Statistician 52:119-126): the score (Wilson) interval has coverage near nominal even at small n, "exact" Clopper-Pearson intervals are conservative (over-covering) because of discreteness, Wald under-covers; the adjusted Wald (add 2 successes and 2 failures at 95%) mimics the score interval. — [Agresti & Coull PDF](https://users.stat.ufl.edu/~aa/articles/agresti_coull_1998.pdf) (via search summary)
- Bowyer et al. 2025 evaluated CLT, Wilson, Clopper-Pearson, bootstrap and Bayesian intervals on IID Bernoulli data: only the Bayesian credible interval and Wilson achieve near-nominal coverage at small N; CLT interval collapses to zero width when the observed accuracy is 0 or 1 and can leave [0,1]; they describe the Bayesian interval as a shrunk Clopper-Pearson that mitigates its over-coverage, and recommend Wilson (or Bayesian). — [arXiv 2503.01747](https://arxiv.org/abs/2503.01747)
- Newcombe (1998, Stat Med 17:2635-2650): existing paired-difference intervals (asymptotic Wald, conditional "exact") perform inadequately (Wald can leave the valid range; exact conditional can be effectively one-sided); he compared 10 methods; later software recommends the continuity-corrected variant for the paired case. — [Newcombe 1998 PDF](https://www.site.uottawa.ca/~nat/Courses/csi5388/Newcombe.1998.pdf) (abstract-level via search summary; the method-selection text was not read)
- Miller 2024 reports the paired difference with a CI and shows that treating paired data as unpaired loses power; for binary scores the `errorbars` package output pairs the paired SE with a McNemar exact test as a cross-check. — [Miller 2024](https://arxiv.org/abs/2411.00640); [errorbars on PyPI](https://pypi.org/project/errorbars/)

### Inferences
Computed 95% intervals (Wilson / Clopper-Pearson / Agresti-Coull / Wald):

| x/n | Wilson | CP | AC | Wald |
|---|---|---|---|---|
| 0/26 | 0.000-0.129 | 0.000-0.132 | 0-0.152 | 0-0 (degenerate) |
| 26/26 | 0.871-1 | 0.868-1 | 0.848-1 | degenerate |
| 1/26 | 0.007-0.189 | 0.001-0.196 | 0-0.204 | 0-0.112 |
| 3/26 | 0.040-0.290 | 0.024-0.302 | 0.032-0.298 | 0-0.238 |
| 0/40 | 0-0.088 | 0-0.088 | 0-0.104 | degenerate |
| 2/40 | 0.014-0.165 | 0.006-0.169 | 0.005-0.174 | 0-0.118 |
| 18/30 | 0.423-0.754 | 0.406-0.773 | 0.423-0.754 | 0.425-0.775 |

- Near the boundaries: Wald is degenerate at 0/N and N/N and badly low for 1-3 successes; Agresti-Coull as implemented here is slightly more conservative than Wilson at the boundary (0.152 vs 0.129 at 0/26) and can exceed the true bounds; Wilson never leaves [0,1] and has nonzero width at 0/N. Clopper-Pearson is only about 0.3 points wider than Wilson at the boundary but about 2 points wider mid-range (18/30: 0.406-0.773), i.e. its over-coverage costs width where you need it.
- At the boundary, Wilson at 0/n gives an upper bound near 3.84/(n + 3.84); this is the Wilson analogue of the "rule of three" (3/n); both say 0/26 does not exclude a rate around 12-13%.
- Contested: guaranteed-coverage camp (Clopper-Pearson, "never claim less uncertainty than nominal") versus accuracy camp (Wilson/Agresti-Coull, "exact" is needlessly conservative). Both are citable; pick Wilson and state CP as sensitivity if a reviewer asks for guaranteed coverage. Bayesian intervals (Beta(1,1) or Jeffreys prior) are a third, defensible option and are what Bowyer et al. promote; state the prior.
- Paired difference worked example (N = 30; A solves 18, B solves 11; both = 9, A-only = 9, B-only = 2, neither = 10): difference = +0.233. My implementation of the Newcombe paired score interval (formula from memory; verify with a package such as R `ratesci::pairbinci` before publishing): 0.019 to 0.416. Subtracting two independent Wilson intervals (ignores pairing) gives -0.018 to 0.447, i.e. wider and including zero. Exact McNemar p = 0.065, mid-p p = 0.039. Here the paired CI barely excludes 0 while the exact test does not: report the 2x2 table, the paired CI, and the pre-registered test, and describe the result as "suggestive, compatible with effects from near 0 to about 40 points", not as significant or not.
- Intervals on pass rates over K repeats at the challenge level are tiny-n binomials: 5/5 gives Wilson 0.57-1.0, 0/5 gives 0-0.43. Five repeats cannot establish "reliably solves"; they only separate p near 0 from p near 1.

### Gaps
- I did not retrieve Wilson 1927 or Clopper-Pearson 1934 (cited via Bowyer et al. and Brown et al.). The Newcombe method I implemented was re-derived from memory; no software cross-check was run (scipy and R unavailable in the sandbox).
- The exact method-ranking in Newcombe 1998 (which of his 10 methods he finally recommends) was not read; the claim that the continuity-corrected variant is "recommended" comes from a package manual snippet.

---

## 3. Repeats per cell and run-to-run variance

### Takeaway
Run-to-run variance in agentic evaluation is substantial and does not vanish at temperature 0: published single-run pass@1 on SWE-bench Verified varies 2.2-6.0 points by which run is picked; single-model 100-run pentest studies show wide spreads. Repeats reduce within-challenge noise but cannot rescue a small challenge set; K = 3-5 per cell is a pragmatic floor and K beyond about 5-10 gives diminishing returns at N = 30.

### Cited Findings
- Bjarnason, Silva, Monperrus (2026), "On Randomness in Agentic Evals": 60,000 trajectories on SWE-Bench-Verified (3 models, 2 scaffolds, 10 independent runs per configuration); single-run pass@1 varied by 2.2-6.0 percentage points depending on which run was chosen; SD above 1.5 points even at temperature 0 (attributed to inference-engine and environment nondeterminism); gains of 2-3 points may be evaluation noise; up to 24.9 points gap between best-case and worst-case pass@k; trajectories diverge within the first few percent of tokens; recommendations: multiple independent runs per task, power analysis to set the number of runs, report pass@k and pass^k with k > 1. — [arXiv 2602.07150](https://arxiv.org/abs/2602.07150) (abstract-level; the paper's own power calculation was not retrieved)
- Atil et al. (2024-25), "Non-Determinism of 'Deterministic' LLM Settings": 5 models, 8 BBH/MMLU tasks, 10 runs, temperature 0, top-p 1, fixed seed: accuracy varied up to about 15% across runs on some tasks, best-to-worst gap up to about 70%, no model consistently repeatable across tasks; accuracy distributions not normal; longer outputs less stable; locally served Llama-3-8B without serving optimizations was deterministic (authors suggest batching or prefix caching, speculative for hosted models); advice: report max-min range over multiple runs plus CIs. Note: these are single-turn tasks, not agentic. — [arXiv 2408.04667v5](https://arxiv.org/html/2408.04667v5)
- Erdem (2026), single-author preprint: 400 autonomous pentest runs (100 per model, 4 models) against one fixed honeypot with prompt and orchestrator constant; full exploitation in 85/100 (Gemini 2.5 Flash-Lite), 61 (Claude Sonnet 4), 56 (GPT-4o-mini), 25 (qwen2.5-coder:14b); 39 Claude runs were truncated by upstream API overload (HTTP 529) not refusals, an error the author corrected from an earlier draft. — [arXiv 2605.30096](https://arxiv.org/abs/2605.30096) (abstract only; test names for the p < 0.001 claim not stated in the abstract; one target, one author, confounded by outages, so do not generalize)
- Gerard et al. (2026): a 60-run sub-study found single-run verdicts largely reproducible (17 of 20 challenge-configurations unanimous), while client choice for a fixed model produced a 2.1x gap. — [arXiv 2607.02873](https://arxiv.org/abs/2607.02873)
- Anthropic engineering (Feb 2026): resource limits alone moved Terminal-Bench 2.0 scores by 6 points (p < 0.01) between strictest and uncapped, infra errors fell from 5.8% to 2.1% to 0.5% with more headroom; leaderboard gaps under 3 points "deserve skepticism" until configuration is documented and matched; run evals at multiple times and days. — [Anthropic](https://www.anthropic.com/engineering/infrastructure-noise)
- Miller: resampling each question K times reduces the within-question variance term by 1/K; in his uniform-difficulty binary example total variance falls by 1/3 (K=2), 1/2 (K=4), 5/9 (K=6), asymptote 2/3. — [arXiv 2411.00640](https://arxiv.org/abs/2411.00640)
- Klees et al. (CCS 2018) for fuzzing, the closest security-tool precedent: multiple trials per configuration (the paper's guidance is at least 30 trials for the fuzzer setting, per the search summary), non-parametric tests (Mann-Whitney U) and the Vargha-Delaney A12 effect size, following Arcuri and Briand; a 2024 SoK found that with only 3 runs the Mann-Whitney test cannot reject at alpha 0.05 at all. — [Klees et al., arXiv 1808.09700](https://arxiv.org/pdf/1808.09700); [SoK, arXiv 2405.10220](https://arxiv.org/pdf/2405.10220) (summaries via search; page-level claims not verified)

### Inferences
- Source of the noise at your scale (computed): a single run's success count has variance sum_i p_i(1-p_i) over challenges. If 8 of 30 challenges are "flaky" with p = 0.5 and the rest deterministic, SD of the run's score = 1.41 challenges = 4.7 points; with 4 flaky it is 3.3 points; N = 40 with 10 flaky: 4.0 points; N = 26 with 6 flaky: 4.7 points. So a single-run difference of two arms that differ by 1-3 challenges (3-10 points) is entirely compatible with identical configurations. This is the same order as the 2.2-6.0 point range Bjarnason reports at N = 500, but at N = 30 each challenge is 3.3 points.
- How many repeats are "enough" to attribute a difference to the configuration: no published rule exists that I could find. The defensible approach is Miller Eq. 9 applied to a pilot: estimate sigma^2 (within-challenge variance) from K >= 3 repeats of one arm, estimate omega^2, choose K so that 2 sigma^2/K is comparable to or below omega^2 (K = 3-5 typically) and then spend remaining budget on challenges, not repeats. Run both arms with the same K, interleaved in time (not arm A on Monday and arm B on Friday) to avoid provider drift; randomize run order.
- Attribution also needs a single-factor ablation: if A and B differ in model, route, prompt, tools and budget at once, the result is a comparison of bundles, not of "the configuration". Say so, or add an ablation arm.
- With K small the per-challenge success estimate is noisy (5/5 Wilson lower bound 0.57); call a challenge "reliably solved" only with K and rule stated up front.
- Temperature 0 does not remove variance (Bjarnason, Atil), and many agent APIs ignore or constrain temperature and seed (reasoning models); record what was requested and what was honoured, and do not claim determinism.

### Gaps
- I did not find a published paper that states the required number of repeats for agentic LLM security evaluations or for paired comparison at N around 30. Bjarnason et al. recommend power analysis without (in the abstract) giving numbers; the paper body may contain a table I did not retrieve.
- The variance in offensive-security agents specifically is only evidenced by Erdem (single-author preprint, one honeypot) and Gerard et al. (60-run sub-study); nothing found comparable to Bjarnason's scale for CTF-style tasks.
- The Klees "at least 30 trials" figure comes from a search summary of the paper, not verified in the paper text; fuzzing has far cheaper runs than LLM agents so the number does not transfer.

---

## 4. pass@k versus single-run reporting; unbiased estimators; what to report alongside

### Takeaway
Report the unbiased pass@k estimator of Chen et al. (2021) computed from n >= k runs per challenge, never 1 - (1 - p_hat)^k; add pass^k (all k succeed) as the reliability counterpart; always state n and k; and report cost, tokens and wall-clock next to every success rate.

### Cited Findings
- Chen et al. (2021), Codex paper, Appendix: unbiased estimator pass@k = E_problems [ 1 - C(n-c, k) / C(n, k) ] with n samples per problem, c correct, n >= k (they used larger n than k); the naive estimate 1 - (1 - p_hat)^k, with p_hat the empirical pass@1, is a consistent underestimate (their Figure 13) and the gap does not close even when n > 5k; the unbiased estimator draws k samples without replacement and may have slightly higher variance; their Figure 3 gives a numerically stable script. — [arXiv 2107.03374](https://arxiv.org/abs/2107.03374) (PDF text read in this session)
- tau-bench (Yao et al., ICLR 2025): introduces pass^k, consistency across k i.i.d. trials; GPT-4o with function calling about 61% pass^1 on retail fell to about 25% at pass^8; the "all k trials succeed" reading is from a secondary summary, check the paper for the exact definition. — [ICLR 2025 proceedings](https://proceedings.iclr.cc/paper_files/paper/2025/hash/1b126cc38b8638e07bef37e7b2bb72bf-Abstract-Conference.html); [arXiv 2406.12045](https://arxiv.org/abs/2406.12045)
- Bjarnason et al.: pass@k is an optimistic bound, pass^k a pessimistic bound; both should be reported with k > 1 beside pass@1. — [arXiv 2602.07150](https://arxiv.org/abs/2602.07150)
- Jiang et al. (Aug 2026): current agent benchmarks misapply pass@k by setting n to the number of unit tests rather than independent rollouts; they propose reliability@k with n = independent rollouts and c = fully passing rollouts; on a synthetic benchmark the misapplied metric inflated scores by 0.85-0.97 absolute; a 5-task SWE-bench Verified pilot gave 0.80 macro hidden-test pass rate but 0.20 strict resolution; a security-adjusted reliability@k counts only rollouts that are functionally correct and free of high-severity insecure patterns; in a 3-agent pilot it changed no ranking and the authors present it as a complementary lens needing larger evaluation. Not a standard security pass@k. — [arXiv 2608.14711](https://arxiv.org/abs/2608.14711) (single preprint, small pilots; weak evidence)
- Cybench and CTF-Dojo use Pass@k citing Chen et al.; surveys note pass@k rises with k and is meaningless unless k is stated. — [CTF-Dojo, arXiv 2508.18370](https://arxiv.org/pdf/2508.18370); [Cybench, arXiv 2408.08926](https://arxiv.org/html/2408.08926v2) (via search snippets)
- Conde et al. (2026) propose a pentest-agent evaluation protocol that scores validated vulnerability discovery with expert-annotated ground truth, LLM-based semantic matching with bipartite resolution, repeated and cumulative evaluation of stochastic agents, and efficiency metrics (abstract-level only). — [arXiv 2605.10834](https://arxiv.org/abs/2605.10834)

### Inferences
- Worked bias example (computed). n = 5 runs, c = 2 correct, k = 3: unbiased pass@3 = 1 - C(3,3)/C(5,3) = 1 - 1/10 = 0.90; the naive estimate 1 - (1 - 0.4)^3 = 0.784 (under by 12 points). n = 3, c = 1, k = 3: unbiased = 1.0 (any success in all three runs), naive 0.70. n = 10, c = 1, k = 5: unbiased 0.50, naive 0.41. Implementation: pass@k = 1 - prod_{i=n-c+1}^{n} (1 - k/i), return 1 if n - c < k.
- Per challenge, pass@k at k = n degenerates to "at least one success in n runs" and pass^k at k = n to "all n succeed". With K = 3-5 repeats, report pass@1 (mean success rate, the unbiased average), pass@K (any), and pass^K (all) per arm, challenge-averaged, and bootstrap over challenges for the CI, not over runs.
- Unbiased pass^k analogue (my derivation, not a citation): estimate = C(c, k) / C(n, k) (sampling k of n runs without replacement, all must succeed); e.g. n = 5, c = 4, k = 3: 0.40 vs naive (0.8)^3 = 0.512 (naive over-estimates here).
- For an attacker/red-team framing, a single success is what matters, so pass@k is the natural capability metric and pass^k is the reliability or "can an operator trust it unattended" metric. State which question each answers. For capability claims such as "agent can exploit X at all", pass@K is legitimate but must be reported with K.
- Always report beside success rate (all per arm, mean and CI over challenges): input and output tokens (and cached/reasoning separately where billed), tool calls or turns, wall-clock, dollar cost at stated price date, timeouts, and terminal states (solved, wrong answer, budget exhausted, infra error). Success-only means (cost of the solved ones) are survivorship-biased; report cost over all runs.
- Security-specific adaptation of the original estimator: none established in what I found beyond Jiang et al.'s unvalidated security-adjusted reliability@k and the use of Pass@k in CTF benchmarks; do not claim an accepted "secure pass@k".

### Gaps
- Did not read the tau-bench definition of pass^k from the paper; the unbiased estimator for pass^k is my derivation.
- No peer-reviewed security-specific pass@k variant found. Cybench and CTF-Dojo statements come from search snippets, not read.
- Conde et al. details (how many runs, which statistics, what cumulative evaluation means) not available from the abstract.

---

## 5. Cost-normalized reporting; arms with different models or routes

### Takeaway
Report accuracy and cost jointly (a Pareto plot or table), not accuracy alone; define cost-per-success as total cost divided by total successes over all runs; and when arms use different models or routes, do not collapse to a single "efficiency" number, report raw tokens, dollars at a dated price list, and wall-clock separately so a reader can reprice.

### Cited Findings
- Kapoor, Stroebl, Siegel, Nadgir, Narayanan (2024), "AI Agents That Matter": accuracy-only evaluation leads to needlessly costly agents; propose jointly optimizing accuracy and cost (Pareto frontier); inadequate holdout sets and inconsistent evaluation practices cause reproducibility problems. — [arXiv 2407.01502](https://arxiv.org/abs/2407.01502)
- Holistic Agent Leaderboard (HAL; Kapoor et al., ICLR 2026): standardized, cost-controlled evaluation; 21,730 rollouts, 9 models, 9 benchmarks, about 40,000 USD; accuracy plotted against cost; LLM-aided log inspection found shortcut behaviours (e.g. searching for the benchmark on HuggingFace); reports higher reasoning effort reducing accuracy in the majority of runs. — [arXiv 2510.11977](https://arxiv.org/abs/2510.11977); [ICLR 2026](https://iclr.cc/virtual/2026/poster/10006806)
- Erol et al. (ICLR 2026), "Cost-of-Pass": defines cost-of-pass as the expected monetary cost of obtaining one correct solution (combining accuracy and inference cost), and a "frontier cost-of-pass" as the minimum over available models or a human-expert baseline; finds common inference-time techniques (majority voting, self-refinement) rarely pay for their added cost. — [arXiv 2504.13359](https://arxiv.org/html/2504.13359v2)
- Anthropic: resource enforcement changes scores by up to 6 points; "report the multiplier used", publish resource specs. — [Anthropic](https://www.anthropic.com/engineering/infrastructure-noise)
- Conde et al. 2026 treat efficiency (runtime and cost) as part of the pentest evaluation protocol. — [arXiv 2605.10834](https://arxiv.org/abs/2605.10834)

### Inferences
- Cost-of-pass = (mean cost per attempt) / (success rate) (from memory of the paper's definition; the search summary says "expected monetary cost of getting one correct answer"). With small N, success counts near zero make this unstable (infinite at zero successes); report total cost, total successes, and a challenge-level bootstrap CI (resample challenges, keep their runs), and also the cost per attempt.
- Budget parity is a design choice, name it: equal token cap, equal dollar cap, equal wall-clock cap, or equal turn cap. They answer different questions (equal tokens favours cheap-per-token models; equal dollars favours the cheaper model; equal turns favours terse tools). Choose one as primary and show the other three as descriptive stats.
- Different models or routes (e.g. Claude through Anthropic API vs an OpenAI-compatible route, or different providers): record exact model ID strings and date, provider route, caching on/off, reasoning effort/thinking budget; convert to dollars with a price table dated and published; also report tokens by type so the price can be recomputed; avoid comparing a self-hosted local model's "free" cost with metered API cost without stating GPU-hour assumptions. If one arm uses prompt caching and the other does not, the dollar comparison is not like-for-like; report both with and without caching.
- If arms differ in model, the paired design still holds (same challenges), but the claim is about "A as deployed vs B as deployed", not about a framework feature.

### Gaps
- No published standard for per-token cost normalization across routes; the Cost-of-Pass definition was taken from an abstract-level summary, not the paper's exact formula.
- No source found on how to handle cost when one arm is metered and one is flat-rate/subscription.

---

## 6. Blinding and inter-rater reliability for "did the agent find the documented vulnerability"

### Takeaway
Blind raters to arm (and to which run is which), randomize presentation order, give them a written rubric tied to the ground-truth finding, have at least two independent raters on all items (or a pre-planned stratified sample), report percent agreement plus a chance-corrected statistic that is robust to prevalence, and keep keyword or tool prefilters out of the rater's view. At N of 26-40 challenges (times K and arms, about 150-250 rated outcomes), agreement estimates still carry wide intervals.

### Cited Findings
- Blinded outcome assessors in trials (clinical canonical source): a 2025 meta-epidemiological study comparing blinded and non-blinded assessors within the same trials estimated that non-blinded assessors exaggerated odds ratios by 29% (8-45%) on average, largest for judgment-based outcomes. The MetaBLIND study (Moustgaard et al., BMJ 2020; 142 Cochrane meta-analyses) found no average difference by blinding status of patients, providers, or outcome assessors, and noted that blinding terminology and reporting are poor. So the evidence is contested on the average effect but consistent on the risk for subjective outcomes. — [Moustgaard 2020](https://jameslindlibrary.org/wp-data/uploads/2024/03/Moustgaard-2020.pdf); [2025 study](https://ddd.uab.cat/pub/artpub/2025/325973/325973.pdf); [combined analysis, PMC2267990](https://pmc.ncbi.nlm.nih.gov/articles/PMC2267990) (all via search summaries, effect sizes not independently verified)
- Pre-filled labels and AI suggestions bias annotators: annotators adopt model suggestions even when wrong (Schroeder et al. 2025, cited by a 2026 paper); in a randomized experiment (Beck et al. 2025, "Bias in the Loop", n = 2,784) AI-favourable participants showed overreliance on suggestions while skeptics detected errors better; syntactic annotation by editing tagger output shows clear anchoring and overestimated parser performance vs annotation from scratch (Berzak et al., EMNLP 2016); a 2024 study found anchoring bias when experts worked with highlighted LLM suggestions with label names; a calibration set labeled before annotation is proposed as mitigation for sequential anchoring. — [Bias in the Loop, arXiv 2509.08514](https://arxiv.org/html/2509.08514v1); [Berzak et al.](https://people.csail.mit.edu/berzak/papers/D16-1239.pdf); [arXiv 2410.04699](https://export.arxiv.org/pdf/2410.04699); [arXiv 2603.21094](https://arxiv.org/pdf/2603.21094) (from search summaries; only abstracts and excerpts seen)
- Kappa paradox: with skewed marginals (high prevalence of one category), kappa can be low while observed agreement is high (Feinstein and Cicchetti 1990); remedies: report positive and negative agreement indices (Cicchetti and Feinstein), PABAK = 2*Po - 1 (Byrt et al.), or Gwet's AC1, which one review found most robust; Vach (2005) argues kappa's prevalence dependence is intended. — [PMC5712640](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC5712640/); [PMC4236536](https://pmc.ncbi.nlm.nih.gov/articles/PMC4236536); [BEA/FCSM paper](https://www.fcsm.gov/assets/files/docs/J4_Xie_2013FCSM.pdf)
- Krippendorff's alpha: conventional thresholds alpha >= 0.800 reliable, 0.667-0.800 only tentative conclusions, < 0.667 discard; judge the lower bound of a bootstrapped CI, not the point estimate; stricter minimums for safety or medical labels. These are a convention, not a validated law. — [CASRAI guide](https://casrai.org/guides/krippendorffs-alpha) (secondary source)
- Conde et al. (2026) use expert-annotated ground truth plus LLM-based semantic matching and bipartite resolution to score pentest findings, i.e. the matching of "found finding to documented vulnerability" is itself the rating problem. — [arXiv 2605.10834](https://arxiv.org/abs/2605.10834)
- Zhu et al. (2025) Agentic Benchmark Checklist: many benchmark flaws are in task setup and reward design (e.g. empty responses counted as successes, insufficient test cases); applying the checklist to CVE-Bench reduced performance overestimation by 33%. This is a grader-validity issue distinct from inter-rater agreement. — [arXiv 2507.02825](https://arxiv.org/abs/2507.02825)

### Inferences
Procedure (my synthesis from the above):
1. Rating unit: each (challenge, arm, run) outcome, not the challenge, so agreement has more items (e.g. 30 x 2 x 3 = 180).
2. Objective ground truth first: where success is a flag, canary token, or an oracle (OAST callback, proof-of-exploit request) use that and do not use human ratings for it. Human rating is for the semantic question "did the report describe the documented vulnerability, at the right location, with a working PoC".
3. Blinding: strip arm identifiers, model names and framework-specific boilerplate from transcripts/reports; assign opaque IDs; shuffle order; separate rater and operator (the person who built the framework should not be a primary rater, or if they must, they rate blinded and a second independent rater is mandatory). Pre-register the rubric: binary or ordinal (e.g. not found / found different issue / found, no valid PoC / found with valid PoC), with the primary endpoint dichotomized in advance.
4. Raters: minimum two independent raters on all items (or on a pre-specified random sample of at least about 30% plus all disagreements adjudicated), plus a third adjudicator for disagreements. One rater is not defensible for a subjective outcome; two with adjudication is the practical minimum for a single developer's study; three raters allow Krippendorff alpha with missing data and majority adjudication.
5. Prefilters: a keyword or tool-assisted prefilter that highlights candidate matches should not be shown to raters (anchoring and automation bias above). If a prefilter is used purely to shrink the pile, apply it identically to both arms, hide its output from raters, and rate a random sample of the not-flagged items to estimate its false-negative rate; report that rate. Rating from scratch rather than editing a suggestion is the documented anti-anchoring design (Berzak). Keyword-matching results can still be used as a separate, labelled automatic measure.
6. Statistic: report observed agreement and Cohen's kappa (two raters) with a CI, plus positive and negative agreement (or PABAK or Gwet AC1) because the prevalence is likely skewed (most runs fail); use Krippendorff's alpha with bootstrap CI when more than two raters or missing ratings. Percent agreement alone is not acceptable (inflated by chance and prevalence).
7. Adequacy: Krippendorff 0.80 / 0.667 convention above; Landis and Koch (1977) bands (0.61-0.80 substantial, above 0.80 almost perfect) are widely cited but arbitrary (from memory, not re-verified); state your threshold in advance, e.g. alpha lower CI bound >= 0.667.
8. Worked precision at your scale (computed with the simple large-sample SE sqrt(Po(1-Po)/(n(1-Pe)^2)); crude): N = 30 ratings, table both-yes 12 / A-only 2 / B-only 1 / both-no 15: Po = 0.90, kappa = 0.80, approximate 95% CI 0.58-1.0. A prevalence-skewed example 3/1/1/25: Po = 0.93 but kappa = 0.71 with CI 0.33-1.0. With about 30 items, a kappa of 0.8 cannot be distinguished from 0.6; use about 150+ rated runs to narrow, and report CIs. The large-sample SE is optimistic at this n; bootstrap is preferable.
9. If the rater disagreement cannot be resolved, do not drop the item: count it with the adjudicated label and publish both raters' labels.

### Gaps
- I did not retrieve primary sources for Cohen 1960, Landis and Koch 1977, Krippendorff's text, or McHugh 2012; the interpretation bands are from memory or secondary pages.
- I found no study that measures anchoring or bias specifically in security-finding rating by keyword-highlighted or tool-assisted pre-annotation; the evidence is from general annotation (NLP and clinical-decision) settings and should be described as indirect.
- I did not find a published sample-size formula for kappa that I could verify (Sim and Wright 2005 exists, from memory, not verified).
- The 29% exaggeration figure comes from a search summary of a 2025 meta-epidemiological study; the exact citation, authors, and journal were not retrieved. Treat as indicative.

---

## 7. Outcome-dependent exclusion: name, bias, and handling of infrastructure failures

### Takeaway
Excluding trials after the fact on criteria that depend on the outcome (or on arm-specific behaviour) is a post-randomization or post-treatment exclusion; it breaks the comparability that pairing provides and biases toward the arm whose failures are being dropped, which is the clinical per-protocol / "modified ITT" problem. Infrastructure failures can legitimately be excluded only under a rule fixed in advance, determined from infrastructure evidence, blind to arm and to agent behaviour, applied symmetrically, and always reported with an intention-to-treat sensitivity analysis.

### Cited Findings
- Hernán and Hernández-Díaz (2012, Clinical Trials 9(1):48-55): ITT is the primary analysis of most RCTs; "as treated" and "per protocol" analyses as commonly implemented have shortcomings; non-naive per-protocol methods (inverse probability weighting, g-estimation, instrumental variables) can handle non-adherence and loss to follow-up; ITT can also misstate effectiveness when adherence differs by arm. — [PMC3731071](https://pmc.ncbi.nlm.nih.gov/articles/PMC3731071)
- Modified ITT (dropping randomized participants who never started treatment) is criticized because post-randomization exclusions can induce bias; ICH E9(R1) encourages defining the estimand first and then choosing an estimator aligned with it, and treats handling of "intercurrent events" through named strategies including treatment policy (analyse as randomized regardless of the event). — [arXiv 2206.10453 (mITT as principal stratum)](https://arxiv.org/pdf/2206.10453); [E9(R1) summaries, PMC7376663](https://pmc.ncbi.nlm.nih.gov/articles/PMC7376663) (secondary; the ICH text itself was not retrieved)
- Agent-evaluation practice: DeepSWE (2026) removes rollouts hit by provider, grading or transient network errors from both numerator and denominator, reports the excluded share (0-5.3%) and states ranking unaffected; MASEval documentation recommends counting agent errors as agentic failures while excluding benchmarking-infrastructure errors and rerunning those; Anthropic reports up to about 6% of Terminal-Bench 2.0 tasks failed from pod errors and that resource enforcement moved scores 6 points, so infrastructure is a confounder, not noise. — [DeepSWE, arXiv 2607.07946](https://arxiv.org/pdf/2607.07946); [MASEval](https://maseval.readthedocs.io/en/stable/guides/exception-handling/); [Anthropic](https://www.anthropic.com/engineering/infrastructure-noise) (search summaries; not read in full)
- Security-agent case where misattribution happened: Erdem's 400-run study initially attributed truncated Claude runs to refusals; full-log audit showed 39 were HTTP 529 upstream overload errors. — [arXiv 2605.30096](https://arxiv.org/abs/2605.30096)
- Zhu et al. (ABC): reward-design flaws (e.g. counting empty answers as success) can change measured performance up to 100% in relative terms. — [arXiv 2507.02825](https://arxiv.org/abs/2507.02825)
- Researcher degrees of freedom: Simmons, Nelson, Simonsohn (2011) show flexible exclusion and stopping rules inflate false positives; one 2025 retrospective gives worst cases as high as 60% against a nominal 5%; preregistration borrowed from clinical trials is the reform, with mixed evidence that it improves quality when plans leave exclusion rules open. — [Simmons et al. via search](https://stafforini.com/works/simmons-2011-falsepositive-psychology-undisclosed/); [retrospective](https://replicationindex.com/2025/08/09/a-decade-after-false-positive-psychology-what-have-we-learned-about-p-hacking-and-the-false-positive-risk-in-psychology)

### Inferences
- Methodological names: post-randomization (post-treatment) exclusion; per-protocol analysis; survivorship / selection bias; "conditioning on a post-treatment variable". The agent-evaluation analogue of ITT: every attempted (challenge, arm, run) enters the denominator and failures count as failures, whatever the cause.
- Why it biases here: the arms differ in prompts, tools, budgets and routes. Many "infrastructure" failures are arm-dependent: more tokens means more context overflow and rate-limit hits; a different provider route means different 429/529 rates; a heavier tool container means more OOM kills; a more aggressive agent trips WAF or crashes the target. Dropping those failures removes losses preferentially from one arm. The paired structure does not fix this: a dropped run removes the pair or turns the challenge into a different effective sample.
- Recommended handling:
  1. Pre-register the failure taxonomy before the run: (a) infrastructure (provider outage, container crash, harness bug, grader crash, network unavailability of the target), (b) agent-attributable (budget exhausted, timeout caused by agent looping, wrong answer, refusal, context overflow as caused by agent output volume), (c) ambiguous. Classification uses infrastructure logs, not trajectory content or outcome, and is done blind to arm (strip arm label).
  2. Retry policy fixed in advance and symmetric: e.g. rerun an infrastructure-failed run up to r = 2 times with identical config; record all attempts; the retry is not an additional sample to cherry-pick from; count only the first attempt that reaches a terminal agent-attributable state.
  3. Primary analysis (state which): ITT, all attempted runs counted, infrastructure failure = failure (conservative; estimand: performance as deployed on this infrastructure), or pre-specified exclusion of category (a) runs, never category (b). If the excluded fraction differs between arms, the exclusion is not symmetric: report it as a result and prefer ITT as primary.
  4. Always add a sensitivity analysis: (i) ITT counting infra failures as failures; (ii) complete-case excluding category (a); (iii) worst-case bounds (all excluded runs assigned success for A and failure for B, and the reverse). If the conclusion differs across (i)-(iii), the study is inconclusive on that point; say so.
  5. Publish a flow table in CONSORT style: planned runs, executed, infra-failed (by cause), retried, analysed, per arm; and the raw per-run file including excluded rows.
  6. Fix infrastructure variables as design factors (container CPU/RAM/time limits, enforced and guaranteed resources, concurrency, time of day) and record them (Anthropic).
- Do not drop a challenge from the set after seeing results (e.g. "unsolvable by both", "target bug"): if the challenge itself is faulty, define challenge-validity criteria in advance, verify with a reference solution before any arm runs, and report the original N.
- Early-stopping and adaptive additions (run more repeats until the difference appears) are also undisclosed flexibility; fix N and K in advance, or use a pre-specified sequential design.

### Gaps
- The ICH E9(R1) text and the CONSORT 2010 statement were not retrieved this session; the named strategies (treatment policy, hypothetical, composite, while-on-treatment, principal stratum) are from memory beyond the "treatment policy" mention in the summary page.
- I found no peer-reviewed methodology paper specifically on exclusion of infrastructure failures from LLM-agent evaluation; the sources are an engineering blog (Anthropic), a library doc (MASEval), and one benchmark paper (DeepSWE), all read only at summary level. Treat the recommended protocol as a synthesis, not a published standard.
- Gupta (2011) on the ITT concept and Fisher et al. on ITT were not retrieved.

---

## 8. Preregistration and reporting standards; what to publish for reproducibility

### Takeaway
There is no accepted preregistration or checklist standard specific to security-agent evaluation. The nearest applicable norms are the NeurIPS checklist (error bars with stated variability source and calculation), ACM and USENIX Security artifact badging, Arp et al.'s pitfalls for ML in security, Klees et al. for tool evaluation with randomized trials, and the 2025-26 agent-evaluation checklists (ABC, HAL, Conde et al.). Preregistration by timestamped commit of a protocol file is cheap and addresses the largest threat at this sample size, researcher degrees of freedom.

### Cited Findings
- NeurIPS paper checklist: report error bars, confidence intervals or significance tests for the experiments supporting main claims; state the source of variability captured (split, initialization, random draw, whole run), how it was computed (closed form, library, bootstrap), assumptions (e.g. normal errors), whether SD or SE; avoid symmetric error bars that leave the valid range (e.g. negative error rates); answering "no" is acceptable with justification. — [NeurIPS 2022 checklist guidelines](https://neurips.cc/Conferences/2022/PaperInformation/PaperChecklist); [2021](https://neurips.cc/Conferences/2021/PaperInformation/PaperChecklist) (2024 wording via a third-party summary)
- ACM Artifact Review and Badging v1.1 (badges from 15 May 2020): independent badges (Artifacts Evaluated - Functional / Reusable, Artifacts Available, Results Reproduced / Results Replicated); v1.1 swapped the definitions of "reproduced" and "replicated" to match NISO. Exact current definitions not retrieved. — [ACM badging terms](https://www.acm.org/publications/badging-terms); [ACM policy page](https://www.acm.org/publications/policies/artifact-review-badging/)
- USENIX Security artifact badges: Artifacts Available (public, mandatory for accepted papers under the Open Science policy, no functionality requirement), Artifacts Functional (complete, documented, exercisable), Results Reproduced (the artifact produces the paper's main results); USENIX Security 2023: 138 Available, 120 Functional, 96 Reproduced badges. — [USENIX Security 2025 badges](https://secartifacts.github.io/usenixsec2025/badges); [USENIX Security 2026 call](https://www.usenix.org/node/315295)
- Arp et al. (USENIX Security 2022, Distinguished Paper), "Dos and Don'ts of ML in Computer Security": ten pitfalls (e.g. sampling bias) found in 30 top-tier security papers, with recommendations. — [USENIX](https://www.usenix.org/conference/usenixsecurity22/presentation/arp); [arXiv 2010.09470](https://arxiv.org/abs/2010.09470) (full list of the ten not retrieved)
- Klees, Ruef, Cooper, Wei, Hicks (CCS 2018), "Evaluating Fuzz Testing": security-tool evaluation guidelines with multiple trials, statistical tests (Mann-Whitney U, Vargha-Delaney A12 following Arcuri and Briand), confidence intervals and effect sizes; the 2024 SoK reports that many fuzzing papers still do not follow them, and that Mann-Whitney with 3 runs cannot reject. — [arXiv 1808.09700](https://arxiv.org/pdf/1808.09700); [SoK arXiv 2405.10220](https://arxiv.org/pdf/2405.10220)
- Agentic evaluations: ABC (Zhu et al. 2025), AI Agents That Matter (holdout sets, cost, reproducibility), HAL (standardized cost-controlled harness, log analysis), Bjarnason et al. (repeat runs, power analysis), Anthropic infrastructure note (publish resource specs and enforcement), Conde et al. (pentest protocol with ground-truth maintenance, repeated and cumulative runs, efficiency metrics). — [arXiv 2507.02825](https://arxiv.org/abs/2507.02825); [arXiv 2407.01502](https://arxiv.org/abs/2407.01502); [arXiv 2510.11977](https://arxiv.org/abs/2510.11977); [arXiv 2602.07150](https://arxiv.org/abs/2602.07150); [Anthropic](https://www.anthropic.com/engineering/infrastructure-noise); [arXiv 2605.10834](https://arxiv.org/abs/2605.10834)
- Effectiveness of preregistration is contested: a 2025 review reports plans often leave flexibility in variables, exclusions and analyses and that badges improve transparency without clearly reducing false discovery; Registered Reports are the most effective reform so far. — [replicationindex retrospective](https://replicationindex.com/2025/08/09/a-decade-after-false-positive-psychology-what-have-we-learned-about-p-hacking-and-the-false-positive-risk-in-psychology) (secondary, blog)

### Inferences
Minimum reproducibility record for a third party to reproduce a run (synthesis; items correspond to sources above):
- Models: exact provider model ID string, snapshot or date, route/base URL, access date; sampling parameters requested and honoured (temperature, top-p, max tokens, reasoning/thinking budget, seed) and a statement that determinism is not claimed.
- Scaffold: repository commit hash, system prompts, skills/tool definitions, tool versions, container image digest, hook/scope-guard configuration, budgets (tokens, turns, wall-clock, dollars), concurrency and rate limits, retry policy, resource limits (CPU, RAM, guaranteed vs hard cap).
- Targets: challenge list with IDs and versions, ground-truth description per challenge, how and when the target was reset, network topology, any contamination checks (whether the challenge text and solutions are public and could be in training data); the ABC checklist items on task validity and outcome validity.
- Design: preregistered protocol (timestamped commit before the first run): primary endpoint, comparison, test (mid-p vs exact), alpha, N, K, exclusion rules, rater procedure, handling of infrastructure failures, which sweeps are confirmatory vs exploratory, stopping rule.
- Data: per-run table (challenge, arm, run id, seed, start time, outcome, failure class, tokens by type, cost, wall-clock), the 2x2 paired table, raw trajectories (redacted), rater labels from each rater, analysis script that regenerates every table.
- Deviations: a deviations log. Everything run, including aborted sweeps and discarded configurations, listed with count.
- Artifact: a container or lockfile enough for the USENIX "Results Reproduced" criterion, with a note that LLM nondeterminism means reproduction is of the distribution (CI overlap), not of identical outputs; and cost estimate to reproduce.
- Preregistration for a solo developer: OSF registration or an immutable git tag plus public hash; add "analysis plan v1" before any confirmatory run; pilots for estimating psi, omega^2, sigma^2 are allowed and declared as pilot (not part of the confirmatory N).
- Legal and ethical notes specific to security: scope and authorization statement (the repository's scope.yaml), the targets are lab or authorized; disclose that offensive tooling results can be dual use.

### Gaps
- No security-specific preregistration standard or reporting checklist for LLM-agent offensive evaluation exists in what I found; ABC and Conde et al. are the nearest. I did not read the ABC checklist items themselves (only the abstract) nor the ten pitfalls of Arp et al.
- NeurIPS 2024/2025 checklist wording was only seen through a third-party summary; ICLR/ACL reproducibility checklists (and Pineau et al.) were not retrieved.
- Exact ACM v1.1 definitions of "Results Reproduced" and "Replicated" were not retrieved.

---

## 9. Multiple comparisons across sweeps over the same targets

### Takeaway
The main protection is design, not a correction formula: pre-register one primary comparison, label everything else exploratory, report the count of all sweeps, configurations and analyses run, and keep a frozen holdout of challenges that were never used to tune the framework. When a family of confirmatory tests exists, use Holm (strong familywise control, uniformly more powerful than Bonferroni); use Benjamini-Hochberg only for exploratory screening.

### Cited Findings
- Demšar (JMLR 2006): comparing classifiers over multiple datasets was handled by ad hoc procedures; recommends non-parametric tests (Wilcoxon signed-ranks for two classifiers, Friedman with post-hoc tests for more) and critical-difference diagrams. — [JMLR](https://jmlr.org/papers/v7/demsar06a.html)
- Simmons et al. (2011): undisclosed flexibility in data collection and analysis makes false positives easy; disclosure requirements proposed (six for authors, four for reviewers). — [SSRN](https://papers.ssrn.com/abstract=1850704)
- AI Agents That Matter: weak or missing holdout sets let agents shortcut and overfit; they propose a framework for avoiding overfitting. — [arXiv 2407.01502](https://arxiv.org/abs/2407.01502)
- A security-agent paper explicitly lists as a limitation that fixes were tuned on the same challenges used for evaluation. — [arXiv 2607.02873](https://arxiv.org/abs/2607.02873)

### Inferences
- Two different problems: (1) multiple tests (several endpoints, several arm pairs, several sweeps) inflate familywise error; (2) adaptive reuse of the same N = 30 challenges to develop the framework (look at failures, change prompts or tools, re-run) makes later p-values invalid regardless of correction, since the test set is no longer independent of the hypothesis. Correction formulas fix only (1).
- Holm (1979, Scand J Stat 6:65-70; from memory): sort p-values p(1) <= ... <= p(m), reject p(i) while p(i) <= alpha/(m - i + 1). Bonferroni: alpha/m. Benjamini-Hochberg (1995, JRSS B 57:289-300; from memory): reject all p(i) with p(i) <= (i/m) q. Neither was retrieved this session; Holm is the default for confirmatory claims about the same sweeps. With m = 3 comparisons at alpha 0.05, the smallest p must be below 0.0167, which at N = 30 requires discordant splits of about 9-0 or 10-1 or better: the correction pushes detectable effects to essentially "all discordants favour one arm". Another reason to keep the family to one or two primary comparisons.
- Practical discipline (a) one primary hypothesis and primary endpoint, fixed N and K; (b) secondary endpoints (cost, tokens, time-to-first-finding) reported as estimates with CIs and labelled descriptive; (c) split challenges into a development set and a held-out confirmatory set before any development (for example 10-12 dev, 20-28 test, or reserve a second, untouched target family) and never inspect confirmatory failures before the primary analysis; (d) counting: report "k sweeps run, j configurations tried, m tests performed", including failed attempts; (e) if the framework was changed between sweeps, report each sweep as a separate version, do not pool, and do not call the final sweep an independent confirmation; (f) report effect estimates and intervals rather than a ladder of p-values, and replicate on fresh targets rather than adjusting.
- A pre-registered sequential plan (e.g. fixed stages with alpha spending) is the principled way to stop early or add challenges; ad hoc additions are not.
- At this sample size, a significant uncorrected sweep result among several unadjusted looks should be treated as hypothesis-generating.

### Gaps
- Holm 1979 and Benjamini-Hochberg 1995 primary sources were not retrieved (search returned only Demšar); the formulas are standard but unverified here.
- I found no LLM-agent-specific multiple-comparison guidance; the advice is transferred from clinical trials, fuzzing evaluation and ML benchmarking.

---

## 10. Synthesis: a defensible minimal protocol for a single-developer, N = 26-40 paired study

### Takeaway
Preregister one two-sided paired comparison with K = 3-5 repeats per cell, analyse at the challenge level, report the 2x2 discordant table, a paired CI and mid-p (or exact) McNemar, with ITT as the primary handling of failures, blinded double rating where outcomes are judged, and a plain statement of the minimum detectable difference. State candidly that anything below a roughly 25-30 point difference is unresolvable at this N.

### Cited Findings
- See sections 1-9 for the sources; the synthesis rests on Miller 2024, Bowyer et al. 2025, Fagerland et al. 2013, Bjarnason et al. 2026, Chen et al. 2021, Kapoor et al. 2024, Zhu et al. 2025, Hernán and Hernández-Díaz 2012 and the artifact-badging norms cited above.

### Inferences
1. Hypothesis and estimand: "success rate of A minus B on the same challenge set, challenge-averaged over K runs, ITT". One primary endpoint, two-sided.
2. Design: same challenges, same infrastructure, interleaved scheduling, one factor differing (or declare a bundle), N and K fixed, dev/confirmatory split.
3. Power statement in the paper: "With N = 30 and an expected discordance of 0.3, the exact McNemar test has 80% power only for a true difference of at least 0.275 (mid-p 0.26); a difference of 0.2 has 40% (exact) to 52% (mid-p) power." (use your own pilot psi.)
4. Analysis: challenge-level per-arm success proportion (K runs collapsed per challenge, or GLMM with challenge random effect); 2x2 table of per-challenge binary outcomes (pre-specified collapse rule); mid-p or exact McNemar (pre-specified); Newcombe paired CI for the difference; Wilson CIs per arm; challenge-bootstrap for pass@1, pass@K, pass^K and for cost per success.
5. Reporting: counts first (b, c, n_disc), then estimates and intervals, then p. Wording rules: if n_disc < 6 write "the design could not detect a difference"; if CI spans from near 0 to a large effect write "compatible with no effect or a large effect"; never write "no difference" from a non-significant result.
6. Failures: taxonomy and symmetric rule fixed in advance; ITT primary; sensitivity analyses; flow table.
7. Rating: blinded, rubric fixed, two independent raters plus adjudicator, kappa with CI plus positive/negative agreement or AC1, prefilters hidden.
8. Publication package: per section 8.
9. Be explicit about contested choices (exact vs mid-p, Wilson vs Clopper-Pearson, ITT vs pre-specified exclusion, pass@k vs pass^k as headline, one-sided vs two-sided), say which was chosen before the data and cite both camps.

### Gaps
- This protocol is my synthesis; no published paper prescribes exactly this combination for agentic security evaluations, and I could not verify that reviewers at security venues apply these norms uniformly.

---

## Verification status summary
- Read in this session at text level: Miller 2024 (PDF text), Bowyer et al. 2025 (PDF text), Chen et al. 2021 (PDF text), abstract-level fetches of Bjarnason 2026, Atil 2024-25, Kapoor 2024, Zhu 2025, Jiang 2026, Gerard 2026, Conde 2026, Erdem 2026, and the Anthropic infrastructure post.
- Search-summary only (not read in full): Fagerland 2013, Brown-Cai-DasGupta 2001, Agresti-Coull 1998, Newcombe 1998, Klees 2018, SoK 2024, Hernán 2012, Arp 2022, Demšar 2006, tau-bench, HAL, Cost-of-Pass, DeepSWE, MASEval, the anchoring and kappa literature, the blinding meta-epidemiology, NeurIPS/ACM/USENIX pages.
- From memory, not retrieved or verified: McNemar 1947, Connor 1987, Holm 1979, Benjamini-Hochberg 1995, Landis-Koch 1977, Cohen 1960, Sim-Wright 2005, ICH E9(R1) named strategies, Arcuri-Briand 2011, Vargha-Delaney 2000, CONSORT 2010, Wilson 1927 and Clopper-Pearson 1934 original texts.
- Computed here, not independently cross-checked against another implementation: all McNemar power numbers, intervals, pass@k examples, kappa examples, the Newcombe paired interval (re-implemented from memory).
