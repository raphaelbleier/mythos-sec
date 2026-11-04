# Benchmark methodology for AI web-pentest agents (status Nov 2026)

## 1. XBOW validation-benchmarks: structure, scoring, published rates, pitfalls, license

### Takeaway
104 Docker CTF-style web challenges, flag injected at build time via `make build`, Apache-2.0. XBOW itself now calls the set outdated/saturated (vendors self-report 96-100%), so it is a sanity/regression suite, not a discriminating one. Published numbers are mostly vendor-reported, differ in white/black-box, retries and patched forks, so they are not comparable with each other.

### Cited Findings
- 104 web Jeopardy-style challenges, one folder per challenge under `benchmarks/`; flag is not hardcoded but injected at build time; each has a `docker-compose.yml`; services reachable by other services use `export`, services reachable by the AI use `ports`; `healthcheck`/`depends_on` used against race conditions; Dockerfiles declare `ARG flag` late. README says the set is outdated and saturated (~100% industry performance) and kept for historical purposes. — [README](https://github.com/xbow-engineering/validation-benchmarks)
- Metadata schema per README: JSON with `name`, `description`, `level` (1 easy, 2 medium, 3 hard), optional `files`, `win_condition` (`flag` or `question`), `tags` (from `tags.csv`), `canaries` (MAPS canary strings). README names the file `benchmark/benchmark-config.json`; the common.mk reads `benchmark.json`. Naming discrepancy between README and Makefile; verify in the checkout. June 2025 update added `benchmark.yaml` for XBOW's autobuild pipeline (schema undocumented). — [README](https://github.com/xbow-engineering/validation-benchmarks), [common.mk](https://raw.githubusercontent.com/xbow-engineering/validation-benchmarks/main/common.mk)
- common.mk: `BENCHMARK` = dir name; `FLAG = sha256(UPPERCASE_DIRNAME)` via `echo -n $(BENCHMARK_UPPER) | openssl sha256 -r`; `FLAG_FMT = FLAG{<hex>}`; passed as build args `FLAG` and `flag`; targets `check-deps` (docker, openssl, docker compose plugin), `clean` (removes guard `.xben_build_done`), `build`, `run` (`docker compose up --wait`), `stop` (`docker compose stop`); `NO_CACHE=1` adds `--no-cache`; override flag with `make build FLAG=<value>`. Consequence: the expected flag is deterministic, e.g. for `XBEN-001-24`: `FLAG{$(echo -n XBEN-001-24 | openssl sha256 -r | cut -d' ' -f1)}`. Prefer overriding FLAG with a random per-run value so agents cannot guess/precompute. — [common.mk](https://raw.githubusercontent.com/xbow-engineering/validation-benchmarks/main/common.mk), [README](https://github.com/xbow-engineering/validation-benchmarks)
- Difficulty split 45 easy / 51 medium / 8 hard (26 tags, 165 tag assignments, multi-label). — [Mako paper listing via search](https://arxiv.org/pdf/2607.11288) (secondary, via search snippet; Strix repo gives the same 45/51/8 split, below)
- License: Apache-2.0 with LICENSE and NOTICE. Contains deliberately unfixed vulnerabilities; run only isolated/sandboxed. Canary string to discourage training-data inclusion (XBOW asks trainers to exclude). — [README](https://github.com/xbow-engineering/validation-benchmarks), [XBOW blog](https://www.xbow.com/blog/benchmarks)
- XBOW own result: 85% of 104; principal pentester 85%, staff 59%; humans had 40 h, XBOW finished in 28 min; one experiment, no repeated runs, no pass@k, no cost reported. Authors are pentest firms engaged by XBOW (given only a vuln-class list). — [XBOW vs humans](https://www.xbow.com/blog/xbow-vs-humans), [XBOW blog](https://www.xbow.com/blog/benchmarks)
- Strix v0.4.0: 100/104 (96%) black-box, `gemini-3-pro-preview`; L1 45/45, L2 49/51, L3 6/8; ~$3.37/challenge avg (~$337 for solved set); ~668K input / ~6.5K output tokens per challenge; 73.5% cache hit; avg solve ~19 min, fastest 2.2 min; simple challenges 1-2 agents / 10-40 tool calls, complex 3-6 agents / 40-160 calls. Failed: XBEN-056-24 (SSTI), -066-24 (HTTP smuggling), -088-24 (race condition), -092-24 (PHP deserialization). Result records `flag_extracted` and `solved`. Timeout not specified. — [usestrix/benchmarks XBEN](https://github.com/usestrix/benchmarks/tree/main/XBEN)
- A secondary blog says the Strix figure is vendor-reported with no independent replication as of Aug 2026, and cites a cost of $3.37 measured with GPT-5.4 (conflicts with the repo's gemini-3-pro-preview attribution; the repo's own config example uses openai/gpt-5). — [dev.to](https://dev.to/creeta/strix-claims-96-on-xben-that-number-is-vendor-reported-3en8) contradicts model attribution in [Strix repo](https://github.com/usestrix/benchmarks/tree/main/XBEN)
- Other self-reported XBOW results: Shannon Lite 96.15% (100/104) on a "cleaned, hint-free" version (white-box); FireCompass 100/104 first attempt, 104/104 with best-of-N on four retried; a GitHub kit 90/104 first pass; a CTF-lab write-up 88/104 earlier, perfect later. Configurations differ (white-box, retries, cleaned benchmarks). — [search summary, sources: firecompass.com, mintlify Shannon, lordx64/pentestkit, redpick](https://firecompass.com/blog-xben-benchmark/)
- Pitfall (single secondary source, unverified): a cold CI build of upstream fails on 39/104 challenges, mostly rotted Debian Buster apt sources; one `sed` rewriting Buster archive URLs reportedly unblocks 36. Many leaderboards run "patched forks" rather than upstream. Hard unsolved examples: XBEN-079 (str_replace bypass -> Apache log poisoning), XBEN-099 (forge MongoDB ObjectID, IDOR). Could not fetch the original pwnkit post (domain unreachable). — [pwnkit investigation (via search)](https://pwnkit-docs.pages.dev/research/unsolved-eight-investigation/), [0sec](https://0sec-ai-homepage.pages.dev/blog/2026-04-07-the-unsolved-nine)

### Inferences
- Networking: README says AI-facing services use `ports`, so the agent must reach `localhost:<random host port>` or the compose network. For an agent in its own container, attach it to the challenge's compose network (or use `host.docker.internal`/host-gateway); not documented in README, check each docker-compose.yml.
- Admin-bot/XSS challenges (23 XSS tags) need the bot container running and reachable from the target; XSS "solved" is only provable via the flag the bot leaks, so the agent needs an attacker-controlled listener reachable from the challenge network. Not documented by sources; test one XSS challenge before the run.
- Because Strix numbers imply ~$3/challenge on a frontier model, a 104 x 3 frameworks x 3 runs sweep on frontier models is roughly $3k; use free/cheap OpenCode models and a challenge subset (stratified by level/tag) for the poster.
- Since the suite is saturated and public (contamination risk), report it as a reference/sanity set and pair with newer targets (below).

### Gaps
- Exact `benchmark.json` field list as shipped (README says `benchmark-config.json`); `tags.csv` contents; whether upstream pins any build fixes in 2026.
- Any official XBOW statement on broken challenges or per-model solve rates; no primary source found.
- Per-challenge timeouts/cost for non-Strix frameworks.

## 2. Other hard web/API benchmarks

### Takeaway
crAPI (21 challenges incl. LLM chatbot), Vuln Bank (11 categories incl. GraphQL and AI support), DVGA (about 20 scenarios), VAmPI (9 vulns) are small, Docker-run, permissively licensed targets with documented vuln lists usable as detection-recall ground truth. Vulhub gives per-CVE compose environments for oracle-based exploit tasks. AutoPenBench and CyberGym are heavier and measure different things. PortSwigger Academy ToS not verified.

### Cited Findings
- crAPI: microservices; run `cd deploy/docker; docker compose pull; docker compose -f docker-compose.yml --compatibility up -d`; web UI :8888, MailHog :8025; env via `.env` (e.g. `LISTEN_IP=0.0.0.0`); Compose >= 1.27.0; Apache-2.0; chatbot LLM provider configurable; resource needs not documented. — [crAPI README](https://github.com/OWASP/crAPI)
- crAPI challenges (docs/challenges.md, 18 disclosed + secret ones; page inconsistent on 2 vs 3 secret): 1 BOLA vehicle details; 2 BOLA mechanic reports; 3 password reset of other user (broken auth); 4 leak other users' sensitive info (excessive data exposure); 5 leak internal video property; 6 layer-7 DoS via contact mechanic (rate limiting); 7 BFLA delete other user's video; 8 mass assignment free item; 9 mass assignment +$1000 balance; 10 mass assignment internal video props; 11 SSRF; 12 NoSQLi coupons; 13 SQLi redeem claimed coupon; 14 unauthenticated endpoint; 15 forge JWT; 16 chatbot prompt injection; 17 extract other user's credentials via chatbot; 18 chatbot acts as another user; 19-21 secret. — [challenges.md](https://raw.githubusercontent.com/OWASP/crAPI/main/docs/challenges.md)
- Vuln Bank (Commando-X): `docker-compose up -d --build`, port 5000, `/api/docs`, `/graphql`, MIT. Categories: auth (SQLi login, weak JWT, BOLA, BOPLA, mass assignment, 3-digit PIN reset), data exposure, transactions (negative transfer, race conditions), file ops (unrestricted upload, traversal, SSRF via image URL), session mgmt, XSS/CSRF/IDOR, virtual cards, bill payments, merchant API, AI customer support (prompt injection, system prompt exposure, DB access via AI), GraphQL (introspection, SQLi in resolvers, no depth limits). — [vuln-bank](https://github.com/Commando-X/vuln-bank)
- DVGA: `docker run -d -t -p 5013:5013 -e WEB_HOST=0.0.0.0 dolevf/dvga`; Beginner/Expert modes; scenarios: discovery/fingerprinting, DoS (batch, deep recursion, resource-intensive, field duplication, aliases), info disclosure (introspection, GraphiQL, field suggestions, SSRF, stack traces), OS command injection x2, stored XSS, log injection, HTML injection, SQLi, JWT forge, interface protection bypass, deny-list bypass, weak password, arbitrary file write/path traversal; MIT. — [DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application)
- VAmPI: `docker run -p 5000:5000 erev0s/vampi:latest`; compose gives secure :5001 and insecure :5002 (useful as a false-positive control); `vulnerable=0/1`; vulns: SQLi, unauthorized password change, BOLA, mass assignment, excessive data exposure (debug endpoint), user/password enumeration, RegexDoS, no rate limiting, JWT weak key; MIT. — [VAmPI](https://github.com/erev0s/VAmPI)
- Vulhub: per-product folders with per-CVE subfolders (e.g. `langflow/CVE-2025-3248`), each with README and compose; `docker compose up -d` / `docker compose down -v`; >=1 GB RAM recommended; some not ARM; MIT; ports only in per-env README; environment count not shown. — [vulhub](https://github.com/vulhub/vulhub)
- AutoPenBench: 33 tasks (22 in-vitro: access control 5, web 7, network 6, crypto 4; 11 real-world CVEs); Kali workstation container + targets on a /16 Docker network; metrics Success Rate and Progress Rate (command/stage milestones, GPT-4o-judged then manually corrected); gpt-4o-2024-08-06, temperature 0, fixed seed; step limit 30 (in-vitro) / 60 (real-world); autonomous 21% SR, assisted 64%; variance: 5 runs of AC0 per model, 10 runs of AC0 and AC2. — [AutoPenBench](https://arxiv.org/html/2410.03225v2)
- CyberGym: 1,507 OSS-Fuzz vuln instances in 188 projects; levels 0-3 (code only; +description; +crash stack; +patch); success = PoC crashes pre-patch sanitizer build and not post-patch; step limit ~80-100; best ~17.9% (OpenHands + Claude Sonnet 4), GPT-5 high reasoning 22.0%; >$40k API credits for the paper; no variance/CI reported. — [CyberGym](https://arxiv.org/html/2506.02548v2)
- NYU CTF Bench: 200 CSAW problems in six categories, compared with 1,176 human teams (survey description only). — [survey](https://arxiv.org/pdf/2607.02605)
- Synack reports its agent solving 10/10 PortSwigger Practitioner SQLi labs (vendor-reported). — [Synack](https://www.synack.com/blog/benchmarking-synacks-agentic-ai-against-portswigger-sqli-labs/)

### Inferences
- Vulhub CVE selection recipe (my suggestion, not from sources): pick 10-20 dirs with web-reachable, unauthenticated RCE/file-read/SQLi CVEs from 2024-2026 (check `git log` dates and README), where the oracle is mechanical: plant a random token in a file (`docker compose exec ... sh -c 'echo $TOKEN > /flag'`) and require the agent to return it, or check a callback listener. Avoid CVEs needing a second auth step or external services.
- For vulnerable-app targets without flags (crAPI, Vuln Bank, DVGA, VAmPI) score against the documented list as ground truth: recall = verified findings / documented vulns, precision from manual triage; VAmPI's secure instance (:5001) gives a free false-positive control.
- crAPI's chatbot challenges (16-18) need a configured LLM provider, a confound for comparisons; exclude or fix one provider.

### Gaps
- PortSwigger Academy terms: official ToS URL 404'd; no primary statement on automation/AI use, rate limits found. Treat as unverified; labs are hosted by PortSwigger (not self-hostable), so a reproducible rig is not possible; check ToS manually before use.
- Vulhub environment count and a curated "recent web CVE" list not retrieved.
- NYU CTF Bench headline success rate and run protocol not retrieved; CyberGym compute appendix truncated.
- crAPI minimum RAM/CPU not documented.

## 3. Scoring methodology in published work

### Takeaway
Published comparisons mostly use flag-capture solve rate from single runs with vendor-chosen configs; rigorous practice (AutoPenBench) adds progress milestones, fixed seeds and repeated runs. For a credible poster: same model, same budget, same tools, N>=3 runs per cell, report mean and range/CI, cost and time, plus a bare-model-with-shell control.

### Cited Findings
- XBOW vs humans: single run, no pass@k, no cost, no variance. — [XBOW](https://www.xbow.com/blog/xbow-vs-humans)
- Strix reports solve rate, per-level and per-vuln-type breakdown, tokens, cache rate, USD per challenge, solve time, tool calls, agents used. — [Strix XBEN](https://github.com/usestrix/benchmarks/tree/main/XBEN)
- AutoPenBench: SR + PR; temperature 0 / fixed seed; 5-10 repeated runs for consistency analysis; step caps. — [AutoPenBench](https://arxiv.org/html/2410.03225v2)
- CyberGym: success rate only, point estimates, no CI; thinking-mode comparison on random 300-task subset. — [CyberGym](https://arxiv.org/html/2506.02548v2)
- Third-party XBOW claims vary by white-box, hint removal, retries (best-of-N) -> not comparable. — [search summary](https://firecompass.com/blog-xben-benchmark/)

### Inferences (recommended protocol; not from a single source)
- Metrics per (framework, challenge): solved (flag matches the injected random FLAG), time-to-solve, requests/tool calls, input/output tokens, USD (or token-equivalent for free models), first-flag timestamp; for non-flag targets: detected (true positive verified by replay), false positives, precision, recall.
- Report pass@1 as mean over N runs with per-challenge solved-in-k/N; pass@k only if k stated; report Wilson 95% CI (n=104, p=0.8 gives about +/-8 pp for single run), and McNemar/paired comparison across frameworks on the same challenges; never mix best-of-N with single-shot numbers.
- Fairness: identical model + temperature, identical wall-clock and token/step cap, identical network position (black-box, no source, no hints from benchmark.json `description`/`tags`), same container image/tool set or explicit toolset listing, same fresh state per run, same scoring script run by the harness, not self-reported by the agent.
- Control: "bare model + shell (curl/python in a sandbox container) with the same prompt and budget" shows what the framework scaffolding adds.
- Strip leaks: do not expose `benchmark.json` tags/level, canary, or the sha256-of-dirname flag formula; randomise FLAG per run.

### Gaps
- No primary-source paper found that reports pass@k with CIs on XBOW; the protocol above is a synthesis.
- Mako paper (arXiv 2607.11288) methodology could not be read (PDF unparseable by fetch); saved at `/home/bleier/.claude/projects/-home-bleier-Documents-Programming-mythos-sec/c5dd8a1f-d2ba-46dd-a24f-4dd82dc73542/tool-results/webfetch-1793796342182-ugngzm.pdf` for local extraction.

## 4. Practical rig: N frameworks x M challenges on 31 GB / 16 cores

### Takeaway
No source documents this; the following is engineering inference. LLM calls dominate latency, so host load is low; the binding limits are RAM per challenge stack, Docker network/port allocation, and provider rate limits.

### Cited Findings
- Vulhub recommends >=1 GB RAM per environment and `docker compose down -v` for cleanup. — [vulhub](https://github.com/vulhub/vulhub)
- XBOW `make run` uses `docker compose up --wait` (honors healthchecks); `make stop` stops; `make clean` removes guard; `NO_CACHE=1`. — [common.mk](https://raw.githubusercontent.com/xbow-engineering/validation-benchmarks/main/common.mk)
- AutoPenBench isolates agent (Kali container) and targets on a dedicated Docker /16 network. — [AutoPenBench](https://arxiv.org/html/2410.03225v2)

### Inferences
- Concurrency: most XBOW stacks are 1-3 small containers (app + DB); budget ~0.5-1 GB each plus the agent process (framework + headless browser can reach 1-2 GB). 6-8 parallel (framework, challenge) pairs fits in 31 GB with headroom; cap by a semaphore, not by core count, and by the API rate limit (section 5).
- Isolation: one compose project per run: `COMPOSE_PROJECT_NAME=bench_<fw>_<chal>_<run>`, which gives a private default network; run the agent container `--network` joined to that project network (or `docker network connect`); no published host ports needed, agent addresses the service by DNS name; deny egress from the target network except to the LLM API via the agent only (agent container needs internet; target should not: use `internal: true` network for targets plus a second network for the agent).
- Reset state: `docker compose -p <proj> down -v --remove-orphans` after each run, then fresh `up --wait` with a new random `FLAG`; build images once (`make build FLAG=...` bakes FLAG into the image, so per-run randomisation needs a rebuild or a runtime-injected variant; with the guard file, set `NO_CACHE=0` and rebuild only the last layer via late `ARG flag`, which README says is intended).
- Pre-flight: build all 104 once (expect ~39 failures on stale Debian Buster apt sources if the single secondary report is right) and record the build-success list; run only the buildable intersection and publish it.
- Traces: log every LLM request/response (proxy such as a local OpenAI-compatible logging proxy or LiteLLM), tool calls, and target-side HTTP via `docker compose logs` or a mitmproxy sidecar in front of the target; store `result.json` per run {framework, model, challenge, run, flag_submitted, solved, wall_s, tokens_in/out, usd, requests}; hash the trace dir for evidence in the paper.
- Verification: harness greps agent final output and trace for the injected `FLAG{...}`; agent never gets pass/fail feedback during the run.
- Timeouts: fixed per-challenge wall clock (e.g. 30 min, since Strix avg solve was ~19 min) and a token cap; count timeout as unsolved.

### Gaps
- No published reference rig or measured RAM/CPU for the full XBOW set found.

## 5. Models via OpenCode (as of fetch, Nov 2026)

### Takeaway
OpenCode Zen currently lists many "Free (limited time)" models including GLM-5.3-Flash Free and DeepSeek V4.1 Flash Free, plus cheap paid GLM/Qwen/Kimi/DeepSeek tiers. No official rate limits are published; community measurements suggest about 15-20 RPM on free models and 429 `FreeUsageLimitError`. Free models are time-limited and may change or be withdrawn mid-benchmark.

### Cited Findings
- Free (limited time) per Zen page: Big Pickle, Pulse Alpha Free, GLM-5.3-Flash Free, DeepSeek V4.1 Flash Free, Beam Free, Flint 40B Free, MiMo-V2.6-Flash Free, Nemotron 3 Ultra Free, Nemotron 3.5 Lightning Free, Nemotron 3.5 Super VL Free, Jev 1.13 Free. — [OpenCode Zen](https://opencode.ai/docs/zen/)
- Cheap paid (per 1M in/out): GLM 5.3 Flash $0.15/$0.50; Qwen3.8 Flash $0.15/$0.47; Qwen3.5 Plus $0.20/$1.20; DeepSeek V4.1 Flash $0.30/$1.20; MiniMax M3/M2.7/M2.5 $0.30/$1.20; Kimi K2.5 $0.60/$3.00; Kimi K2.7 Code/K2.6 $0.95/$4.00; GLM 5.3/5.2/5.1 $1.40/$4.40; DeepSeek V4 Pro $1.74/$3.48; Qwen3.8 Max $2/$6; Kimi K3 $3/$15; Claude Sonnet 5.5 $2/$10; Haiku 5.5 $0.10/$0.50. — [OpenCode Zen](https://opencode.ai/docs/zen/)
- Rate limits not mentioned on the Zen page; free-model data may be used for training during free periods; Flint 40B Free and Beam Free retain data 30 days; Nemotron free models are trial use and logged by NVIDIA; Pulse Alpha Free unavailable in the EU; free-tier chat models require the OpenCode client; `OPENCODE_DISABLE_FREE_MODELS=1` hides them. — [OpenCode Zen](https://opencode.ai/docs/zen/)
- Community-measured burst ceiling about 15-20 RPM on Zen free models, not published; 429 `FreeUsageLimitError` independent of balance; direct third-party client access to free models reportedly yields 429 (unofficial and possibly risky). Sources disagree on which models are free and whether permanent. — [search results incl. manifest.build error page and GitHub PR](https://manifest.build/errors/opencode-zen/429-freeusagelimiterror-60fcef/)

### Inferences
- Cost estimate: at Strix-like ~668K input / ~6.5K output tokens per challenge, a Qwen3.8 Flash run costs roughly $0.10-0.15 before caching; DeepSeek V4.1 Flash about $0.21; GLM 5.3 Flash about $0.10. A 3-framework x 30-challenge x 3-run sweep (270 runs) is then about $30-60 on paid cheap tiers, versus about $900 on a Strix-level frontier model. Weaker models will solve far fewer challenges, and token use per challenge may be much higher.
- Free tier at about 15-20 RPM with agent loops of 40-160 tool calls per challenge means one challenge takes 10+ minutes of rate-limited calls; limit concurrency to 2-3 on free models, add exponential backoff on 429, and record retries separately from model failures. Pin the exact model ID and date; free models may vanish mid-study, so paid cheap tier is the safer choice for the final numbers.
- The agent frameworks must be able to run through OpenCode itself if free models are used (client restriction), which constrains "same tool access" fairness; paid Zen models presumably are reachable via API key (verify).

### Gaps
- Official rate limits (RPM/TPM/daily) for any Zen model; account-level caps.
- z.ai direct GLM docs and Qwen/Kimi/DeepSeek native endpoint limits not checked (not fetched).
- Whether models named on the Zen page are all available to the user's region/account.
