# AI-app and agentic attack surface: what a 2026 red-team framework must test (as of 2026-11-14)

Scope note: research budget was about 20 tool calls. Primary sources fetched: OWASP GenAI Top 10 page, MCP 2025-11-25 security best practices, arXiv abstract 2510.09023. Everything else is from search snippets (secondary) and is marked as such. Repo state was read from /home/bleier/Documents/Programming/mythos-sec (skills/ai-app/SKILL.md, knowledge/web/llm-*.md, knowledge/web/mcp-security.md).

## 1. Prompt injection taxonomy, OWASP lists, defence bypass rates

### Takeaway
LLM01 prompt injection is still rank 1 on the only OWASP LLM list the primary page shows (2025 edition). Several secondary sources describe a "2026 edition" with different ranks, but I could not confirm it at owasp.org. Static defences measured against adaptive attackers fail at over 90% for most of 12 tested; only architectural designs (CaMeL) give a guarantee, at a utility cost.

### Cited Findings
- The OWASP GenAI page lists the 2025 edition: LLM01 Prompt Injection, 02 Sensitive Information Disclosure, 03 Supply Chain, 04 Data and Model Poisoning, 05 Improper Output Handling, 06 Excessive Agency, 07 System Prompt Leakage, 08 Vector and Embedding Weaknesses, 09 Misinformation, 10 Unbounded Consumption. The page describes no 2026 update to the Top 10. — [OWASP GenAI Top 10](https://genai.owasp.org/llm-top-10/)
- Secondary sources (vendor blogs) claim a "2026 edition" in which excessive agency moves 6th to 3rd, System Prompt Leakage becomes "Hidden Context Exposure", Improper Output Handling falls 5th to 10th, Unbounded Consumption rises to 6th. Sources disagree on ranks; unverified against owasp.org. — [CSA blog 2026-10-21](https://cloudsecurityalliance.org/blog/2026/10/21/the-owasp-top-10-for-llm-applications-2026-what-changed-and-why-it-matters), [Security Boulevard 2026-11](https://securityboulevard.com/2026/11/owasp-top-10-for-llm-applications-2026-mapped-to-controls/); contradicted for existence of an official 2026 list by [OWASP GenAI page](https://genai.owasp.org/llm-top-10/)
- OWASP Top 10 for Agentic Applications 2026 (ASI01 Agent Goal Hijack through ASI10 Rogue Agents; includes Tool Misuse, Identity and Privilege Abuse, Supply Chain, Unexpected Code Execution, memory poisoning, inter-agent communication, cascading failures, human-agent trust exploitation), published December 2025. — [Cycode summary](https://cycode.com/blog/owasp-top-10-agentic-applications/), [deepteam mapping](https://www.trydeepteam.com/docs/frameworks-owasp-top-10-for-agentic-applications)
- "The Attacker Moves Second" (Nasr, Carlini, Sitawarin, Schulhoff et al., 2025-10-10): 12 recent defenses (prompting, adversarial training, filtering, secret-knowledge) bypassed with adaptive attacks (gradient descent, RL, random search, human-guided exploration); ASR above 90% for most, while most had reported near-zero ASR. — [arXiv 2510.09023](https://arxiv.org/abs/2510.09023)
- Original AgentDojo: attacks succeed against the best agents in under 25% of cases; with a secondary detector 8%. — [AgentDojo, arXiv 2406.13352](https://arxiv.org/pdf/2406.13352)
- Adaptive attacks are less effective on AgentDojo than on InjecAgent (all adaptive ASR above 50% on InjecAgent), attributed to AgentDojo's longer contexts; eight defenses consistently bypassed above 50%. — [arXiv 2503.00061](https://arxiv.org/pdf/2503.00061)
- AutoDojo (2026) argues one aggregate ASR measures robustness to a frozen attack, not an adaptive adversary, and finds system-level defenses still give some protection. — [HF paper 2606.15057](https://huggingface.co/papers/2606.15057)
- One 2026 defence paper claims AgentDojo, InjecAgent and Agent Security Bench have flawed success metrics, bugs and weak attacks; its own ~0% ASR claim is the authors' and unreplicated. — [arXiv 2603.15714](https://arxiv.org/pdf/2603.15714)
- CaMeL (Google/DeepMind, "Defeating Prompt Injections by Design"): control/data-flow separation plus a custom interpreter with capabilities; 77% of AgentDojo tasks with provable security vs 84% undefended (v2; a 67% figure appears in other summaries, version/backbone unclear). — [arXiv 2503.18813](https://arxiv.org/pdf/2503.18813)
- Browser-agent hijack: Brave showed hidden page text steering Perplexity Comet (2025-08) and screenshot-embedded text (2025-10); LayerX "CometJacking"; UW paper (Roesner, Kohlbrenner, 2026) shows a PoC against ChatGPT Atlas on same-origin-policy interaction and says the preconditions exist for Chrome with Gemini, Claude for Chrome, Comet. A defender blog dated 2026-08-07 says Atlas, Comet and Edge Copilot remain injectable after patching (secondary). — [UW PDF](https://homes.cs.washington.edu/~franzi/pdf/roesner_kohlbrenner_2026_agentic_sop.pdf), [ppc.land on Comet](https://ppc.land/comet-browser-faces-multiple-security-vulnerabilities-from-prompt-injection/), [Security Arsenal](https://securityarsenal.com/blog/ai-browser-prompt-injection-why-openai-atlas-perplexity-comet-and-copilot-still-leak-and-how-to-defend-your-enterprise)

### Inferences
- A black-box web target will almost always have an input/output classifier or prompt hardening; per the adaptive-attack results, "the filter blocked my 5 payloads" is not evidence of safety. The framework needs payload mutation per target (carrier format x framing x encoding), reported as rate per variant.
- Mythos' `knowledge/web/llm-prompt-injection.md` already cites Willison's trifecta, Brave Comet, tag-character smuggling. It does not cite the adaptive-attack literature, so nothing in the repo tells the agent to adapt after a block.
- AIRTBench and OWASP-test benchmarks are of limited use as scoring for a live-target tool; they matter for regression-testing Mythos' own agent (see gaps).

### Gaps
- Official OWASP 2026 LLM list: not confirmed; need owasp.org primary check.
- AIRTBench results: search returned nothing.
- The 12 defenses named in the Attacker Moves Second paper: abstract page does not list them; full PDF not read.
- Per-vector measured rates (RAG docs, images, filenames, HTML comments, email) beyond Brave's Comet demos: not found as measured numbers.

## 2. Agentic surface: tools, MCP, A2A, computer use

### Takeaway
The MCP spec (2025-11-25) names concrete, testable attack classes: confused-deputy OAuth proxies, token passthrough, SSRF in OAuth discovery, session hijack, local-server compromise, javascript:/shell URL handling, scope inflation. Mythos already has a `knowledge/web/mcp-security.md` covering most of them; the user's gap statement "no MCP-specific playbook" is partly wrong. The missing pieces are tool-poisoning/rug-pull diffing, client-side targets, and ecosystem CVEs.

### Cited Findings
- Spec requirements (all from the 2025-11-25 page): proxy servers MUST implement per-client consent before the third-party flow, with consent cookies `__Host-` prefixed, signed, bound to client_id; exact-string redirect_uri match; `state` stored only after consent approval, single-use, ~10 min; MCP servers MUST NOT accept tokens not issued for them (token passthrough forbidden); MCP servers MUST NOT use sessions for authentication and MUST use non-deterministic session IDs; clients MUST reject `javascript:`, `data:`, `file:`, `vbscript:` authorization URLs and MUST NOT open URLs via a shell; clients SHOULD block private/link-local ranges in OAuth discovery (SSRF), validate redirect hops, consider egress proxies; scope minimization (no omnibus scopes, incremental `WWW-Authenticate scope=` challenges). — [MCP security best practices 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)
- Session-hijack prompt injection variant: attacker uses a guessed/obtained session ID against server B in a multi-node deployment; event is queued and delivered to the victim client via SSE/resumed stream (including `notifications/tools/list_changed` to add tools). — same spec page
- Ecosystem CVEs: MCP Inspector CVE-2025-49596 (CVSS 9.4, no auth between client and proxy, RCE; fixed 0.14.1); mcp-remote CVE-2025-6514 (CVSS 9.6, OS command injection via rogue OAuth server); Anthropic Git MCP server CVE-2025-68143/68144/68145; fake `postmark-mcp` npm package backdoored in 1.0.16 (BCC of emails); MCPJam Inspector CVE-2026-23744 (unauthenticated install of arbitrary servers). Counts like "30 CVEs in 60 days" come from a single blog. — [Tenable CVE-2025-49596](https://www.tenable.com/cve/CVE-2025-49596), [Hacker News mcp-remote](https://thehackernews.com/2025/07/critical-mcp-remote-vulnerability.html), [GovInfoSecurity](https://www.govinfosecurity.com/serious-flaws-patched-in-model-context-protocol-tools-a-28924), [heyuan110 roundup (secondary)](https://heyuan110.com/posts/ai/2026-03-10-mcp-security-2026)
- Tool poisoning, shadowing and rug pulls were named by Invariant Labs 2025-04-01 (as recorded in repo note, not re-fetched). — repo: /home/bleier/Documents/Programming/mythos-sec/knowledge/web/mcp-security.md
- A2A: Agent Card signing is optional (JWS "MAY"); card spoofing, task replay, server impersonation in MAESTRO analysis; ICLR 2026 A2ASecBench reports effective attacks; Keysight added "Agent Card Poisoning" (description-field injection) simulations in March 2026 (vendor, and one forum post doubts public evidence). — [arXiv 2504.16902](https://arxiv.org/pdf/2504.16902), [Keysight](https://keysight.com/blogs/en/tech/nwvs/2026/03/12/agent-card-poisoning), [Grith](https://grith.ai/blog/a2a-protocol-zero-defenses-prompt-injection)

### Inferences
- A remote MCP endpoint in a web bounty scope is testable with the existing table plus (a) a `tools/list` snapshot diff across sessions/time for rug-pull detection, (b) tag-character and instruction scan of every descriptor field, (c) per-tool authz checks via two principals, (d) `Mcp-Session-Id` entropy and cross-user replay, (e) `resources/`, `prompts/` and sampling/elicitation abuse (not covered in the repo note; sampling abuse I found no primary source for).
- Computer-use agents: no primary source gathered in this pass; treat as out of web-target scope unless the programme lists the agent product.

### Gaps
- MCP 2026 spec revisions beyond the draft's "state handle hijacking" wording (repo note says draft differs from 2025-11-25): not independently re-fetched.
- Sampling abuse and elicitation phishing: no primary source found.
- Computer-use agent risks: not researched (budget).
- Measured rug-pull or tool-poisoning success rates against real clients: not found.

## 3. Infrastructure of AI apps as targets

### Takeaway
Real exploited bugs are classic web bugs in AI builders and exposed unauthenticated model servers; exposure counts are large. The repo's ai-app section 5 lists Langflow and Flowise only; n8n, Ollama/vLLM exposure, vector DBs, gateways, pickle, Gradio, Jupyter are missing.

### Cited Findings
- n8n "Ni8mare" CVE-2026-21858: CVSS 10.0, unauthenticated file read via Content-Type confusion on webhook, chains to RCE; affects 1.65.0 to below 1.121.0; Shadowserver counted over 24,700 unpatched exposed instances in Feb 2026; Horizon3 reported no impacted customer instances, others claim exploitation (conflict). Related CVE-2025-68613, CVE-2026-21877 (fixed 1.121.3). — [Censys advisory](https://censys.com/advisory/cve-2026-21858), [Security Affairs](https://securityaffairs.com/186648/security/ni8mare-flaw-gives-unauthenticated-control-of-n8n-instances.html), [Horizon3](https://horizon3.ai/attack-research/attack-blogs/the-ni8mare-test-n8n-rce-under-the-microscope-cve-2026-21858/), [CSA note](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_n8n_rce_ai_pipeline_attack_surface_20260312-csa-styled.pdf)
- Ollama exposure: Cisco found 1,100+ via Shodan (about 20% hosting reachable models); SentinelLABS with Censys (2026-01) reported 175,000 hosts in 130 countries; a criminal service scans for unauthenticated Ollama, vLLM and OpenAI-compatible APIs and resells compute. Default ports 11434 (Ollama), 8080 (vLLM), 5000 (TGI) per a forum post (weak). — [Cisco](https://blogs.cisco.com/security/detecting-exposed-llm-servers-shodan-case-study-on-ollama), [Hacker News 2026-01](https://thehackernews.com/2026/01/researchers-find-175000-publicly.html)
- Unbounded Consumption (LLM10:2025) covers denial-of-wallet; leaked keys and uncapped agent loops are the usual path; hard per-key budgets recommended over alerts. — [OWASP LLM10](https://genai.owasp.org/llmrisk/llm10), [Prompt Security](https://prompt.security/blog/denial-of-wallet-in-ai)
- Langflow CVE-2026-33017, CVE-2026-5027 and Flowise CVE-2025-59528 are already in the repo skill with dates (not re-verified here). — repo: skills/ai-app/SKILL.md

### Inferences
- A non-destructive denial-of-wallet check is "is there a per-user/per-key cap": measure the largest accepted input/`max_tokens`, absence of rate-limit headers, and recursion limits on own account with a small bounded spend budget; never run flood tests. Cost counts against `rules.max_requests`.
- Vector DB checks (unauthenticated Chroma/Qdrant/Weaviate/Milvus REST, collection listing, cross-tenant namespace filter bypass via client-supplied filter) are testable with an own-planted canary; no source found for exposure statistics.

### Gaps
- Dify, vLLM, Triton CVEs: search returned nothing; unconfirmed.
- Vector DB exposure reports, embedding inversion measured results: no source found.
- Pickle/model-file deserialization (HF, torch.load), Gradio/Streamlit, Jupyter exposures, AI gateways (LiteLLM etc.): not researched.

## 4. Output handling
### Takeaway
Repo note `knowledge/web/llm-output-handling.md` already tabulates sinks (raw HTML/SVG, markdown image exfil, link unfurl, agent SQL, model-emitted URLs, code interpreter) and cites EchoLeak. I did not research this area further.
### Cited Findings
- Interpreter checks use a no-op marker and an OAST DNS lookup, never filesystem pivots. — repo: knowledge/web/llm-output-handling.md line 19
### Inferences
- Missing in repo: sandbox-escape/egress characterization for code interpreters (metadata endpoint reach, DNS egress as OAST), CSP-aware exfil (which image/connect hosts the UI allows), streaming-render XSS (partial markdown).
### Gaps
- No fresh 2026 primary sources gathered for this section.

## 5. Methodology, tooling, statistics

### Takeaway
garak, PyRIT and promptfoo are model/prompt-level scanners; none was described as a full MCP/agent scanner. They give candidates, not proof. The repo's nonce/OAST/control/k method is the defensible part; what is missing is a confidence interval, adaptive mutation, and tool integration.

### Cited Findings
- garak: model-level probes (120+ modules per one source, 37+ per another); does not test RAG pipelines, agent workflows or MCP integrations; multi-turn agentic attacks reported added in v0.15.0 (May 2026, secondary). PyRIT: orchestrator for custom multi-turn and multimodal campaigns. Promptfoo: eval plus red-team (50+ vulnerability types), reportedly acquired by OpenAI on 2026-03-09, core still MIT (secondary). — [appsecsanta](https://appsecsanta.com/ai-security-tools/llm-red-teaming), [Giskard 2026](https://www.giskard.ai/knowledge/best-ai-agent-red-teaming-tools-in-2026-understanding-features-functions-and-solutions), [promptfoo vs garak](https://www.promptfoo.dev/blog/promptfoo-vs-garak/)
- AI-Infra-Guard is listed as scanning self-hosted agents, MCP, skills and infrastructure (single roundup, vendor-adjacent). — [appsecsanta](https://appsecsanta.com/ai-security-tools/llm-red-teaming)
- Existing repo oracle: per-trial nonce, OAST hit, control arm, interleaved arms, k <= 10; verdict `reproduced` at n/k >= 0.5 with control 0/k. — repo: skills/ai-app/SKILL.md

### Inferences
- Statistics: with k = 10, a 5/10 observation has a 95% Wilson interval of roughly 24% to 76%; control 0/10 only bounds the control rate below ~31% (rule of three, 95%). k <= 10 supports "reproducible" claims only coarsely; report Wilson/Clopper-Pearson bounds, and for a bar like OpenAI's 50% pass use a lower-bound rule or raise k when budget allows. This is my arithmetic, not from a source.
- Adaptive loop: after a 0/k, mutate framing/encoding/carrier and rerun, keeping each variant's own control; cap total spend. This operationalizes Attacker Moves Second without gradient access.
- garak/PyRIT/promptfoo are useful as payload generators/wrappers pointed at the chat endpoint to produce candidates, which then pass the nonce runner; their own pass/fail judgments (LLM judge or string match) must never count as proof.

### Gaps
- No official release notes for garak/PyRIT/promptfoo 2026; version-specific claims secondary.
- Burp AI extensions and agentic red-team harness comparisons: not researched.

## 6. Bounty acceptance and evidence

### Takeaway
Programmes pay indirect injection with real cross-user effect and reject jailbreaks and self-injection. The repo already encodes this; evidence a triager wants is victim-account state change plus reproducibility.

### Cited Findings
- Google AI VRP (launched 2025-10-07): direct prompt injection, jailbreaks and alignment issues out of scope; "rogue actions" (modify victim account/data with clear security impact, e.g. indirect injection making an AI forward email) pay up to $20,000 in flagship products, $15,000 standard, $10,000 other; $30,000 ceiling for high-quality novel reports; also in scope: persistent cross-user HTML injection on Google-branded sites, model theft of full parameters. No 2026 changes found; current rules page not opened. — [The Register](https://www.theregister.com/2025/10/07/google_ai_bug_bounty/), [SecurityWeek](https://www.securityweek.com/google-offers-up-to-20000-in-new-ai-bug-bounty-program/)
- OpenAI Safety Bug Bounty (launched 2026-03-25, Bugcrowd): third-party prompt injection and data exfiltration hijacking Browser/ChatGPT Agent in scope, must reproduce at least 50% of the time; jailbreaks and content-policy bypasses without safety impact out; access-control issues go to the Security Bug Bounty. Rules page not opened (secondary coverage; the repo note records a 403). — [OpenAI announcement](https://openai.com/index/safety-bug-bounty), [SecurityBrief UK](https://securitybrief.co.uk/story/openai-launches-safety-bug-bounty-for-ai-abuse-risks)

### Inferences
- A defensible report: trifecta worksheet, vector reachable without victim cooperation, nonce OAST log lines, attack n/k with confidence bounds, control 0/k, victim-principal state change, model/version and date (behaviour drifts), no real third-party data. Matches the repo's `reproduced`/`validated` states.
- Anthropic, Microsoft (Copilot/Zero Day Quest), Meta and HackerOne/Bugcrowd AI-program policies were not checked.

### Gaps
- Anthropic, Microsoft, Meta, Bugcrowd/HackerOne AI scope policies: not researched.
- Current (Nov 2026) Google and OpenAI rule text: not read at the source.

## Gap list vs. Mythos (confirmed and extended)

Repo already has: ai-app skill (nonce/OAST/control/k runner, trifecta worksheet, recon routes), four knowledge notes (prompt injection, output handling, agent tools, MCP security incl. OAuth-proxy table and tool-poisoning scan), Langflow/Flowise CVE table.

Correction to the brief: an MCP playbook exists (knowledge/web/mcp-security.md); what is missing is depth, listed below.
