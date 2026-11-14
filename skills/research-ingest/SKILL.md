---
name: research-ingest
description: Research a web security topic (a CVE, a technique, a new tool, a bug class) and save a concise, citable note into the Mythos knowledge base that the agents read at runtime. Use when asked to research a topic or to update the knowledge base with new techniques or papers, outside an engagement run.
---

# Research ingest

Turn a research question into a durable knowledge note the Mythos agents consult
during engagements. Keep notes short, concrete and sourced.

## Steps

1. **Scope the question.** One topic per note: a bug class (e.g. "prototype
   pollution"), a CVE, a technique (e.g. "JWT alg confusion"), or a tool.

2. **Gather from high-trust sources.** Prefer primary sources: vendor advisories,
   the tool's own docs, OWASP, PortSwigger Web Security Academy, the CVE record,
   original research write-ups. Use web search / Context7 for tool docs. Note
   the date — techniques age.

3. **Write the note** to the right folder:
   - `knowledge/web/` — web bug classes and how to detect/confirm them.
   - `knowledge/network/` — network/service techniques.
   - `knowledge/techniques/` — cross-cutting methodology, chaining, evasion-free
     validation.

   Use this shape:

   ```markdown
   # <Topic>

   **Class:** <bug class> **Updated:** <YYYY-MM-DD>

   ## What it is

   One paragraph.

   ## How Mythos detects it

   Concrete signals the tools look for; which tool/check applies.

   ## How to confirm (non-destructive)

   Minimal PoC that proves it without damage.

   ## Remediation

   What the fix is.

   ## Sources

   - <url> (<date>)
   ```

4. **Keep it runtime-useful.** The scanner and exploiter read these to cut false
   positives and to pick confirmation steps. Write for that use, not as an essay.

5. **Index it.** Add a one-line pointer to `knowledge/README.md`.

Do not paste large copyrighted text; summarize and cite. One fact per note.
