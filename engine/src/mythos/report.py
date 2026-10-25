"""Render findings to bug-bounty Markdown and a short summary.

The per-finding format matches what HackerOne / Bugcrowd / Intigriti expect:
title, severity + CVSS, affected asset, steps to reproduce, evidence, impact,
remediation. The German .docx lab report is produced separately by the
security-lab skill, which consumes findings.json.
"""

from __future__ import annotations

from datetime import date

from .findings import FindingStore, Severity

_SEV_EMOJI = {
    Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵", Severity.INFO: "⚪",
}


def render_summary(target: str, store: FindingStore) -> str:
    c = store.counts()
    return (f"Mythos scan of {target}\n"
            f"critical={c['critical']} high={c['high']} medium={c['medium']} "
            f"low={c['low']} info={c['info']} total={len(store)}\n")


def render_markdown(target: str, store: FindingStore, data: dict | None = None) -> str:
    data = data or {}
    c = store.counts()
    lines: list[str] = []
    lines.append(f"# Mythos Engagement Report — {target}")
    lines.append("")
    lines.append(f"_Generated {date.today().isoformat()} by mythos-sec. "
                 "For authorized testing only._")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {sev.capitalize()} | {c[sev]} |")
    lines.append(f"| **Total** | **{len(store)}** |")
    lines.append("")

    fp = data.get("fingerprint") or {}
    if fp:
        techs = ", ".join(fp.get("technologies") or []) or "n/a"
        lines.append(f"**Server:** {fp.get('server') or 'n/a'}  ")
        lines.append(f"**Technologies:** {techs}  ")
        if fp.get("waf"):
            lines.append(f"**WAF:** {fp['waf']}  ")
        lines.append("")
    tools = [t for t, ok in (data.get("tools_used") or {}).items() if ok]
    if tools:
        lines.append(f"**Tools available:** {', '.join(tools)}")
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not len(store):
        lines.append("_No findings._")
        return "\n".join(lines)

    for i, f in enumerate(store.findings, 1):
        emoji = _SEV_EMOJI[f.severity]
        lines.append(f"### {i}. {emoji} {f.title}")
        lines.append("")
        lines.append(f"- **Severity:** {f.severity.value.capitalize()}"
                     + (f" (`{f.cvss}`)" if f.cvss else ""))
        lines.append(f"- **Asset:** {f.url}")
        if f.param:
            lines.append(f"- **Parameter:** `{f.param}`")
        lines.append(f"- **Confidence:** {f.confidence}")
        lines.append(f"- **Source:** {f.source}")
        lines.append("")
        if f.description:
            lines.append(f.description)
            lines.append("")
        if f.payload:
            lines.append("**Payload / Steps to reproduce:**")
            lines.append("")
            lines.append("```")
            lines.append(f.payload)
            lines.append("```")
            lines.append("")
        if f.evidence and (f.evidence.request or f.evidence.response or f.evidence.matched):
            lines.append("**Evidence:**")
            lines.append("")
            lines.append("```http")
            if f.evidence.request:
                lines.append(f.evidence.request.strip())
            if f.evidence.response:
                lines.append("---")
                lines.append(f.evidence.response.strip()[:800])
            if f.evidence.matched:
                lines.append(f"[matched] {f.evidence.matched}")
            lines.append("```")
            lines.append("")
        if f.impact:
            lines.append(f"**Impact:** {f.impact}")
            lines.append("")
        if f.remediation:
            lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")
        if f.references:
            lines.append("**References:** " + ", ".join(f.references[:5]))
            lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)
