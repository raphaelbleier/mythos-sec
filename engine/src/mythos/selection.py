"""Tool selection intelligence.

A target-type and technology-driven tool-priority table, in the spirit of
HexStrike's IntelligentDecisionEngine but transparent and editable. Given a
fingerprint, it returns the ordered list of external tools worth running, so
the scanner spends time on what matters for this stack.
"""

from __future__ import annotations

# base priority per target type (higher = run earlier / more important)
WEB_TOOLS = [
    ("nuclei", 0.95), ("dalfox", 0.90), ("sqlmap", 0.88), ("ffuf", 0.80),
    ("katana", 0.78), ("httpx", 0.75), ("arjun", 0.72), ("nikto", 0.65),
    ("wafw00f", 0.60), ("whatweb", 0.55), ("commix", 0.70), ("jwt_tool", 0.60),
    ("graphw00f", 0.55), ("wpscan", 0.50), ("testssl.sh", 0.45),
]
API_TOOLS = [
    ("nuclei", 0.92), ("arjun", 0.85), ("jwt_tool", 0.80), ("graphw00f", 0.78),
    ("sqlmap", 0.75), ("ffuf", 0.70), ("dalfox", 0.60),
]
NETWORK_TOOLS = [
    ("nmap", 0.95), ("naabu", 0.85), ("masscan", 0.70), ("subfinder", 0.80),
    ("httpx", 0.75), ("amass", 0.60),
]

# technology -> tools that become more relevant
TECH_BOOST = {
    "WordPress": ["wpscan"],
    "Drupal": ["nuclei"],
    "Joomla": ["nuclei"],
    "PHP": ["sqlmap", "commix"],
    "GraphQL": ["graphw00f", "nuclei"],
    "Swagger/OpenAPI": ["arjun", "nuclei"],
    "Java/Servlet": ["nuclei"],
    "ASP.NET": ["nuclei"],
}


def classify(fingerprint: dict) -> str:
    """Return 'api' | 'web' from a fingerprint dict."""
    techs = set(fingerprint.get("technologies") or [])
    title = (fingerprint.get("title") or "").lower()
    if {"GraphQL", "Swagger/OpenAPI"} & techs or "api" in title:
        return "api"
    return "web"


def select_tools(fingerprint: dict, available: dict[str, bool],
                 target_type: str | None = None) -> list[str]:
    """Ordered, de-duplicated list of available tools worth running."""
    ttype = target_type or classify(fingerprint)
    base = {"api": API_TOOLS, "network": NETWORK_TOOLS}.get(ttype, WEB_TOOLS)
    scores: dict[str, float] = {name: score for name, score in base}
    for tech in fingerprint.get("technologies") or []:
        for tool in TECH_BOOST.get(tech, []):
            scores[tool] = scores.get(tool, 0.5) + 0.05
    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    return [name for name, _ in ranked if available.get(name)]
