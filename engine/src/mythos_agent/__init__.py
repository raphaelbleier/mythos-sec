"""Mythos autonomous agent runtime.

A standalone LLM-driven pentest agent (in the spirit of CAI / Strix / PentestGPT):
an LLM reasons in a ReAct loop, choosing tools from a registry that wraps the
Mythos engine (scope-aware HTTP, recon, vulnerability checks) and the Kali
toolbox. Unlike the Claude Code plugin agents, this runs on its own:

    mythos-agent https://target --scope scope.yaml --model claude-opus-4-8

Model backends are pluggable: the `claude` CLI (uses existing Claude Code auth,
no API key) or the Anthropic API (ANTHROPIC_API_KEY). For authorized testing only.
"""

__version__ = "0.1.0"
