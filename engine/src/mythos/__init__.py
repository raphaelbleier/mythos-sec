"""Mythos web red-team engine.

A scope-aware HTTP reconnaissance and vulnerability-probing engine designed to
run against any web application. Pure-Python core (no external binaries
required); optionally orchestrates nuclei / ffuf / sqlmap / nmap / projectdiscovery
tools when they are present on PATH.

Part of the Mythos security framework (mythos-sec). For authorized red-team
engagements and bug-bounty programs only. Every network action is gated by an
engagement scope (see mythos.scope).
"""

__version__ = "0.1.0"
