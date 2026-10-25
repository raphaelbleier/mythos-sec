"""Pluggable LLM backends for the Mythos agent.

  * ClaudeCLIBackend  — shells out to the `claude` CLI (`claude -p ... --model m`).
    Uses the machine's existing Claude Code auth; no API key required.
  * AnthropicBackend  — the Anthropic Messages API (needs ANTHROPIC_API_KEY),
    for parity with CAI/Strix when a key is available.

Both expose complete(system, prompt) -> str. The agent drives a text ReAct
protocol, so a plain completion string is all that is needed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess


class LLMError(RuntimeError):
    pass


class ClaudeCLIBackend:
    name = "claude-cli"

    def __init__(self, model: str = "claude-opus-4-8", timeout: int = 180):
        self.model = model
        self.timeout = timeout
        if not shutil.which("claude"):
            raise LLMError("`claude` CLI not found on PATH")

    def complete(self, system: str, prompt: str) -> str:
        cmd = ["claude", "-p", prompt, "--model", self.model,
               "--append-system-prompt", system, "--output-format", "text"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            raise LLMError(f"claude CLI timed out after {self.timeout}s") from exc
        if proc.returncode != 0:
            raise LLMError(f"claude CLI failed: {proc.stderr.strip()[:200]}")
        return proc.stdout.strip()


class AnthropicBackend:
    name = "anthropic-api"

    def __init__(self, model: str = "claude-opus-4-8", timeout: int = 180):
        self.model = model
        self.timeout = timeout
        self.key = os.environ.get("ANTHROPIC_API_KEY")
        if not self.key:
            raise LLMError("ANTHROPIC_API_KEY not set")

    def complete(self, system: str, prompt: str) -> str:
        import urllib.request
        body = json.dumps({
            "model": self.model, "max_tokens": 2048, "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=body,
            headers={"x-api-key": self.key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except Exception as exc:
            raise LLMError(f"anthropic API error: {exc}") from exc
        return "".join(b.get("text", "") for b in data.get("content", []))


class LiteLLMBackend:
    """Any provider via LiteLLM (like Strix): OpenAI, Anthropic, Gemini, Azure,
    local Ollama/vLLM, etc. Model string selects the provider, e.g.
    'gpt-4o', 'anthropic/claude-opus-4-8', 'ollama/llama3', 'gemini/gemini-2.5-pro'.
    Needs `pip install litellm` and that provider's key in the environment
    (none for local Ollama). Lets anyone plug in their own provider."""
    name = "litellm"

    def __init__(self, model: str, timeout: int = 180):
        self.model = model
        self.timeout = timeout
        try:
            import litellm  # noqa: F401
        except Exception as exc:
            raise LLMError("litellm not installed (pip install litellm)") from exc

    def complete(self, system: str, prompt: str) -> str:
        import litellm
        try:
            resp = litellm.completion(
                model=self.model, timeout=self.timeout, max_tokens=2048,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": prompt}])
        except Exception as exc:
            raise LLMError(f"litellm error: {exc}") from exc
        return resp["choices"][0]["message"]["content"] or ""


def get_backend(name: str, model: str):
    # Default: claude CLI (no API key, uses Claude Code auth).
    if name in ("claude-cli", "cli", "auto"):
        try:
            return ClaudeCLIBackend(model=model)
        except LLMError:
            if name == "auto":
                try:
                    return LiteLLMBackend(model=model)
                except LLMError:
                    return AnthropicBackend(model=model)
            raise
    if name in ("litellm", "any"):
        return LiteLLMBackend(model=model)
    if name in ("anthropic", "api"):
        return AnthropicBackend(model=model)
    raise LLMError(f"unknown backend {name!r}")
