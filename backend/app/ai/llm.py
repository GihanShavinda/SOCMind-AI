"""Optional LLM client (FR-22 via LLM path).

Disabled by default — the assistant works fully without it (reliability NFR).
Enable by setting env vars (see .env.example):

    LLM_PROVIDER = openai | anthropic | ollama
    LLM_API_KEY  = <key>          (not needed for ollama)
    LLM_MODEL    = gpt-4o-mini | claude-3-5-sonnet-20241022 | llama3
    LLM_BASE_URL = <optional override>

Uses only the Python standard library (urllib) so no extra dependency is added.
On any error or timeout, returns None and the caller falls back to the
deterministic engine. Untrusted log content is passed as data, never as
instructions (injection resistance, FR — prompt safety).
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error

from app.core.config import settings


def is_enabled() -> bool:
    return bool(settings.LLM_PROVIDER)


def _post(url: str, headers: dict, payload: dict) -> dict | None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=settings.LLM_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None


def generate(system: str, user: str) -> str | None:
    """Return the model's text response, or None if disabled/unavailable."""
    provider = settings.LLM_PROVIDER.lower()

    if provider == "openai":
        base = settings.LLM_BASE_URL or "https://api.openai.com/v1"
        out = _post(
            f"{base}/chat/completions",
            {"Authorization": f"Bearer {settings.LLM_API_KEY}",
             "Content-Type": "application/json"},
            {"model": settings.LLM_MODEL,
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": user}],
             "temperature": 0.2},
        )
        if out:
            try:
                return out["choices"][0]["message"]["content"]
            except (KeyError, IndexError):
                return None

    elif provider == "anthropic":
        base = settings.LLM_BASE_URL or "https://api.anthropic.com/v1"
        out = _post(
            f"{base}/messages",
            {"x-api-key": settings.LLM_API_KEY,
             "anthropic-version": "2023-06-01",
             "Content-Type": "application/json"},
            {"model": settings.LLM_MODEL, "max_tokens": 1024,
             "system": system,
             "messages": [{"role": "user", "content": user}]},
        )
        if out:
            try:
                return out["content"][0]["text"]
            except (KeyError, IndexError):
                return None

    elif provider == "ollama":
        base = settings.LLM_BASE_URL or "http://localhost:11434"
        out = _post(
            f"{base}/api/chat",
            {"Content-Type": "application/json"},
            {"model": settings.LLM_MODEL, "stream": False,
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": user}]},
        )
        if out:
            try:
                return out["message"]["content"]
            except KeyError:
                return None

    return None
