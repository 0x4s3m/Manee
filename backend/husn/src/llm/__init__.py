"""Shared LLM client. DeepSeek-via-OpenAI-SDK by default, swappable.

Used by:
  * chatbot — interactive SOC analyst
  * auto_reports — daily / weekly natural-language summaries
  * investigate — per-IP situational summaries

Configure with:
    HUSN_DEEPSEEK_KEY=sk-...        (env var, never on disk)

Or in /etc/husn/config.yml:
    llm:
      provider: deepseek            # or 'openai' for vanilla OpenAI
      model: deepseek-chat          # or deepseek-reasoner for harder problems
      api_key_env: HUSN_DEEPSEEK_KEY
      base_url: https://api.deepseek.com
      max_tokens: 1024
      temperature: 0.4
"""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("husn.llm")

DEFAULT_PROVIDER = "deepseek"
DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"
DEFAULT_MAX_TOKENS = 1024
DEFAULT_TEMPERATURE = 0.4


def _cfg() -> dict[str, Any]:
    from husn.src import config
    return config.get("llm", {}) or {}


def api_key() -> str:
    """Resolved at call time — picks up env-var changes without restart."""
    return _cfg().get("api_key") or ""


def model() -> str:
    return _cfg().get("model") or DEFAULT_MODEL


def base_url() -> str:
    return _cfg().get("base_url") or DEFAULT_BASE_URL


def max_tokens() -> int:
    return int(_cfg().get("max_tokens") or DEFAULT_MAX_TOKENS)


def temperature() -> float:
    return float(_cfg().get("temperature", DEFAULT_TEMPERATURE))


def is_configured() -> bool:
    return bool(api_key())


def complete(
    system: str,
    messages: list[dict[str, str]],
    temperature_override: float | None = None,
    max_tokens_override: int | None = None,
) -> dict[str, Any]:
    """Single completion call. Returns {ok, reply, error, model, usage}.

    `messages` is a list of {role: 'user'|'assistant', content: str}.
    `system` is the system prompt (sent as the first 'system' message)."""
    if not is_configured():
        return {
            "ok": False, "reply": "", "error":
            "LLM is not configured. Set HUSN_DEEPSEEK_KEY in the environment "
            "(systemd drop-in for husn-backend), then restart the backend."
        }
    try:
        from openai import OpenAI
    except ImportError:
        return {"ok": False, "reply": "", "error": "openai SDK not installed"}

    try:
        client = OpenAI(api_key=api_key(), base_url=base_url())
        resp = client.chat.completions.create(
            model=model(),
            max_tokens=max_tokens_override or max_tokens(),
            temperature=temperature_override if temperature_override is not None else temperature(),
            messages=[{"role": "system", "content": system}, *messages],
        )
        choice = resp.choices[0]
        reply = (choice.message.content or "").strip()
        return {
            "ok": True, "reply": reply,
            "model": model(),
            "usage": {
                "input_tokens": getattr(resp.usage, "prompt_tokens", 0),
                "output_tokens": getattr(resp.usage, "completion_tokens", 0),
            },
        }
    except Exception as exc:
        log.exception("[llm] completion failed")
        return {"ok": False, "reply": "", "error": str(exc)}
