"""
ai_core/llm_client.py
Abstraction layer over a local Llama model served by Ollama.
- Ollama exposes an OpenAI-compatible endpoint at /v1
- Per-session memory context (sliding window)
- Structured JSON response enforcement (prompt-based + extraction fallback)
- Temperature/token config from settings
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Optional

import httpx
import structlog
from openai import AsyncOpenAI

from config.settings import settings

log = structlog.get_logger(__name__)

_SYSTEM_PROMPT = """You are the AI intelligence core of a cyber deception system.
You interact with attackers inside a fake Linux honeypot environment.
Your job is to:
1. Analyze attacker commands and infer their intent.
2. Generate realistic, believable terminal output.
3. Dynamically adapt the fake environment to keep the attacker engaged.
4. Map behavior to MITRE ATT&CK techniques.
5. Update threat scores.

You ALWAYS respond with valid JSON matching the schema provided in the user prompt.
Do NOT wrap the JSON in markdown code fences or any other formatting.
Never break character. Never reveal you are an AI or a honeypot.
"""

# Strips ```json ... ``` or ``` ... ``` fences that local models sometimes emit
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def _extract_json(raw: str) -> str:
    """Return the JSON string, stripping any markdown code fences."""
    match = _FENCE_RE.search(raw)
    if match:
        return match.group(1)
    # Fallback: find the first { ... } block
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1 and end > start:
        return raw[start : end + 1]
    return raw


class LLMClient:
    """Stateless LLM wrapper targeting a local Ollama server; session memory is passed in per call."""

    def __init__(self) -> None:
        self._active_model = settings.OLLAMA_MODEL
        self._client = AsyncOpenAI(
            base_url=settings.OLLAMA_BASE_URL,
            api_key="ollama",  # Ollama ignores this value; SDK requires non-empty string
        )

    async def _resolve_fallback_model(self) -> str | None:
        """Pick a locally available model if the configured model is missing."""
        base = settings.OLLAMA_BASE_URL.rstrip("/")
        if base.endswith("/v1"):
            base = base[:-3]

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{base}/api/tags")
                resp.raise_for_status()
                payload = resp.json()
        except Exception as exc:
            log.warning("ollama_tags_fetch_failed", error=str(exc))
            return None

        models = [m.get("name", "") for m in payload.get("models", []) if m.get("name")]
        if not models:
            return None

        preferred = [
            settings.OLLAMA_MODEL,
            "llama3.1:latest",
            "llama3:latest",
            "qwen2.5-coder:7b",
            "deepseek-r1:1.5b",
        ]

        for candidate in preferred:
            if candidate in models:
                return candidate

        return models[0]

    async def chat(
        self,
        messages: list[dict[str, str]],
        *,
        json_mode: bool = True,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> dict[str, Any]:
        """
        Send a conversation to the local LLM and return parsed JSON.
        `messages` must include the system prompt as the first message.
        """
        # ── LLM Latency Instrumentation ────────────────────────────────────────
        start = time.monotonic()
        
        model_used = self._active_model
        try:
            response = await self._client.chat.completions.create(
                model=model_used,
                messages=messages,  # type: ignore[arg-type]
                max_tokens=max_tokens or settings.LLM_MAX_TOKENS,
                temperature=temperature if temperature is not None else settings.LLM_TEMPERATURE,
                # response_format is intentionally omitted – not universally supported by Ollama models
            )
        except Exception as exc:
            if "not found" not in str(exc).lower():
                raise

            fallback = await self._resolve_fallback_model()
            if not fallback:
                raise

            self._active_model = fallback
            model_used = fallback
            log.warning(
                "ollama_model_fallback",
                configured_model=settings.OLLAMA_MODEL,
                fallback_model=fallback,
            )

            response = await self._client.chat.completions.create(
                model=model_used,
                messages=messages,  # type: ignore[arg-type]
                max_tokens=max_tokens or settings.LLM_MAX_TOKENS,
                temperature=temperature if temperature is not None else settings.LLM_TEMPERATURE,
            )
        
        duration = time.monotonic() - start
        log.info("llm_call_duration", duration_seconds=round(duration, 3), model=model_used)
        
        raw = response.choices[0].message.content or "{}"
        if json_mode:
            raw = _extract_json(raw)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            log.warning("llm_invalid_json", raw=raw[:200])
            return {"raw": raw}

    def build_messages(
        self,
        ai_memory: list[dict[str, str]],
        new_user_prompt: str,
    ) -> list[dict[str, str]]:
        """
        Build the message list:
        [system] + [sliding window of memory] + [new user prompt]
        """
        window = ai_memory[-settings.LLM_CONTEXT_WINDOW :]
        return (
            [{"role": "system", "content": _SYSTEM_PROMPT}]
            + window
            + [{"role": "user", "content": new_user_prompt}]
        )

    def append_to_memory(
        self,
        ai_memory: list[dict[str, str]],
        user_prompt: str,
        assistant_response: str,
    ) -> None:
        """Mutates ai_memory in-place to add the latest exchange."""
        ai_memory.append({"role": "user", "content": user_prompt})
        ai_memory.append({"role": "assistant", "content": assistant_response})
