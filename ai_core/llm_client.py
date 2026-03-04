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
        self._client = AsyncOpenAI(
            base_url=settings.OLLAMA_BASE_URL,
            api_key="ollama",  # Ollama ignores this value; SDK requires non-empty string
        )

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
        
        response = await self._client.chat.completions.create(
            model=settings.OLLAMA_MODEL,
            messages=messages,  # type: ignore[arg-type]
            max_tokens=max_tokens or settings.LLM_MAX_TOKENS,
            temperature=temperature if temperature is not None else settings.LLM_TEMPERATURE,
            # response_format is intentionally omitted – not universally supported by Ollama models
        )
        
        duration = time.monotonic() - start
        log.info("llm_call_duration", duration_seconds=round(duration, 3), model=settings.OLLAMA_MODEL)
        
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
