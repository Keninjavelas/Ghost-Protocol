"""
ai_core/intent_inference.py
Infers attacker intent from command history using the LLM.

Output schema:
{
  "attacker_type": str,
  "primary_objective": str,
  "sophistication_level": str,   // low | medium | high | nation-state
  "confidence": float            // 0.0 – 1.0
}
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import structlog

from ai_core.llm_client import LLMClient

if TYPE_CHECKING:
    from session.session_model import SessionState

log = structlog.get_logger(__name__)

_INTENT_PROMPT_TEMPLATE = """
You are a cyber-behavioral analyst inside a honeypot.

Attacker session context:
- Source IP: {source_ip}
- Username: {username}
- Working directory: {working_directory}
- Command history (most recent last):
{command_history}

Based on these commands, classify the attacker.

Respond ONLY with this exact JSON schema:
{{
  "attacker_type": "<script-kiddie|opportunist|professional|apt|insider>",
  "primary_objective": "<reconnaissance|credential-harvesting|data-exfiltration|persistence|lateral-movement|ransomware|unknown>",
  "sophistication_level": "<low|medium|high|nation-state>",
  "confidence": <0.0-1.0>,
  "reasoning": "<one sentence justification>"
}}
"""


class IntentInferenceEngine:
    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm

    async def infer(self, session_state: "SessionState") -> dict[str, Any]:
        """Classify attacker intent from session command history."""
        history = session_state.command_history[-20:]  # last 20 commands
        history_text = "\n".join(
            f"  [{i+1}] {entry['command']}" for i, entry in enumerate(history)
        )
        if not history_text.strip():
            history_text = "  (no commands yet)"

        prompt = _INTENT_PROMPT_TEMPLATE.format(
            source_ip=session_state.source_ip,
            username=session_state.username,
            working_directory=session_state.working_directory,
            command_history=history_text,
        )

        messages = self._llm.build_messages(session_state.ai_memory, prompt)

        try:
            result = await self._llm.chat(messages, json_mode=True)
            log.info(
                "intent_inferred",
                session_id=str(session_state.session_id),
                attacker_type=result.get("attacker_type"),
                objective=result.get("primary_objective"),
                confidence=result.get("confidence"),
            )
            return result
        except Exception as exc:
            log.warning("intent_inference_error", error=str(exc))
            return {
                "attacker_type": "unknown",
                "primary_objective": "unknown",
                "sophistication_level": "low",
                "confidence": 0.0,
                "reasoning": "inference failed",
            }
