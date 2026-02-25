"""
ai_core/mitre_mapper.py
Maps attacker commands to MITRE ATT&CK techniques using the LLM.

Output schema:
{
  "tactics_detected": [str],
  "techniques": [
    {
      "id": "T1059.004",
      "name": "Unix Shell",
      "tactic": "Execution",
      "confidence": 0.92
    }
  ]
}
"""
from __future__ import annotations

from typing import Any

import structlog

from ai_core.llm_client import LLMClient

log = structlog.get_logger(__name__)

_MITRE_PROMPT_TEMPLATE = """
You are a MITRE ATT&CK framework expert.

Analyze this Linux terminal command from a suspected attacker:
  Command: {command}

Attacker context:
  - Inferred intent: {primary_objective}
  - Attacker type: {attacker_type}

Map the command to the most relevant MITRE ATT&CK techniques (Enterprise matrix).

Respond ONLY with this JSON schema:
{{
  "tactics_detected": ["<tactic name>", ...],
  "techniques": [
    {{
      "id": "<Txxxx.xxx>",
      "name": "<technique name>",
      "tactic": "<tactic name>",
      "confidence": <0.0-1.0>,
      "rationale": "<one sentence>"
    }}
  ]
}}

Return an empty techniques array if the command is benign or unclassifiable.
"""


class MitreMapper:
    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm

    async def map(
        self,
        command: str,
        intent: dict[str, Any],
    ) -> dict[str, Any]:
        """Map a single command to MITRE ATT&CK techniques."""
        prompt = _MITRE_PROMPT_TEMPLATE.format(
            command=command,
            primary_objective=intent.get("primary_objective", "unknown"),
            attacker_type=intent.get("attacker_type", "unknown"),
        )

        # MITRE mapping uses a minimal, stateless context (no session memory)
        messages = [
            {"role": "system", "content": "You are a MITRE ATT&CK expert. Always respond with valid JSON."},
            {"role": "user", "content": prompt},
        ]

        try:
            result = await self._llm.chat(messages, json_mode=True)
            techniques = result.get("techniques", [])
            log.info(
                "mitre_mapped",
                command=command[:60],
                technique_count=len(techniques),
                top_technique=techniques[0].get("id") if techniques else "none",
            )
            return result
        except Exception as exc:
            log.warning("mitre_mapping_error", error=str(exc))
            return {"tactics_detected": [], "techniques": []}
