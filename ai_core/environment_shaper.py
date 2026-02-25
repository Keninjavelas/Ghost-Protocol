"""
ai_core/environment_shaper.py
Dynamically modifies the visible fake filesystem based on attacker intent.

- Injects relevant bait files (SSH keys, .env files, db dumps, etc.)
- Keeps the environment consistent across commands
- Returns an env_context dict consumed by the ResponseGenerator
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

from ai_core.llm_client import LLMClient

if TYPE_CHECKING:
    from session.session_model import SessionState

log = structlog.get_logger(__name__)

_SHAPER_PROMPT_TEMPLATE = """
You are shaping a fake Linux honeypot filesystem to deceive an attacker.

Attacker profile:
- Type: {attacker_type}
- Objective: {primary_objective}
- Sophistication: {sophistication_level}
- Current directory: {working_directory}

Your job: decide what fake files and directories should be VISIBLE and ACCESSIBLE
to make this environment maximally convincing and to lure the attacker deeper.

Respond ONLY with this JSON schema:
{{
  "injected_files": [
    {{
      "path": "<absolute path>",
      "content_hint": "<brief description of what the file contains>",
      "is_bait": true
    }}
  ],
  "injected_dirs": ["<absolute path>", ...],
  "environment_narrative": "<one sentence describing the fake server's role>",
  "canary_trigger_files": ["<absolute path of files that should embed canary tokens>"]
}}
"""


class EnvironmentShaper:
    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm

    async def shape(
        self,
        session_state: "SessionState",
        intent: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Generate environment context based on attacker intent.
        Returns env_context dict that ResponseGenerator uses.
        """
        prompt = _SHAPER_PROMPT_TEMPLATE.format(
            attacker_type=intent.get("attacker_type", "unknown"),
            primary_objective=intent.get("primary_objective", "unknown"),
            sophistication_level=intent.get("sophistication_level", "low"),
            working_directory=session_state.working_directory,
        )

        messages = self._llm.build_messages(session_state.ai_memory, prompt)

        try:
            result = await self._llm.chat(messages, json_mode=True)

            # Merge injected paths into session fake_fs
            for f in result.get("injected_files", []):
                path = f.get("path", "")
                if path:
                    session_state.fake_fs[path] = {
                        "content_hint": f.get("content_hint", ""),
                        "is_bait": f.get("is_bait", False),
                    }

            log.info(
                "environment_shaped",
                session_id=str(session_state.session_id),
                injected_files=len(result.get("injected_files", [])),
                canary_count=len(result.get("canary_trigger_files", [])),
            )
            return result
        except Exception as exc:
            log.warning("environment_shaping_error", error=str(exc))
            return {
                "injected_files": [],
                "injected_dirs": [],
                "environment_narrative": "Generic Linux server",
                "canary_trigger_files": [],
            }
