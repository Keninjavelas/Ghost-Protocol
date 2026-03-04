"""
ai_core/environment_shaper.py
Dynamically modifies the visible fake filesystem based on attacker intent.

- Provides consistent corporate server narrative for demo reliability
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

# ── Consistent Corporate Narrative ─────────────────────────────────────────────
# Used for demo reliability - same environment every time

CORPORATE_NARRATIVE = (
    "Ubuntu 22.04 LTS server (ip-10-0-4-12) hosting internal company APIs, "
    "DevOps automation tooling, and production database backups. "
    "Managed infrastructure includes AWS S3, Kubernetes clusters, and financial data storage."
)

_SHAPER_PROMPT_TEMPLATE = """
You are shaping a fake Linux honeypot filesystem to deceive an attacker.

System environment: {environment_narrative}

Attacker profile:
- Type: {attacker_type}
- Objective: {primary_objective}
- Sophistication: {sophistication_level}
- Current directory: {working_directory}

Your job: decide what fake files and directories should be VISIBLE and ACCESSIBLE
to make this environment maximally convincing and to lure the attacker deeper.

IMPORTANT: The base filesystem already contains corporate data including:
- AWS credentials, Kubernetes configs, Terraform state
- Database backups with customer PII
- Employee payroll and HR records
- Nginx configurations and deployment scripts
- Docker registry credentials

Only suggest ADDITIONAL files if they enhance the deception for this specific attacker.

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
  "environment_narrative": "{environment_narrative}",
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
        Returns env_context dict with consistent corporate narrative.
        
        For demo reliability, the narrative is fixed rather than LLM-generated.
        The LLM can still inject additional files based on attacker behavior.
        """
        prompt = _SHAPER_PROMPT_TEMPLATE.format(
            environment_narrative=CORPORATE_NARRATIVE,
            attacker_type=intent.get("attacker_type", "unknown"),
            primary_objective=intent.get("primary_objective", "unknown"),
            sophistication_level=intent.get("sophistication_level", "low"),
            working_directory=session_state.working_directory,
        )

        messages = self._llm.build_messages(session_state.ai_memory, prompt)

        try:
            result = await self._llm.chat(messages, json_mode=True)

            # Ensure consistent narrative is always returned
            if not result.get("environment_narrative"):
                result["environment_narrative"] = CORPORATE_NARRATIVE

            # Merge injected paths into session fake_fs
            for f in result.get("injected_files", []):
                path = f.get("path", "")
                if path and path not in session_state.fake_fs:  # Don't overwrite preloaded bait
                    session_state.fake_fs[path] = {
                        "content_hint": f.get("content_hint", ""),
                        "is_bait": f.get("is_bait", False),
                    }

            log.info(
                "environment_shaped",
                session_id=str(session_state.session_id),
                narrative=CORPORATE_NARRATIVE,
                injected_files=len(result.get("injected_files", [])),
                canary_count=len(result.get("canary_trigger_files", [])),
            )
            return result
        except Exception as exc:
            log.warning("environment_shaping_error", error=str(exc))
            # Fallback to consistent corporate environment
            return {
                "injected_files": [],
                "injected_dirs": [],
                "environment_narrative": CORPORATE_NARRATIVE,
                "canary_trigger_files": [],
            }
