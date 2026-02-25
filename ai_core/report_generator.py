"""
ai_core/report_generator.py
Generates a structured intelligence report on session termination.

Triggered by: session end / timeout
Output stored in database `reports` table.

Report schema:
{
  "session_id": str,
  "executive_summary": str,
  "techniques_used": [...],
  "intent_analysis": {...},
  "threat_score": {...},
  "mitigation_suggestions": [str],
  "timeline": [...]
}
"""
from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

import structlog

from ai_core.llm_client import LLMClient

if TYPE_CHECKING:
    from session.session_model import SessionState

log = structlog.get_logger(__name__)

_REPORT_PROMPT_TEMPLATE = """
You are an autonomous cyber threat intelligence analyst.

Generate a final intelligence report for the following attacker session.

Session data:
- Session ID: {session_id}
- Source IP: {source_ip}
- Username used: {username}
- Duration: {duration}
- Total commands: {command_count}
- Attacker type: {attacker_type}
- Primary objective: {primary_objective}
- Sophistication: {sophistication_level}
- Risk score: {risk_score}
- Threat level: {threat_level}

Command history (last 30):
{command_history}

Generate a professional intelligence report. Respond ONLY with this JSON:
{{
  "executive_summary": "<2-3 sentence high-level summary>",
  "attacker_profile": {{
    "type": "{attacker_type}",
    "objective": "{primary_objective}",
    "sophistication": "{sophistication_level}",
    "likely_nation_state": <true|false>
  }},
  "techniques_used": [
    {{
      "mitre_id": "<Txxxx>",
      "name": "<technique>",
      "description": "<brief>"
    }}
  ],
  "intent_analysis": {{
    "primary_goal": "<str>",
    "secondary_goals": ["<str>"],
    "behavioral_patterns": "<str>"
  }},
  "threat_assessment": {{
    "risk_score": {risk_score},
    "threat_level": "{threat_level}",
    "immediate_danger": <true|false>,
    "data_at_risk": ["<str>"]
  }},
  "mitigation_suggestions": [
    "<actionable recommendation>",
    "<actionable recommendation>",
    "<actionable recommendation>"
  ],
  "iocs": {{
    "ip_addresses": ["{source_ip}"],
    "usernames": ["{username}"],
    "tools_or_commands": ["<str>"]
  }}
}}
"""


class ReportGenerator:
    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm

    async def generate(self, session_state: "SessionState") -> dict[str, Any]:
        """Generate and return the final intelligence report dict."""
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        duration_secs = int((now - session_state.start_time).total_seconds())

        history = session_state.command_history[-30:]
        history_text = "\n".join(
            f"  [{i+1}] {e['command']}" for i, e in enumerate(history)
        ) or "  (no commands)"

        prompt = _REPORT_PROMPT_TEMPLATE.format(
            session_id=str(session_state.session_id),
            source_ip=session_state.source_ip,
            username=session_state.username,
            duration=f"{duration_secs}s",
            command_count=len(session_state.command_history),
            attacker_type=session_state.attacker_type or "unknown",
            primary_objective=session_state.primary_objective or "unknown",
            sophistication_level=session_state.sophistication_level or "low",
            risk_score=session_state.risk_score,
            threat_level=session_state.threat_level,
            command_history=history_text,
        )

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a professional cyber threat intelligence analyst. "
                    "Always respond with valid JSON. Be precise and actionable."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        try:
            report = await self._llm.chat(messages, json_mode=True, max_tokens=2048)
            report["session_id"] = str(session_state.session_id)
            report["generated_at"] = now.isoformat()
            log.info("report_generated", session_id=str(session_state.session_id))
            return report
        except Exception as exc:
            log.warning("report_generation_error", error=str(exc))
            return {
                "session_id": str(session_state.session_id),
                "executive_summary": "Report generation failed.",
                "error": str(exc),
            }
