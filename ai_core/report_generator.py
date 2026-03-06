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
            log.warning("report_generation_llm_failed", error=str(exc))
            # Generate a comprehensive fallback report without LLM
            return self._generate_fallback_report(session_state, now, history)

    def _generate_fallback_report(
        self,
        session_state: "SessionState",
        now,
        history: list,
    ) -> dict[str, Any]:
        """Generate a complete intelligence report without LLM as fallback."""
        from datetime import timezone

        duration_secs = int((now - session_state.start_time).total_seconds())
        cmd_count = len(session_state.command_history)
        risk_score = session_state.risk_score
        threat_level = session_state.threat_level
        attacker_type = session_state.attacker_type or "unknown"
        objective = session_state.primary_objective or "reconnaissance"
        sophistication = session_state.sophistication_level or "low"
        source_ip = session_state.source_ip
        username = session_state.username

        # Extract commands list
        commands_list = [e["command"] for e in history]

        # Detect accessed sensitive files
        sensitive_files = []
        tools_used = set()
        for cmd in commands_list:
            cmd_lower = cmd.lower()
            tools_used.add(cmd.split()[0] if cmd.split() else "")
            if any(k in cmd_lower for k in ["password", "credential", "shadow", ".aws", ".env", "db", "sql", "key"]):
                sensitive_files.append(cmd)

        # Build executive summary
        if risk_score > 70:
            severity = "HIGH"
            summary = (
                f"An attacker from IP {source_ip} (username: {username}) conducted a {severity}-severity "
                f"intrusion lasting {duration_secs}s. The attacker executed {cmd_count} commands focused on "
                f"{objective.replace('-', ' ')}. Risk score: {risk_score:.0f}/100. Immediate containment recommended."
            )
        elif risk_score > 40:
            severity = "MEDIUM"
            summary = (
                f"A {severity}-severity attack was detected from {source_ip} (username: {username}). "
                f"The attacker executed {cmd_count} commands over {duration_secs}s, primarily engaged in "
                f"{objective.replace('-', ' ')}. Risk score: {risk_score:.0f}/100."
            )
        else:
            severity = "LOW"
            summary = (
                f"A {severity}-severity session was recorded from {source_ip} (username: {username}). "
                f"{cmd_count} commands were executed over {duration_secs}s. "
                f"Activity classified as {objective.replace('-', ' ')}. Risk score: {risk_score:.0f}/100."
            )

        report = {
            "session_id": str(session_state.session_id),
            "generated_at": now.isoformat(),
            "executive_summary": summary,
            "attacker_profile": {
                "type": attacker_type,
                "objective": objective,
                "sophistication": sophistication,
                "likely_nation_state": sophistication == "high" and risk_score > 70,
            },
            "techniques_used": [],
            "intent_analysis": {
                "primary_goal": objective,
                "secondary_goals": ["system enumeration", "data access"],
                "behavioral_patterns": f"Attacker used {len(tools_used)} unique tools across {cmd_count} commands",
            },
            "threat_assessment": {
                "risk_score": risk_score,
                "threat_level": threat_level,
                "immediate_danger": risk_score > 70,
                "data_at_risk": sensitive_files[:5] if sensitive_files else ["No sensitive data accessed"],
            },
            "mitigation_suggestions": [
                f"Block IP address {source_ip} at firewall level",
                "Rotate all credentials that may have been exposed",
                "Review system logs for additional unauthorized access",
                "Implement multi-factor authentication for SSH access",
                "Deploy intrusion detection system (IDS) monitoring",
            ],
            "iocs": {
                "ip_addresses": [source_ip],
                "usernames": [username],
                "tools_or_commands": list(tools_used)[:10],
            },
        }

        log.info("fallback_report_generated", session_id=str(session_state.session_id))
        return report
