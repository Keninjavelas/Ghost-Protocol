"""
interception/command_interceptor.py
Central command processing pipeline.

Every terminal command from the attacker flows through here:
  Command → AI Core pipeline → telemetry → response string
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

import structlog

from ai_core.intent_inference import IntentInferenceEngine
from ai_core.environment_shaper import EnvironmentShaper
from ai_core.mitre_mapper import MitreMapper
from ai_core.response_generator import ResponseGenerator
from ai_core.threat_scorer import ThreatScorer
from ai_core.report_generator import ReportGenerator
from ai_core.llm_client import LLMClient
from session.session_manager import SessionManager
from telemetry.logger import TelemetryLogger

if TYPE_CHECKING:
    from session.session_model import SessionState
    from dashboard.backend.websocket import ConnectionManager

log = structlog.get_logger(__name__)


class CommandInterceptor:
    """
    Orchestrates the full per-command AI pipeline.
    Never executes commands on the real host.
    """

    def __init__(
        self,
        session_manager: SessionManager,
        llm_client: LLMClient,
        intent_engine: IntentInferenceEngine,
        env_shaper: EnvironmentShaper,
        mitre_mapper: MitreMapper,
        threat_scorer: ThreatScorer,
        response_generator: ResponseGenerator,
        report_generator: ReportGenerator,
        telemetry: TelemetryLogger,
        ws_manager: Optional["ConnectionManager"] = None,
    ) -> None:
        self._session_mgr = session_manager
        self._llm = llm_client
        self._intent = intent_engine
        self._shaper = env_shaper
        self._mitre = mitre_mapper
        self._scorer = threat_scorer
        self._responder = response_generator
        self._reporter = report_generator
        self._telemetry = telemetry
        self._ws = ws_manager

    async def process(
        self,
        session_state: "SessionState",
        command: str,
    ) -> str:
        """
        Full AI pipeline for a single command.
        Returns the terminal response string to send back to the attacker.
        """
        sid = session_state.session_id
        ts = datetime.now(timezone.utc)

        log.info("command_intercepted", session_id=str(sid), command=command)
        
        # ── WebSocket Event: command_received ──────────────────────────────────
        if self._ws:
            await self._ws.broadcast(
                self._ws.make_event(
                    "command_received",
                    str(sid),
                    {"command": command},
                )
            )

        # ── 1. Intent Inference ────────────────────────────────────────────────
        intent = await self._intent.infer(session_state)
        
        # ── WebSocket Event: intent_inferred ───────────────────────────────────
        if self._ws:
            await self._ws.broadcast(
                self._ws.make_event(
                    "intent_inferred",
                    str(sid),
                    {
                        "attacker_type": intent.get("attacker_type"),
                        "primary_objective": intent.get("primary_objective"),
                        "sophistication_level": intent.get("sophistication_level"),
                        "confidence": intent.get("confidence"),
                    },
                )
            )

        # ── 2. Update session threat profile ──────────────────────────────────
        await self._session_mgr.update_threat_profile(
            sid,
            attacker_type=intent.get("attacker_type"),
            primary_objective=intent.get("primary_objective"),
            sophistication_level=intent.get("sophistication_level"),
            intent_confidence=float(intent.get("confidence", 0.0)),
        )

        # ── 3. Environment Shaping ─────────────────────────────────────────────
        env_context = await self._shaper.shape(session_state, intent)

        # ── 4. Generate Response ───────────────────────────────────────────────
        response = await self._responder.generate(
            session_state=session_state,
            command=command,
            env_context=env_context,
        )
        
        # ── 4a. Credential Theft Detection ────────────────────────────────────
        # Check if response generator detected credential file access
        credential_access_events = getattr(session_state, 'credential_accesses', [])
        if credential_access_events:
            # Get the most recent credential access event
            latest_access = credential_access_events[-1]
            
            # Log credential access to telemetry
            await self._telemetry.log_credential_access(
                session_id=sid,
                file_path=latest_access["file"],
                command=latest_access["command"],
                mitre_technique=latest_access.get("mitre_technique"),
            )
            
            # ── WebSocket Event: credential_access_detected ────────────────────
            if self._ws:
                await self._ws.broadcast(
                    self._ws.make_event(
                        "credential_access_detected",
                        str(sid),
                        {
                            "file": latest_access["file"],
                            "command": latest_access["command"],
                            "technique": latest_access.get("mitre_technique", "T1552"),
                            "severity": "HIGH",
                        },
                    )
                )

        # ── 5. MITRE Mapping (parallel-ish, fire-and-forget telemetry) ─────────
        try:
            mitre_result = await self._mitre.map(command, intent)
            
            # ── WebSocket Event: mitre_mapped ──────────────────────────────────
            if self._ws:
                await self._ws.broadcast(
                    self._ws.make_event(
                        "mitre_mapped",
                        str(sid),
                        {
                            "command": command,
                            "techniques": mitre_result.get("techniques", []),
                            "tactics_detected": mitre_result.get("tactics_detected", []),
                        },
                    )
                )
            
            for technique in mitre_result.get("techniques", []):
                await self._telemetry.log_mitre(
                    session_id=sid,
                    technique_id=technique.get("id", "T0000"),
                    technique_name=technique.get("name", ""),
                    tactic=technique.get("tactic", ""),
                    confidence=float(technique.get("confidence", 0.0)),
                )
        except Exception as exc:
            log.warning("mitre_mapping_error", error=str(exc))
            mitre_result = {"techniques": [], "tactics_detected": []}

        # ── 6. Threat Scoring ──────────────────────────────────────────────────
        try:
            # Count credential accesses for threat escalation
            credential_count = len(getattr(session_state, 'credential_accesses', []))
            
            threat = self._scorer.score(
                intent=intent,
                mitre_result=mitre_result,
                command_count=len(session_state.command_history),
                credential_access_count=credential_count,
            )
            await self._session_mgr.update_threat_profile(
                sid,
                risk_score=threat.get("risk_score"),
                threat_level=threat.get("threat_level"),
                likelihood_apt=threat.get("likelihood_APT"),
            )
            
            # ── WebSocket Event: threat_updated ────────────────────────────────
            if self._ws:
                await self._ws.broadcast(
                    self._ws.make_event(
                        "threat_updated",
                        str(sid),
                        {
                            "risk_score": threat["risk_score"],
                            "threat_level": threat["threat_level"],
                            "attacker_category": threat.get("attacker_category", "unknown"),
                            "likelihood_apt": threat.get("likelihood_APT", 0.0),
                            "credential_theft_detected": credential_count > 0,
                        },
                    )
                )
            
            await self._telemetry.log_threat_update(
                session_id=sid,
                risk_score=threat["risk_score"],
                threat_level=threat["threat_level"],
                attacker_category=threat.get("attacker_category", "unknown"),
                likelihood_apt=threat.get("likelihood_APT", 0.0),
            )
        except Exception as exc:
            log.warning("threat_scoring_error", error=str(exc))

        # ── 7. Telemetry: log command ──────────────────────────────────────────
        top_technique = ""
        techs = mitre_result.get("techniques", [])
        if techs:
            top_technique = techs[0].get("id", "")

        await self._telemetry.log_command(
            session_id=sid,
            command=command,
            ai_classification=intent.get("primary_objective"),
            mitre_technique=top_technique,
        )
        
        # ── WebSocket Event: command_output ────────────────────────────────────
        if self._ws:
            await self._ws.broadcast(
                self._ws.make_event(
                    "command_output",
                    str(sid),
                    {
                        "command": command,
                        "output": response[:500],  # Truncate long outputs
                    },
                )
            )

        # ── WebSocket Event: attack_timeline ───────────────────────────────────
        # Emit a comprehensive timeline event for judge-friendly visualization
        if self._ws:
            threat_data = {}
            try:
                threat = self._scorer.score(
                    intent=intent,
                    mitre_result=mitre_result,
                    command_count=len(session_state.command_history),
                    credential_access_count=len(getattr(session_state, 'credential_accesses', [])),
                )
                threat_data = threat
            except Exception:
                pass
            
            timeline_event = {
                "type": "attack_timeline",
                "session_id": str(sid),
                "timestamp": ts.isoformat(),
                "data": {
                    "timestamp_short": ts.strftime("%H:%M:%S"),
                    "event_type": "COMMAND",
                    "command": command,
                    "intent": intent.get("primary_objective", "unknown"),
                    "mitre_technique": top_technique,
                    "mitre_tactic": mitre_result.get("tactics_detected", [None])[0] if mitre_result.get("tactics_detected") else None,
                    "threat_score": threat_data.get("risk_score", 0),
                    "threat_level": threat_data.get("threat_level", "UNKNOWN"),
                    "description": self._generate_timeline_description(command, intent, mitre_result),
                    "ai_confidence": intent.get("confidence", 0),
                },
            }
            await self._ws.broadcast(timeline_event)

        return response

    def _generate_timeline_description(self, command: str, intent: dict, mitre_result: dict) -> str:
        """Generate a human-readable description for the timeline event."""
        objective = intent.get("primary_objective", "unknown").lower()
        
        keywords = {
            "credential_harvesting": "Credential file access",
            "data-exfiltration": "Data exfiltration attempt",
            "persistence": "Persistence mechanism setup",
            "reconnaissance": "Reconnaissance activity",
            "exploration": "System exploration",
            "lateral-movement": "Lateral movement probe",
        }
        
        for key, desc in keywords.items():
            if key in objective:
                return desc
        
        if "cat" in command or "less" in command or "more" in command:
            return "File access"
        elif "find" in command or "ls" in command or "dir" in command:
            return "Filesystem enumeration"
        elif "whoami" in command or "id" in command or "groups" in command:
            return "Identity detection"
        elif "curl" in command or "wget" in command or "nc" in command:
            return "Network connection"
        elif "chmod" in command or "sudo" in command:
            return "Privilege escalation attempt"
        
        return "System activity"
