"""
interception/command_interceptor.py
Central command processing pipeline.

Every terminal command from the attacker flows through here:
  Command → AI Core pipeline → telemetry → response string
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

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

        # ── 1. Intent Inference ────────────────────────────────────────────────
        intent = await self._intent.infer(session_state)

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

        # ── 5. MITRE Mapping (parallel-ish, fire-and-forget telemetry) ─────────
        try:
            mitre_result = await self._mitre.map(command, intent)
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
            threat = self._scorer.score(
                intent=intent,
                mitre_result=mitre_result,
                command_count=len(session_state.command_history),
            )
            await self._session_mgr.update_threat_profile(
                sid,
                risk_score=threat.get("risk_score"),
                threat_level=threat.get("threat_level"),
                likelihood_apt=threat.get("likelihood_APT"),
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

        return response
