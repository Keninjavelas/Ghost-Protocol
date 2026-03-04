"""
telemetry/logger.py
Structured JSON telemetry logger.
Logs every command, AI classification, MITRE mapping, threat score updates, and beacon events.
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from typing import Any, Optional
import uuid

import structlog

from config.settings import settings


def configure_logging() -> None:
    """Initialize structlog with JSON output (or pretty console for dev)."""
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        # NOTE: add_logger_name is omitted — it requires stdlib.LoggerFactory,
        # but we use PrintLoggerFactory which produces a PrintLogger without .name
    ]

    if settings.LOG_JSON:
        processors = shared_processors + [
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]
    else:
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )


class TelemetryLogger:
    """
    High-level telemetry logger.
    Each method persists an event to the database AND emits structured log.
    """

    def __init__(self) -> None:
        self._log = structlog.get_logger("telemetry")

    # ── Command logging ────────────────────────────────────────────────────────

    async def log_command(
        self,
        session_id: uuid.UUID,
        command: str,
        ai_classification: Optional[str] = None,
        mitre_technique: Optional[str] = None,
    ) -> None:
        from database.db import get_session
        from database.models import Command

        self._log.info(
            "command",
            session_id=str(session_id),
            command=command,
            ai_classification=ai_classification,
            mitre_technique=mitre_technique,
        )
        async with get_session() as db:
            db.add(
                Command(
                    session_id=session_id,
                    command=command,
                    timestamp=datetime.now(timezone.utc),
                    ai_classification=ai_classification,
                    mitre_technique=mitre_technique,
                )
            )

    # ── MITRE mapping logging ──────────────────────────────────────────────────

    async def log_mitre(
        self,
        session_id: uuid.UUID,
        technique_id: str,
        technique_name: str,
        tactic: str,
        confidence: float,
    ) -> None:
        from database.db import get_session
        from database.models import MitreMapping

        self._log.info(
            "mitre_mapping",
            session_id=str(session_id),
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence=confidence,
        )
        async with get_session() as db:
            db.add(
                MitreMapping(
                    session_id=session_id,
                    technique_id=technique_id,
                    technique_name=technique_name,
                    tactic=tactic,
                    confidence=confidence,
                    timestamp=datetime.now(timezone.utc),
                )
            )

    # ── Threat score logging ───────────────────────────────────────────────────

    async def log_threat_update(
        self,
        session_id: uuid.UUID,
        risk_score: float,
        threat_level: str,
        attacker_category: str,
        likelihood_apt: float,
    ) -> None:
        self._log.info(
            "threat_score_update",
            session_id=str(session_id),
            risk_score=risk_score,
            threat_level=threat_level,
            attacker_category=attacker_category,
            likelihood_apt=likelihood_apt,
        )

    # ── Beacon event logging ───────────────────────────────────────────────────

    async def log_beacon(
        self,
        session_id: uuid.UUID,
        token_id: str,
        triggered_ip: Optional[str],
        user_agent: Optional[str],
    ) -> None:
        from database.db import get_session
        from database.models import BeaconEvent

        self._log.warning(
            "beacon_triggered",
            session_id=str(session_id),
            token_id=token_id,
            triggered_ip=triggered_ip,
            user_agent=user_agent,
        )
        async with get_session() as db:
            db.add(
                BeaconEvent(
                    session_id=session_id,
                    token_id=token_id,
                    triggered_ip=triggered_ip,
                    triggered_time=datetime.now(timezone.utc),
                    user_agent=user_agent,
                )
            )

    # ── Credential access logging ──────────────────────────────────────────────

    async def log_credential_access(
        self,
        session_id: uuid.UUID,
        file_path: str,
        command: str,
        mitre_technique: Optional[str] = None,
    ) -> None:
        """
        Log when an attacker accesses a sensitive bait file containing credentials.
        This is a high-severity security event for demo scenarios.
        """
        self._log.warning(
            "credential_theft_detected",
            session_id=str(session_id),
            file=file_path,
            command=command,
            mitre_technique=mitre_technique,
            severity="HIGH",
        )
        # Note: We log to MITRE mappings table since we're tracking techniques
        if mitre_technique:
            from database.db import get_session
            from database.models import MitreMapping
            
            async with get_session() as db:
                db.add(
                    MitreMapping(
                        session_id=session_id,
                        technique_id=mitre_technique,
                        technique_name=f"Credential Access: {file_path}",
                        tactic="Credential Access",
                        confidence=1.0,  # Direct file access = 100% confidence
                        timestamp=datetime.now(timezone.utc),
                    )
                )

    # ── Report logging ─────────────────────────────────────────────────────────

    async def log_report(
        self,
        session_id: uuid.UUID,
        report: dict[str, Any],
    ) -> None:
        from database.db import get_session
        from database.models import Report

        self._log.info("report_generated", session_id=str(session_id))
        async with get_session() as db:
            db.merge(
                Report(
                    session_id=session_id,
                    report_json=report,
                    generated_at=datetime.now(timezone.utc),
                )
            )
