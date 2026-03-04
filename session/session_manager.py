"""
session/session_manager.py
Thread-safe, async-compatible manager for all active attacker sessions.
Coordinates session lifecycle: create → allocate sandbox → track → teardown.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, Optional

import structlog

from database.db import get_session
from database.models import Session as DBSession, Report as DBReport
from sandbox.docker_manager import DockerManager
from session.session_model import SessionState

if TYPE_CHECKING:
    from ai_core.report_generator import ReportGenerator
    from dashboard.backend.websocket import ConnectionManager

log = structlog.get_logger(__name__)


class SessionManager:
    """Singleton-like manager; create one instance and share it."""

    def __init__(
        self,
        docker_manager: DockerManager,
        report_generator: Optional["ReportGenerator"] = None,
        ws_manager: Optional["ConnectionManager"] = None,
    ) -> None:
        self._sessions: Dict[uuid.UUID, SessionState] = {}
        self._lock = asyncio.Lock()
        self._docker = docker_manager
        self._report_gen = report_generator
        self._ws = ws_manager

    # ── Public API ─────────────────────────────────────────────────────────────

    async def create_session(
        self,
        source_ip: str,
        username: str,
    ) -> SessionState:
        """
        Create a new session, persist it to DB, spawn a Docker sandbox,
        and return the runtime SessionState.
        """
        session_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        state = SessionState(
            session_id=session_id,
            source_ip=source_ip,
            username=username,
            start_time=now,
        )

        # ── Preload Credential Theft Trap Bait Files ──────────────────────────
        # Guarantee high-value targets appear in every session for demo
        from ai_core.bait_files import get_all_bait_files
        
        bait_files = get_all_bait_files()
        for file_path, metadata in bait_files.items():
            state.fake_fs[file_path] = {
                "content_hint": metadata.get("content_hint", ""),
                "is_bait": metadata.get("is_bait", False),
                "is_sensitive": metadata.get("is_sensitive", False),
            }
        
        log.info(
            "bait_files_preloaded",
            session_id=str(session_id),
            bait_count=len(bait_files),
        )

        # Persist to DB
        async with get_session() as db:
            db_session = DBSession(
                id=session_id,
                source_ip=source_ip,
                username=username,
                start_time=now,
                status="active",
            )
            db.add(db_session)

        # Spawn Docker sandbox
        try:
            container_id = await self._docker.spawn_container(session_id=str(session_id))
            state.container_id = container_id
            log.info("sandbox_spawned", session_id=str(session_id), container_id=container_id)
        except Exception as exc:
            log.warning(
                "sandbox_spawn_failed",
                session_id=str(session_id),
                error=str(exc),
            )
            # Continue without sandbox; AI still works

        async with self._lock:
            self._sessions[session_id] = state

        log.info(
            "session_created",
            session_id=str(session_id),
            source_ip=source_ip,
            username=username,
        )
        return state

    async def get_session(self, session_id: uuid.UUID) -> Optional[SessionState]:
        async with self._lock:
            return self._sessions.get(session_id)

    async def all_sessions(self) -> list[SessionState]:
        async with self._lock:
            return list(self._sessions.values())

    async def update_threat_profile(
        self,
        session_id: uuid.UUID,
        *,
        attacker_type: Optional[str] = None,
        primary_objective: Optional[str] = None,
        sophistication_level: Optional[str] = None,
        intent_confidence: Optional[float] = None,
        risk_score: Optional[float] = None,
        threat_level: Optional[str] = None,
        likelihood_apt: Optional[float] = None,
    ) -> None:
        """Update AI-derived threat profile into runtime state and DB."""
        async with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                return

            if attacker_type is not None:
                state.attacker_type = attacker_type
            if primary_objective is not None:
                state.primary_objective = primary_objective
            if sophistication_level is not None:
                state.sophistication_level = sophistication_level
            if intent_confidence is not None:
                state.intent_confidence = intent_confidence
            if risk_score is not None:
                state.risk_score = risk_score
            if threat_level is not None:
                state.threat_level = threat_level
            if likelihood_apt is not None:
                state.likelihood_apt = likelihood_apt

        # Async DB update
        async with get_session() as db:
            db_obj = await db.get(DBSession, session_id)
            if db_obj:
                if attacker_type is not None:
                    db_obj.attacker_type = attacker_type
                if primary_objective is not None:
                    db_obj.primary_objective = primary_objective
                if sophistication_level is not None:
                    db_obj.sophistication_level = sophistication_level
                if risk_score is not None:
                    db_obj.risk_score = risk_score
                if threat_level is not None:
                    db_obj.threat_level = threat_level

    async def append_command(
        self,
        session_id: uuid.UUID,
        command: str,
        timestamp: Optional[datetime] = None,
    ) -> None:
        ts = timestamp or datetime.now(timezone.utc)
        async with self._lock:
            state = self._sessions.get(session_id)
            if state:
                state.command_history.append({"command": command, "timestamp": ts.isoformat()})

    async def close_session(self, session_id: uuid.UUID) -> None:
        """Teardown: destroy sandbox, mark DB session closed, remove from memory."""
        async with self._lock:
            state = self._sessions.pop(session_id, None)

        if state is None:
            return

        # ── Automatic Report Generation ────────────────────────────────────────
        # Generate intelligence report before cleanup
        report_data = None
        if self._report_gen:
            try:
                report_data = await self._report_gen.generate(state)
                
                # Persist report to database
                async with get_session() as db:
                    db_report = DBReport(
                        session_id=session_id,
                        report_json=report_data,
                    )
                    db.add(db_report)
                
                log.info("report_persisted", session_id=str(session_id))
                
                # ── WebSocket Event: report_generated ──────────────────────────
                if self._ws:
                    await self._ws.broadcast(
                        self._ws.make_event(
                            "report_generated",
                            str(session_id),
                            {"report": report_data},
                        )
                    )
            except Exception as exc:
                log.warning("report_generation_failed", session_id=str(session_id), error=str(exc))

        # Destroy Docker container
        if state.container_id:
            try:
                await self._docker.destroy_container(state.container_id)
                log.info("container_destroyed", container_id=state.container_id)
            except Exception as exc:
                log.warning("container_destroy_failed", error=str(exc))

        # Update DB
        async with get_session() as db:
            db_obj = await db.get(DBSession, session_id)
            if db_obj:
                db_obj.status = "closed"
                db_obj.end_time = datetime.now(timezone.utc)
        
        # ── WebSocket Event: session_closed ────────────────────────────────────
        if self._ws:
            await self._ws.broadcast(
                self._ws.make_event(
                    "session_closed",
                    str(session_id),
                    {
                        "session_id": str(session_id),
                        "duration": int((datetime.now(timezone.utc) - state.start_time).total_seconds()),
                        "command_count": len(state.command_history),
                        "threat_level": state.threat_level,
                        "risk_score": state.risk_score,
                    },
                )
            )

        log.info("session_closed", session_id=str(session_id))
