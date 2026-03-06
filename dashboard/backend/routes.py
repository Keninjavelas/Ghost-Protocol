"""
dashboard/backend/routes.py
FastAPI route handlers for the Ghost Protocol dashboard API.

Endpoints:
  GET /sessions          – list all sessions
  GET /session/{id}      – session detail + commands
  GET /mitre/{id}        – MITRE mappings for session
  GET /threat/{id}       – threat score for session
  GET /beacons           – all beacon events
  GET /report/{id}       – intelligence report for session
  GET /ws-test           – broadcast a scripted demo event burst (no attacker needed)
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database.db import get_db_session
from database.models import (
    BeaconEvent,
    Command,
    MitreMapping,
    Report,
    Session as DBSession,
)
from session.session_manager import SessionManager
from dashboard.backend.websocket import ConnectionManager

log = structlog.get_logger(__name__)
router = APIRouter(tags=["dashboard"])

_DEMO_SESSION_ID = "demo-0000-0000-0000-000000000001"


def _generate_attack_narrative(session: DBSession) -> str:
    """Generate a human-readable attack summary from session data."""
    if not session:
        return "No attack data available."
    
    objective = (session.primary_objective or "unknown").lower()
    attacker = (session.attacker_type or "unknown").lower()
    techniques = [m.technique_id for m in session.mitre_mappings]
    commands = len(session.commands)
    
    # Build narrative
    parts = []
    
    # Opening
    if "opportunity" in attacker or "script" in attacker:
        parts.append(f"The attacker engaged in {objective.replace('-', ' ')} behavior, "
                    "suggesting an opportunistic rather than targeted approach.")
    elif "apt" in attacker or "nation" in attacker:
        parts.append(f"Advanced persistent threat behavior detected. "
                    f"Attacker objectives include {objective.replace('-', ' ')}.")
    else:
        parts.append(f"The attacker initiated a {objective.replace('-', ' ')} campaign "
                    f"({commands} commands executed).")
    
    # MITRE behavior
    if techniques:
        tactics_set = set(m.tactic for m in session.mitre_mappings if m.tactic)
        tactics_str = ", ".join(sorted(tactics_set)[:3])
        parts.append(f"MITRE ATT&CK analysis reveals {len(techniques)} techniques "
                    f"across {tactics_str}.")
    
    # Threat assessment
    if session.risk_score and session.risk_score > 70:
        parts.append(f"Risk score ({session.risk_score:.0f}/100) indicates HIGH severity. "
                    "Immediate containment recommended.")
    elif session.risk_score and session.risk_score > 40:
        parts.append(f"Risk score ({session.risk_score:.0f}/100) indicates MEDIUM severity.")
    else:
        parts.append(f"Risk score ({session.risk_score:.0f}/100) indicates LOW severity.")
    
    return " ".join(parts)


def create_dashboard_router(
    session_manager: SessionManager,
    ws_manager: ConnectionManager,
) -> APIRouter:
    """Factory that injects the session_manager into route handlers."""

    @router.get("/sessions")
    async def list_sessions(db: AsyncSession = Depends(get_db_session)) -> list[dict[str, Any]]:
        """Return all sessions (active + closed) with summary fields."""
        sessions: list[DBSession] = []
        try:
            result = await db.execute(
                select(DBSession).order_by(DBSession.start_time.desc()).limit(200)
            )
            sessions = list(result.scalars().all())
        except Exception as exc:
            log.warning("sessions_db_query_failed", error=str(exc))

        # Merge with live in-memory state for active sessions
        live = {str(s.session_id): s for s in await session_manager.all_sessions()}

        out = []
        seen_ids: set[str] = set()
        for s in sessions:
            sid_str = str(s.id)
            seen_ids.add(sid_str)
            entry: dict[str, Any] = {
                "session_id": sid_str,
                "source_ip": s.source_ip,
                "username": s.username,
                "start_time": s.start_time.isoformat() if s.start_time else None,
                "end_time": s.end_time.isoformat() if s.end_time else None,
                "status": s.status,
                "threat_level": s.threat_level,
                "risk_score": s.risk_score,
                "attacker_type": s.attacker_type,
                "primary_objective": s.primary_objective,
            }
            if sid_str in live:
                live_state = live[sid_str]
                entry["command_count"] = len(live_state.command_history)
                entry["working_directory"] = live_state.working_directory
            out.append(entry)

        # Add live-only sessions when DB is unavailable.
        for sid_str, live_state in live.items():
            if sid_str in seen_ids:
                continue
            out.append(
                {
                    "session_id": sid_str,
                    "source_ip": live_state.source_ip,
                    "username": live_state.username,
                    "start_time": live_state.start_time.isoformat(),
                    "end_time": None,
                    "status": "active",
                    "threat_level": live_state.threat_level,
                    "risk_score": live_state.risk_score,
                    "attacker_type": live_state.attacker_type,
                    "primary_objective": live_state.primary_objective,
                    "command_count": len(live_state.command_history),
                    "working_directory": live_state.working_directory,
                }
            )

        return out

    @router.get("/session/{session_id}")
    async def get_session(
        session_id: str,
        db: AsyncSession = Depends(get_db_session),
    ) -> dict[str, Any]:
        """Return full session detail including last 100 commands."""
        try:
            uid = uuid.UUID(session_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid session ID")

        try:
            result = await db.execute(
                select(DBSession)
                .where(DBSession.id == uid)
                .options(selectinload(DBSession.commands))
            )
            s = result.scalar_one_or_none()
            if s is not None:
                commands = sorted(s.commands, key=lambda c: c.timestamp)[-100:]
                return {
                    "session_id": str(s.id),
                    "source_ip": s.source_ip,
                    "username": s.username,
                    "start_time": s.start_time.isoformat() if s.start_time else None,
                    "end_time": s.end_time.isoformat() if s.end_time else None,
                    "status": s.status,
                    "threat_level": s.threat_level,
                    "risk_score": s.risk_score,
                    "attacker_type": s.attacker_type,
                    "primary_objective": s.primary_objective,
                    "sophistication_level": s.sophistication_level,
                    "commands": [
                        {
                            "command": c.command,
                            "timestamp": c.timestamp.isoformat(),
                            "ai_classification": c.ai_classification,
                            "mitre_technique": c.mitre_technique,
                        }
                        for c in commands
                    ],
                }
        except Exception as exc:
            log.warning("session_detail_db_query_failed", session_id=session_id, error=str(exc))

        # Fallback to in-memory state for degraded DB mode.
        live = await session_manager.get_session(uid)
        if not live:
            raise HTTPException(status_code=404, detail="Session not found")

        return {
            "session_id": str(live.session_id),
            "source_ip": live.source_ip,
            "username": live.username,
            "start_time": live.start_time.isoformat(),
            "end_time": None,
            "status": "active",
            "threat_level": live.threat_level,
            "risk_score": live.risk_score,
            "attacker_type": live.attacker_type,
            "primary_objective": live.primary_objective,
            "sophistication_level": live.sophistication_level,
            "commands": [
                {
                    "command": c.get("command", ""),
                    "timestamp": c.get("timestamp"),
                    "ai_classification": None,
                    "mitre_technique": None,
                }
                for c in live.command_history[-100:]
            ],
        }

    @router.get("/mitre/{session_id}")
    async def get_mitre(
        session_id: str,
        db: AsyncSession = Depends(get_db_session),
    ) -> list[dict[str, Any]]:
        """Return all MITRE ATT&CK mappings for a session."""
        try:
            uid = uuid.UUID(session_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid session ID")

        try:
            result = await db.execute(
                select(MitreMapping)
                .where(MitreMapping.session_id == uid)
                .order_by(MitreMapping.timestamp)
            )
            mappings = result.scalars().all()
        except Exception as exc:
            log.warning("mitre_db_query_failed", session_id=session_id, error=str(exc))
            mappings = []

        return [
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
                "confidence": m.confidence,
                "timestamp": m.timestamp.isoformat(),
            }
            for m in mappings
        ]
    @router.get("/threat/{session_id}")
    async def get_threat(
        session_id: str,
        db: AsyncSession = Depends(get_db_session),
    ) -> dict[str, Any]:
        """Return current threat score for a session."""
        try:
            uid = uuid.UUID(session_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid session ID")

        live_sessions = {str(x.session_id): x for x in await session_manager.all_sessions()}
        live = live_sessions.get(session_id)

        try:
            s = await db.get(DBSession, uid)
        except Exception as exc:
            log.warning("threat_db_query_failed", session_id=session_id, error=str(exc))
            s = None

        if s is None and live is None:
            raise HTTPException(status_code=404, detail="Session not found")

        return {
            "session_id": session_id,
            "risk_score": live.risk_score if live else s.risk_score,
            "threat_level": live.threat_level if live else s.threat_level,
            "attacker_category": live.attacker_type if live else s.attacker_type,
            "likelihood_APT": live.likelihood_apt if live else None,
            "status": (s.status if s else "active"),
        }

    @router.get("/beacons")
    async def list_beacons(
        db: AsyncSession = Depends(get_db_session),
    ) -> list[dict[str, Any]]:
        """Return all beacon (canary token) trigger events."""
        result = await db.execute(
            select(BeaconEvent).order_by(BeaconEvent.triggered_time.desc()).limit(500)
        )
        events = result.scalars().all()
        return [
            {
                "id": e.id,
                "session_id": str(e.session_id),
                "token_id": e.token_id,
                "triggered_ip": e.triggered_ip,
                "triggered_time": e.triggered_time.isoformat(),
                "user_agent": e.user_agent,
            }
            for e in events
        ]

    @router.get("/report/{session_id}")
    async def get_report(
        session_id: str,
        db: AsyncSession = Depends(get_db_session),
    ) -> dict[str, Any]:
        """Return the final intelligence report for a session."""
        try:
            uid = uuid.UUID(session_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid session ID")

        try:
            result = await db.execute(
                select(Report).where(Report.session_id == uid)
            )
            report = result.scalar_one_or_none()
        except Exception as exc:
            log.warning("report_db_query_failed", session_id=session_id, error=str(exc))
            raise HTTPException(status_code=503, detail="Database unavailable for reports")

        if report is None:
            raise HTTPException(status_code=404, detail="Report not yet generated")

        return {
            "session_id": session_id,
            "generated_at": report.generated_at.isoformat(),
            "report": report.report_json,
        }
    # ── Session Snapshot (Quick Summary for Judges) ────────────────────────────
    @router.get("/snapshot/{session_id}")
    async def get_session_snapshot(
        session_id: str,
        db: AsyncSession = Depends(get_db_session),
    ) -> dict[str, Any]:
        """
        Return a judge-friendly session snapshot with all key intelligence.
        Displayed at the top of the dashboard for instant understanding.
        """
        try:
            uid = uuid.UUID(session_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid session ID")

        # Get session
        s = await db.execute(
            select(DBSession)
            .where(DBSession.id == uid)
            .options(selectinload(DBSession.commands), selectinload(DBSession.mitre_mappings))
        )
        session = s.scalar_one_or_none()
        if session is None:
            raise HTTPException(status_code=404, detail="Session not found")

        # Calculate session duration
        start = session.start_time
        end = session.end_time or datetime.now(timezone.utc)
        duration_seconds = int((end - start).total_seconds()) if start else 0
        duration_str = f"{duration_seconds // 60}m {duration_seconds % 60}s"

        # Collect unique MITRE techniques
        techniques = {}
        tactics = {}
        for mm in session.mitre_mappings:
            if mm.technique_id not in techniques:
                techniques[mm.technique_id] = {
                    "id": mm.technique_id,
                    "name": mm.technique_name,
                    "tactic": mm.tactic,
                }
            if mm.tactic:
                tactics[mm.tactic] = tactics.get(mm.tactic, 0) + 1

        return {
            "session_id": str(session.id),
            "source_ip": session.source_ip,
            "username": session.username,
            "attacker_type": session.attacker_type or "Unknown",
            "primary_objective": session.primary_objective or "Unknown",
            "threat_level": session.threat_level or "UNKNOWN",
            "risk_score": session.risk_score or 0,
            "sophistication_level": session.sophistication_level or "Unknown",
            "commands_executed": len(session.commands),
            "session_duration": duration_str,
            "mitre_techniques": list(techniques.values())[:10],  # Top 10
            "mitre_tactics": sorted(tactics.items(), key=lambda x: x[1], reverse=True)[:5],  # Top 5
            "status": session.status,
            "start_time": session.start_time.isoformat() if session.start_time else None,
            "end_time": session.end_time.isoformat() if session.end_time else None,
        }

    # ── Attack Summary (AI-Generated) ──────────────────────────────────────────
    @router.get("/attack-summary/{session_id}")
    async def get_attack_summary(
        session_id: str,
        db: AsyncSession = Depends(get_db_session),
    ) -> dict[str, Any]:
        """
        Return an AI-generated narrative summary of the attack.
        Used for judges to quickly understand attacker behavior.
        """
        try:
            uid = uuid.UUID(session_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid session ID")

        s = await db.execute(
            select(DBSession)
            .where(DBSession.id == uid)
            .options(selectinload(DBSession.commands), selectinload(DBSession.mitre_mappings))
        )
        session = s.scalar_one_or_none()
        if session is None:
            raise HTTPException(status_code=404, detail="Session not found")

        # Build summary from session data
        summary = _generate_attack_narrative(session)
        
        return {
            "session_id": str(session.id),
            "summary": summary,
            "confidence": 0.85,  # Base confidence
            "attacker_type": session.attacker_type,
            "primary_objective": session.primary_objective,
        }

    # ── Logs Endpoint (Technical Event Log) ──────────────────────────────────
    @router.get("/logs/{session_id}")
    async def get_session_logs(
        session_id: str,
        event_type: str = "all",
        limit: int = 200,
        db: AsyncSession = Depends(get_db_session),
    ) -> dict[str, Any]:
        """
        Return structured technical logs for a session.
        Event types: all, commands, ai_analysis, mitre, system
        """
        try:
            uid = uuid.UUID(session_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid session ID")

        s = await db.execute(
            select(DBSession)
            .where(DBSession.id == uid)
            .options(selectinload(DBSession.commands), selectinload(DBSession.mitre_mappings))
        )
        session = s.scalar_one_or_none()
        if session is None:
            raise HTTPException(status_code=404, detail="Session not found")

        logs = []

        # SESSION log entry
        if event_type in ("all", "system"):
            logs.append({
                "timestamp": session.start_time.isoformat() if session.start_time else None,
                "event_type": "SESSION",
                "details": f"Session started: {session.source_ip} / {session.username}",
                "severity": "INFO",
            })

        # COMMAND log entries
        if event_type in ("all", "commands"):
            for cmd in sorted(session.commands, key=lambda c: c.timestamp):
                logs.append({
                    "timestamp": cmd.timestamp.isoformat(),
                    "event_type": "COMMAND",
                    "details": f"$ {cmd.command}",
                    "severity": "INFO",
                })

        # MITRE_MAPPING log entries
        if event_type in ("all", "mitre"):
            for mm in sorted(session.mitre_mappings, key=lambda m: m.timestamp):
                logs.append({
                    "timestamp": mm.timestamp.isoformat(),
                    "event_type": "MITRE",
                    "details": f"{mm.technique_id} ({mm.tactic}): {mm.technique_name} [conf: {mm.confidence}]",
                    "severity": "HIGH" if mm.confidence and mm.confidence > 0.7 else "MEDIUM",
                })

        # Sort by timestamp descending
        logs.sort(key=lambda x: x["timestamp"], reverse=True)
        logs = logs[:limit]

        return {
            "session_id": str(session.id),
            "total_logs": len(logs),
            "filters_available": ["all", "commands", "ai_analysis", "mitre", "system"],
            "current_filter": event_type,
            "logs": logs,
        }

    # ── Frontend Bridge Endpoints ─────────────────────────────────────────────
    @router.get("/snapshot/{session_id}")
    async def get_snapshot(
        session_id: str,
        db: AsyncSession = Depends(get_db_session),
    ) -> dict[str, Any]:
        """Snapshot data for frontend dashboard (session summary)."""
        try:
            uid = uuid.UUID(session_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid session ID")

        result = await db.execute(
            select(DBSession)
            .where(DBSession.id == uid)
            .options(selectinload(DBSession.mitre_mappings))
        )
        s = result.scalar_one_or_none()
        if s is None:
            raise HTTPException(status_code=404, detail="Session not found")

        # Get live data if active
        live_sessions = {str(x.session_id): x for x in await session_manager.all_sessions()}
        live = live_sessions.get(session_id)

        # Calculate duration
        start = s.start_time or datetime.now(timezone.utc)
        end = s.end_time or datetime.now(timezone.utc)
        duration_seconds = (end - start).total_seconds()
        minutes = int(duration_seconds // 60)
        seconds = int(duration_seconds % 60)

        # MITRE techniques from mappings
        mitre_techniques = [
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
                "confidence": m.confidence or 0.0,
            }
            for m in s.mitre_mappings
        ]

        return {
            "session_id": session_id,
            "primary_objective": s.primary_objective or "unknown",
            "attacker_type": s.attacker_type or "unknown",
            "threat_level": live.threat_level if live else s.threat_level or "LOW",
            "commands_executed": len(s.commands) if s.commands else (live.command_count if live else 0),
            "session_duration": f"{minutes}m {seconds}s",
            "mitre_techniques": mitre_techniques,
            "confidence": live.confidence if live else 0.0,
        }

    @router.get("/attack-summary/{session_id}")
    async def get_attack_summary(
        session_id: str,
        db: AsyncSession = Depends(get_db_session),
    ) -> dict[str, str]:
        """Attack narrative and summary for frontend."""
        try:
            uid = uuid.UUID(session_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid session ID")

        result = await db.execute(
            select(DBSession)
            .where(DBSession.id == uid)
            .options(selectinload(DBSession.mitre_mappings))
        )
        s = result.scalar_one_or_none()
        if s is None:
            raise HTTPException(status_code=404, detail="Session not found")

        summary = _generate_attack_narrative(s)
        return {"summary": summary}

    @router.get("/logs/{session_id}")
    async def get_session_logs_v2(
        session_id: str,
        event_type: str = "all",
        limit: int = 500,
        db: AsyncSession = Depends(get_db_session),
    ) -> dict[str, Any]:
        """Get session logs (events) in frontend-compatible format."""
        try:
            uid = uuid.UUID(session_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid session ID")

        result = await db.execute(
            select(DBSession)
            .where(DBSession.id == uid)
            .options(selectinload(DBSession.commands))
        )
        s = result.scalar_one_or_none()
        if s is None:
            raise HTTPException(status_code=404, detail="Session not found")

        # Get live events if session is active
        live_sessions = {str(x.session_id): x for x in await session_manager.all_sessions()}
        live = live_sessions.get(session_id)

        logs = []

        # Add commands as logs
        if event_type in ["all", "commands"]:
            for cmd in sorted(s.commands, key=lambda c: c.timestamp) if s.commands else []:
                logs.append({
                    "timestamp": cmd.timestamp.isoformat() if cmd.timestamp else None,
                    "event_type": "command",
                    "details": cmd.command_text or "unknown",
                })

        # Add live session info if available
        if live and event_type in ["all", "system"]:
            logs.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "system",
                "details": f"Session active from {s.source_ip} as {s.username}",
            })

        # Limit and sort
        logs = sorted(logs, key=lambda x: x["timestamp"], reverse=True)[:limit]

        return {
            "session_id": session_id,
            "total_logs": len(logs),
            "filters_available": ["all", "commands", "system"],
            "current_filter": event_type,
            "logs": logs,
        }

    # ── Demo burst ────────────────────────────────────────────────────────────
    @router.get("/ws-test", tags=["meta"])
    async def ws_demo_burst() -> dict[str, str]:
        """
        Fire a scripted sequence of all 7 event types to every connected
        WebSocket client. Use this to demo the dashboard without a real attacker.
        """
        sid = _DEMO_SESSION_ID
        now = lambda: datetime.now(timezone.utc).isoformat()  # noqa: E731

        script: list[tuple[float, dict[str, Any]]] = [
            (0.0, {"type": "session", "session_id": sid, "timestamp": now(),
                   "data": {"action": "started", "source_ip": "185.220.101.47",
                            "username": "root"}}),
            (0.5, {"type": "command", "session_id": sid, "timestamp": now(),
                   "data": {"command": "ls -la /etc",
                            "ai_response": "total 88\ndrwxr-xr-x  1 root root 4096 Feb 23 18:00 .\n...",
                            "timestamp": now()}}),
            (1.2, {"type": "timeline", "session_id": sid, "timestamp": now(),
                   "data": {"event_text": "Initial recon: directory listing on /etc"}}),
            (1.8, {"type": "intent", "session_id": sid, "timestamp": now(),
                   "data": {"attacker_type": "Human Operator",
                            "primary_intent": "System Reconnaissance",
                            "sophistication": "Medium", "confidence": 0.62}}),
            (2.2, {"type": "threat", "session_id": sid, "timestamp": now(),
                   "data": {"risk_score": 3.1, "threat_level": "LOW"}}),
            (2.5, {"type": "mitre", "session_id": sid, "timestamp": now(),
                   "data": {"tactic": "Discovery", "technique_id": "T1083",
                            "technique_name": "File and Directory Discovery",
                            "confidence": 0.72}}),
            (3.4, {"type": "command", "session_id": sid, "timestamp": now(),
                   "data": {"command": "cat /etc/passwd",
                            "ai_response": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...",
                            "timestamp": now()}}),
            (4.0, {"type": "mitre", "session_id": sid, "timestamp": now(),
                   "data": {"tactic": "Credential Access", "technique_id": "T1003",
                            "technique_name": "OS Credential Dumping",
                            "confidence": 0.87}}),
            (4.3, {"type": "intent", "session_id": sid, "timestamp": now(),
                   "data": {"attacker_type": "Human Operator",
                            "primary_intent": "Credential Harvesting",
                            "sophistication": "Medium", "confidence": 0.78}}),
            (4.6, {"type": "threat", "session_id": sid, "timestamp": now(),
                   "data": {"risk_score": 6.0, "threat_level": "MED"}}),
            (4.9, {"type": "timeline", "session_id": sid, "timestamp": now(),
                   "data": {"event_text": "Credential access: /etc/passwd read (T1003, conf 0.87)"}}),
            (5.8, {"type": "command", "session_id": sid, "timestamp": now(),
                   "data": {"command": "sudo su -",
                            "ai_response": "[sudo] password for root:",
                            "timestamp": now()}}),
            (6.4, {"type": "mitre", "session_id": sid, "timestamp": now(),
                   "data": {"tactic": "Privilege Escalation", "technique_id": "T1548",
                            "technique_name": "Abuse Elevation Control Mechanism",
                            "confidence": 0.91}}),
            (6.7, {"type": "threat", "session_id": sid, "timestamp": now(),
                   "data": {"risk_score": 8.5, "threat_level": "HIGH"}}),
            (7.0, {"type": "timeline", "session_id": sid, "timestamp": now(),
                   "data": {"event_text": "Privilege escalation attempt (T1548, conf 0.91) — THREAT HIGH"}}),
            (8.2, {"type": "beacon", "session_id": sid, "timestamp": now(),
                   "data": {"token_id": "api_key_backup.txt",
                            "triggered_ip": "185.220.101.47",
                            "triggered_time": now(),
                            "user_agent": "curl/7.88.1"}}),
            (8.5, {"type": "timeline", "session_id": sid, "timestamp": now(),
                   "data": {"event_text": "🚨 BEACON: canary api_key_backup.txt triggered from 185.220.101.47"}}),
        ]

        async def _run() -> None:
            prev_ts = 0.0
            for abs_ts, event in script:
                interval = abs_ts - prev_ts
                if interval > 0:
                    await asyncio.sleep(interval)
                prev_ts = abs_ts
                await ws_manager.broadcast(event)

        asyncio.create_task(_run())
        return {"status": "demo_started", "events": str(len(script))}

    return router
