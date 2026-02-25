"""
tracking/beacon_listener.py
FastAPI router that receives HTTP callbacks from triggered canary tokens.

When an attacker opens/fetches a bait file containing a canary URL,
their HTTP client (browser, wget, curl) hits this endpoint.
The hit is logged and an alert is sent to the dashboard.
"""
from __future__ import annotations

import uuid
from typing import Optional

import structlog
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse

from tracking.canary_manager import CanaryManager
from telemetry.logger import TelemetryLogger

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/beacon", tags=["beacon"])


def create_beacon_router(
    canary_manager: CanaryManager,
    telemetry: TelemetryLogger,
) -> APIRouter:
    """Factory: returns a configured beacon router with injected deps."""

    @router.get("/{token_id}")
    async def beacon_hit(token_id: str, request: Request) -> JSONResponse:
        """
        Called when an attacker's machine fetches a canary-embedded URL.
        Logs the trigger event to telemetry and database.
        """
        client_ip: str = request.client.host if request.client else "unknown"
        user_agent: Optional[str] = request.headers.get("user-agent")

        log.warning(
            "beacon_callback_received",
            token_id=token_id,
            client_ip=client_ip,
            user_agent=user_agent,
        )

        session_id_str = canary_manager.mark_triggered(
            token_id=token_id,
            triggered_ip=client_ip,
        )

        if session_id_str is None:
            # Unknown token – still log it
            log.warning("beacon_unknown_token", token_id=token_id, ip=client_ip)
            # Return a 200 to not tip off the attacker
            return JSONResponse(content={"status": "ok"})

        try:
            session_uuid = uuid.UUID(session_id_str)
            await telemetry.log_beacon(
                session_id=session_uuid,
                token_id=token_id,
                triggered_ip=client_ip,
                user_agent=user_agent,
            )
        except Exception as exc:
            log.warning("beacon_telemetry_error", error=str(exc))

        # Return a plausible-looking 200 response (don't reveal it's a trap)
        return JSONResponse(content={"status": "ok"})

    return router
