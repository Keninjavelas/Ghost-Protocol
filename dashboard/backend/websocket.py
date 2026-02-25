"""
dashboard/backend/websocket.py
WebSocket ConnectionManager for Ghost Protocol real-time event streaming.

Standard event envelope (all 7 types):
    {
        "type":       "session|command|intent|threat|mitre|timeline|beacon",
        "session_id": "<uuid>",
        "timestamp":  "<ISO-8601 UTC>",
        "data":       { ... }
    }
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

log = structlog.get_logger(__name__)


class ConnectionManager:
    """
    Broadcast hub for all connected WebSocket clients.
    Single-process only — scale with Redis pub/sub for multi-worker deployments.
    """

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)
        log.info("ws_client_connected", total=len(self._connections))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)
        log.info("ws_client_disconnected", total=len(self._connections))

    async def broadcast(self, event: dict[str, Any]) -> None:
        """Push a structured event envelope to every connected client."""
        if "timestamp" not in event:
            event["timestamp"] = datetime.now(timezone.utc).isoformat()

        dead: list[WebSocket] = []
        async with self._lock:
            clients = list(self._connections)

        for ws in clients:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)
            log.warning("ws_stale_connections_removed", count=len(dead))

    @staticmethod
    def make_event(
        event_type: str,
        session_id: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Return a fully-formed standard event envelope."""
        return {
            "type": event_type,
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }


def create_ws_router(manager: ConnectionManager) -> APIRouter:
    """Return an APIRouter with the /ws WebSocket endpoint."""
    ws_router = APIRouter()

    @ws_router.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket) -> None:
        await manager.connect(ws)
        try:
            while True:
                # Dashboard is server-push only; receive keeps connection alive.
                await ws.receive_text()
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            log.warning("ws_unexpected_error", error=str(exc))
        finally:
            await manager.disconnect(ws)

    return ws_router
