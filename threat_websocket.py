"""
WebSocket handler for real-time threat events.
"""

from typing import Set
from fastapi import WebSocket, WebSocketDisconnect
import asyncio
import json
import structlog
from datetime import datetime, timezone

logger = structlog.get_logger(__name__)


class ThreatEventManager:
    """Manages real-time threat event subscriptions."""

    def __init__(self):
        """Initialize event manager."""
        self.active_connections: Set[WebSocket] = set()
        self._broadcast_task: asyncio.Task = None

    async def connect(self, websocket: WebSocket):
        """Accept and register WebSocket connection."""
        try:
            await websocket.accept()
            self.active_connections.add(websocket)
            logger.info("websocket_connected", client=websocket.client)
            
            # Send welcome message
            await websocket.send_json({
                "type": "connection",
                "status": "connected",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "message": "Real-time threat monitoring active"
            })
        except Exception as e:
            logger.error("websocket_accept_failed", error=str(e))

    async def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection."""
        try:
            self.active_connections.discard(websocket)
            logger.info(
                "websocket_disconnected",
                client=websocket.client,
                remaining=len(self.active_connections)
            )
        except Exception as e:
            logger.error("websocket_disconnect_error", error=str(e))

    async def broadcast_threat(
        self,
        threat_data: dict,
        priority: str = "normal"
    ):
        """Broadcast threat event to all connected clients."""
        payload = {
            "type": "threat_detected",
            "priority": priority,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": threat_data
        }

        disconnected = set()
        
        for websocket in self.active_connections:
            try:
                await websocket.send_json(payload)
            except Exception as e:
                logger.warning(
                    "websocket_send_failed",
                    error=str(e),
                    client=websocket.client
                )
                disconnected.add(websocket)
        
        # Clean up disconnected clients
        for ws in disconnected:
            await self.disconnect(ws)

    async def broadcast_alert(self, alert_data: dict):
        """Broadcast security alert."""
        payload = {
            "type": "alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": alert_data
        }

        disconnected = set()
        
        for websocket in self.active_connections:
            try:
                await websocket.send_json(payload)
            except Exception as e:
                logger.warning(
                    "websocket_alert_send_failed",
                    error=str(e),
                    client=websocket.client
                )
                disconnected.add(websocket)
        
        for ws in disconnected:
            await self.disconnect(ws)

    async def broadcast_status_update(self, status: dict):
        """Broadcast system status update."""
        payload = {
            "type": "status_update",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": status
        }

        disconnected = set()
        
        for websocket in self.active_connections:
            try:
                await websocket.send_json(payload)
            except Exception as e:
                logger.warning(
                    "websocket_status_send_failed",
                    error=str(e),
                    client=websocket.client
                )
                disconnected.add(websocket)
        
        for ws in disconnected:
            await self.disconnect(ws)

    async def send_message(self, websocket: WebSocket, message: dict):
        """Send message to specific WebSocket."""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(
                "websocket_send_failed",
                error=str(e),
                client=websocket.client
            )
            await self.disconnect(websocket)

    def get_active_connections(self) -> int:
        """Get count of active connections."""
        return len(self.active_connections)


# Global event manager instance
threat_event_manager = ThreatEventManager()


async def websocket_handler(websocket: WebSocket):
    """Handle WebSocket connections."""
    await threat_event_manager.connect(websocket)
    
    try:
        while True:
            # Receive messages from client
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                
                # Handle different message types
                if message.get("type") == "ping":
                    await threat_event_manager.send_message(
                        websocket,
                        {"type": "pong", "timestamp": datetime.now(timezone.utc).isoformat()}
                    )
                
                elif message.get("type") == "request_status":
                    from detection_api import get_orchestrator
                    orchestrator = get_orchestrator()
                    status = orchestrator.get_network_status()
                    await threat_event_manager.send_message(
                        websocket,
                        {
                            "type": "status",
                            "data": status,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    )
                
                elif message.get("type") == "request_threats":
                    from detection_api import get_orchestrator
                    orchestrator = get_orchestrator()
                    threats = orchestrator.get_threats(limit=50)
                    await threat_event_manager.send_message(
                        websocket,
                        {
                            "type": "threats",
                            "data": threats,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    )
                
                else:
                    logger.warning(
                        "unknown_websocket_message",
                        message_type=message.get("type")
                    )
            
            except json.JSONDecodeError:
                logger.warning("invalid_websocket_json", data=data)
    
    except WebSocketDisconnect:
        await threat_event_manager.disconnect(websocket)
        logger.info("client_disconnected", client=websocket.client)
    
    except Exception as e:
        logger.error("websocket_error", error=str(e))
        await threat_event_manager.disconnect(websocket)
