"""
Automated response orchestrator.
Handles IP blocking, traffic throttling, and emergency protocols.
"""

from typing import List, Dict, Optional
from datetime import datetime, timezone, timedelta
from enum import Enum
import asyncio

import structlog

logger = structlog.get_logger(__name__)


class ResponseAction(str, Enum):
    """Automatic response actions."""
    NONE = "NONE"
    MONITOR = "MONITOR"
    THROTTLE = "THROTTLE"
    BLOCK_IP = "BLOCK_IP"
    DISABLE_DEVICE = "DISABLE_DEVICE"
    ALERT_ADMIN = "ALERT_ADMIN"
    SHUTDOWN_SERVICE = "SHUTDOWN_SERVICE"


class ResponseOrchestrator:
    """
    Orchestrates automated responses to threats.
    Includes IP blocking, traffic shaping, and emergency protocols.
    """

    def __init__(self):
        """Initialize response orchestrator."""
        self.blocked_ips: List[str] = []
        self.throttled_connections: Dict[str, float] = {}
        self.response_history: List[Dict] = []
        
        #Thresholds for automatic responses
        self.threat_score_threshold = 0.8
        
        logger.info("response_orchestrator_initialized")

    async def respond_to_threat(
        self,
        threat_result,
        threat_score: float
    ) -> Optional[ResponseAction]:
        """
        Determine and execute response to threat.
        
        Args:
            threat_result: ThreatDetectionResult
            threat_score: Overall threat score (0-1)
            
        Returns:
            ResponseAction taken
        """
        # Determine action based on threat score and type
        action = self._determine_action(threat_result, threat_score)
        
        if action != ResponseAction.NONE:
            await self._execute_action(action, threat_result)
        
        return action

    def _determine_action(
        self,
        threat_result,
        threat_score: float
    ) -> ResponseAction:
        """Determine response action."""
        # Critical threats triggered action
        if threat_result.threat_level.value == "CRITICAL":
            if threat_score > 0.95:
                return ResponseAction.BLOCK_IP
            else:
                return ResponseAction.THROTTLE
        
        # Malicious threats: block if high confidence
        elif threat_result.threat_level.value == "MALICIOUS":
            if threat_score > 0.85:
                return ResponseAction.BLOCK_IP
            else:
                return ResponseAction.MONITOR
        
        # Suspicious: monitor
        else:
            return ResponseAction.MONITOR

    async def _execute_action(
        self,
        action: ResponseAction,
        threat_result
    ) -> None:
        """Execute response action."""
        source_ip = threat_result.source_ip
        
        try:
            if action == ResponseAction.BLOCK_IP:
                await self._block_ip(source_ip)
            
            elif action == ResponseAction.THROTTLE:
                await self._throttle_connection(source_ip)
            
            elif action == ResponseAction.MONITOR:
                await self._monitor_connection(source_ip)
            
            # Log action
            self.response_history.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": source_ip,
                "action": action.value,
                "attack_type": threat_result.attack_type,
                "threat_level": threat_result.threat_level.value,
            })
        
        except Exception as e:
            logger.error("response_execution_failed", error=str(e))

    async def _block_ip(self, source_ip: str) -> None:
        """Block IP address."""
        if source_ip not in self.blocked_ips:
            self.blocked_ips.append(source_ip)
            logger.critical("ip_blocked", source_ip=source_ip)

    async def _throttle_connection(self, source_ip: str) -> None:
        """Throttle connection from IP."""
        # Set bandwidth limit (simplified)
        self.throttled_connections[source_ip] = 0.5  # 50% bandwidth
        logger.warning("connection_throttled", source_ip=source_ip)

    async def _monitor_connection(self, source_ip: str) -> None:
        """Monitor connection (no action)."""
        logger.info("connection_monitored", source_ip=source_ip)

    def is_ip_blocked(self, source_ip: str) -> bool:
        """Check if IP is blocked."""
        return source_ip in self.blocked_ips

    def unblock_ip(self, source_ip: str) -> None:
        """Unblock IP address."""
        if source_ip in self.blocked_ips:
            self.blocked_ips.remove(source_ip)
            logger.info("ip_unblocked", source_ip=source_ip)

    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IPs."""
        return self.blocked_ips.copy()

    def get_throttled_connections(self) -> Dict[str, float]:
        """Get throttled connections and limits."""
        return self.throttled_connections.copy()

    def get_response_history(
        self,
        source_ip: Optional[str] = None,
        action: Optional[ResponseAction] = None
    ) -> List[Dict]:
        """Query response history."""
        results = self.response_history
        
        if source_ip:
            results = [r for r in results if r["source_ip"] == source_ip]
        
        if action:
            results = [r for r in results if r["action"] == action.value]
        
        return results

    @property
    def stats(self) -> Dict:
        """Get response statistics."""
        actions_taken = {}
        for entry in self.response_history:
            action = entry["action"]
            actions_taken[action] = actions_taken.get(action, 0) + 1
        
        return {
            "total_responses": len(self.response_history),
            "blocked_ips": len(self.blocked_ips),
            "throttled_connections": len(self.throttled_connections),
            "actions_by_type": actions_taken,
        }
