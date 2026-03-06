"""
Module 10: Automated Response System
Automated actions in response to detected threats.
"""

from typing import Dict, List, Optional, Set
import structlog
import asyncio
from datetime import datetime, timedelta
from enum import Enum

logger = structlog.get_logger(__name__)


class ResponseAction(Enum):
    """Available automated response actions."""
    BLOCK_IP = "block_ip"
    THROTTLE_IP = "throttle_ip"
    QUARANTINE_IP = "quarantine_ip"
    RATE_LIMIT = "rate_limit"
    LOG_ONLY = "log_only"
    ALERT_ADMIN = "alert_admin"
    DISCONNECT_SESSION = "disconnect_session"


class ResponseEngine:
    """
    Automated response engine for threat mitigation.
    """

    def __init__(
        self,
        enabled: bool = True,
        dry_run: bool = True,
        auto_block_threshold: float = 80.0,
        auto_throttle_threshold: float = 60.0,
        alert_callback=None
    ):
        """
        Initialize response engine.
        
        Args:
            enabled: Enable automated responses
            dry_run: Log actions without executing (for testing)
            auto_block_threshold: Threat score threshold for auto-blocking
            auto_throttle_threshold: Threat score threshold for throttling
            alert_callback: Callback for sending alerts
        """
        self.enabled = enabled
        self.dry_run = dry_run
        self.auto_block_threshold = auto_block_threshold
        self.auto_throttle_threshold = auto_throttle_threshold
        self.alert_callback = alert_callback
        
        # Blocked IPs and expiry times
        self.blocked_ips: Dict[str, datetime] = {}
        self.throttled_ips: Dict[str, Dict] = {}
        
        # Response history
        self.response_history: List[Dict] = []
        
        logger.info(
            "response_engine_initialized",
            enabled=enabled,
            dry_run=dry_run,
            auto_block_threshold=auto_block_threshold,
            auto_throttle_threshold=auto_throttle_threshold
        )

    async def execute_response(
        self,
        threat_level: str,
        threat_score: float,
        threat_data: Dict,
        session_id: Optional[str] = None
    ) -> List[ResponseAction]:
        """
        Execute automated response based on threat level.
        
        Args:
            threat_level: NORMAL, SUSPICIOUS, MALICIOUS, or CRITICAL
            threat_score: Threat score (0-100)
            threat_data: Full threat detection result
            session_id: Associated session ID
        
        Returns:
            List of actions executed
        """
        if not self.enabled:
            return []
        
        # Determine appropriate actions
        actions = self._determine_actions(threat_level, threat_score, threat_data)
        
        if not actions:
            return []
        
        logger.info(
            "executing_responses",
            threat_level=threat_level,
            threat_score=threat_score,
            actions=[a.value for a in actions],
            dry_run=self.dry_run
        )
        
        # Execute each action
        executed_actions = []
        for action in actions:
            try:
                success = await self._execute_action(
                    action,
                    threat_data,
                    session_id
                )
                
                if success:
                    executed_actions.append(action)
                    self._log_response(action, threat_data, session_id)
            
            except Exception as e:
                logger.error(
                    "response_action_failed",
                    action=action.value,
                    error=str(e)
                )
        
        return executed_actions

    def _determine_actions(
        self,
        threat_level: str,
        threat_score: float,
        threat_data: Dict
    ) -> List[ResponseAction]:
        """Determine appropriate response actions."""
        actions = []
        
        # Always log
        actions.append(ResponseAction.LOG_ONLY)
        
        # Critical threats - block immediately
        if threat_level == "CRITICAL" or threat_score >= self.auto_block_threshold:
            actions.append(ResponseAction.BLOCK_IP)
            actions.append(ResponseAction.ALERT_ADMIN)
            actions.append(ResponseAction.DISCONNECT_SESSION)
        
        # Malicious threats - throttle or block
        elif threat_level == "MALICIOUS" or threat_score >= self.auto_throttle_threshold:
            actions.append(ResponseAction.THROTTLE_IP)
            actions.append(ResponseAction.RATE_LIMIT)
            actions.append(ResponseAction.ALERT_ADMIN)
        
        # Suspicious - rate limit only
        elif threat_level == "SUSPICIOUS":
            actions.append(ResponseAction.RATE_LIMIT)
        
        return actions

    async def _execute_action(
        self,
        action: ResponseAction,
        threat_data: Dict,
        session_id: Optional[str]
    ) -> bool:
        """Execute a specific response action."""
        # Extract source IPs
        source_ips = self._extract_source_ips(threat_data)
        
        if not source_ips and action != ResponseAction.LOG_ONLY:
            logger.warning("no_source_ips_found", action=action.value)
            return False
        
        # Execute action
        if action == ResponseAction.BLOCK_IP:
            return await self._block_ips(source_ips, duration_hours=24)
        
        elif action == ResponseAction.THROTTLE_IP:
            return await self._throttle_ips(source_ips, rate_limit=10)
        
        elif action == ResponseAction.QUARANTINE_IP:
            return await self._quarantine_ips(source_ips)
        
        elif action == ResponseAction.RATE_LIMIT:
            return await self._apply_rate_limit(source_ips, rate_limit=100)
        
        elif action == ResponseAction.DISCONNECT_SESSION:
            return await self._disconnect_session(session_id)
        
        elif action == ResponseAction.ALERT_ADMIN:
            return await self._alert_admin(threat_data, session_id)
        
        elif action == ResponseAction.LOG_ONLY:
            return True
        
        return False

    async def _block_ips(
        self,
        ip_addresses: List[str],
        duration_hours: int = 24
    ) -> bool:
        """
        Block IP addresses for specified duration.
        
        In production, this would:
        - Add iptables rules
        - Update firewall configuration
        - Add to network ACL
        """
        expiry = datetime.utcnow() + timedelta(hours=duration_hours)
        
        for ip in ip_addresses:
            self.blocked_ips[ip] = expiry
            
            if self.dry_run:
                logger.info(
                    "dry_run_block_ip",
                    ip=ip,
                    duration_hours=duration_hours,
                    expiry=expiry.isoformat()
                )
            else:
                # Execute actual blocking
                # TODO: Implement iptables/firewall integration
                logger.warning(
                    "blocking_ip",
                    ip=ip,
                    duration_hours=duration_hours,
                    expiry=expiry.isoformat()
                )
                
                # Example: subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        
        return True

    async def _throttle_ips(
        self,
        ip_addresses: List[str],
        rate_limit: int = 10
    ) -> bool:
        """Throttle IP addresses to limited rate."""
        for ip in ip_addresses:
            self.throttled_ips[ip] = {
                "rate_limit": rate_limit,
                "expires": datetime.utcnow() + timedelta(hours=1)
            }
            
            if self.dry_run:
                logger.info(
                    "dry_run_throttle_ip",
                    ip=ip,
                    rate_limit=rate_limit
                )
            else:
                logger.warning(
                    "throttling_ip",
                    ip=ip,
                    rate_limit=rate_limit
                )
                
                # TODO: Implement rate limiting via iptables or application layer
        
        return True

    async def _quarantine_ips(self, ip_addresses: List[str]) -> bool:
        """Quarantine IPs to isolated network segment."""
        for ip in ip_addresses:
            if self.dry_run:
                logger.info("dry_run_quarantine_ip", ip=ip)
            else:
                logger.warning("quarantining_ip", ip=ip)
                # TODO: Implement VLAN/network segmentation
        
        return True

    async def _apply_rate_limit(
        self,
        ip_addresses: List[str],
        rate_limit: int = 100
    ) -> bool:
        """Apply soft rate limiting."""
        for ip in ip_addresses:
            if self.dry_run:
                logger.info("dry_run_rate_limit", ip=ip, limit=rate_limit)
            else:
                logger.info("rate_limiting_ip", ip=ip, limit=rate_limit)
                # TODO: Implement application-level rate limiting
        
        return True

    async def _disconnect_session(self, session_id: Optional[str]) -> bool:
        """Disconnect active session."""
        if not session_id:
            return False
        
        if self.dry_run:
            logger.info("dry_run_disconnect_session", session_id=session_id)
        else:
            logger.warning("disconnecting_session", session_id=session_id)
            # TODO: Integrate with session manager to terminate session
        
        return True

    async def _alert_admin(
        self,
        threat_data: Dict,
        session_id: Optional[str]
    ) -> bool:
        """Send alert to administrator."""
        if self.alert_callback:
            await self.alert_callback(threat_data, session_id)
        
        logger.critical(
            "admin_alert_sent",
            threat_level=threat_data.get("threat_level"),
            threat_score=threat_data.get("threat_score")
        )
        
        return True

    def _extract_source_ips(self, threat_data: Dict) -> List[str]:
        """Extract source IP addresses from threat data."""
        ips = set()
        
        # From attacks
        for attack in threat_data.get("attacks", []):
            if "source_ip" in attack:
                ips.add(attack["source_ip"])
        
        return list(ips)

    def _log_response(
        self,
        action: ResponseAction,
        threat_data: Dict,
        session_id: Optional[str]
    ) -> None:
        """Log response action to history."""
        self.response_history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": action.value,
            "threat_level": threat_data.get("threat_level"),
            "threat_score": threat_data.get("threat_score"),
            "session_id": session_id,
            "dry_run": self.dry_run
        })

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        if ip not in self.blocked_ips:
            return False
        
        # Check if block expired
        if datetime.utcnow() > self.blocked_ips[ip]:
            del self.blocked_ips[ip]
            return False
        
        return True

    def get_response_history(self, limit: int = 100) -> List[Dict]:
        """Get recent response actions."""
        return self.response_history[-limit:]
