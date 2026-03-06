"""
Real-time alert engine with multi-channel notifications.
"""

from typing import List, Dict, Optional, Callable
from datetime import datetime, timezone
from enum import Enum
import asyncio

import structlog

logger = structlog.get_logger(__name__)


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AlertChannel(str, Enum):
    """Alert notification channels."""
    DASHBOARD = "DASHBOARD"
    EMAIL = "EMAIL"
    SYSLOG = "SYSLOG"
    WEBHOOK = "WEBHOOK"


class AlertEngine:
    """
    Multi-channel alert system for real-time threat notifications.
    Supports dashboard, email, syslog, and webhook channels.
    """

    def __init__(self):
        """Initialize alert engine."""
        self.alerts: List[Dict] = []
        self.max_alerts = 10000
        
        # Alert handlers
        self._channel_handlers: Dict[AlertChannel, Callable] = {
            AlertChannel.DASHBOARD: self._send_dashboard_alert,
            AlertChannel.EMAIL: self._send_email_alert,
            AlertChannel.SYSLOG: self._send_syslog_alert,
            AlertChannel.WEBHOOK: self._send_webhook_alert,
        }
        
        # Configuration
        self._enabled_channels = [AlertChannel.DASHBOARD, AlertChannel.SYSLOG]
        self._email_config = None
        self._webhook_url = None
        
        logger.info(
            "alert_engine_initialized",
            channels=len(self._enabled_channels)
        )

    async def send_alert(
        self,
        alert_type: str,
        severity: AlertSeverity,
        message: str,
        details: Optional[Dict] = None,
        channels: Optional[List[AlertChannel]] = None
    ) -> None:
        """
        Send alert via configured channels.
        
        Args:
            alert_type: Type of alert
            severity: Alert severity
            message: Alert message
            details: Additional details
            channels: Override default channels
        """
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": alert_type,
            "severity": severity.value,
            "message": message,
            "details": details or {},
        }
        
        # Store in history
        self.alerts.append(alert)
        if len(self.alerts) > self.max_alerts:
            self.alerts.pop(0)
        
        # Determine channels
        target_channels = channels or self._enabled_channels
        
        # Send via each channel
        for channel in target_channels:
            try:
                handler = self._channel_handlers.get(channel)
                if handler:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(alert)
                    else:
                        handler(alert)
            except Exception as e:
                logger.error(
                    "alert_send_failed",
                    channel=channel.value,
                    error=str(e)
                )
        
        # Log alert
        logger.info(
            "alert_sent",
            alert_type=alert_type,
            severity=severity.value,
            channels=[c.value for c in target_channels]
        )

    def _send_dashboard_alert(self, alert: Dict) -> None:
        """Send alert to dashboard (stored for WebSocket)."""
        # In production, would push to WebSocket
        logger.info("dashboard_alert", alert_type=alert.get("alert_type"))

    async def _send_email_alert(self, alert: Dict) -> None:
        """Send email alert."""
        if not self._email_config:
            return
        
        # Simplified: would use SMTP
        logger.info("email_alert_sent", to=self._email_config.get("to"))

    def _send_syslog_alert(self, alert: Dict) -> None:
        """Send syslog alert."""
        if alert["severity"] == AlertSeverity.CRITICAL.value:
            logger.critical("syslog_alert", **alert)
        elif alert["severity"] == AlertSeverity.WARNING.value:
            logger.warning("syslog_alert", **alert)
        else:
            logger.info("syslog_alert", **alert)

    async def _send_webhook_alert(self, alert: Dict) -> None:
        """Send webhook alert."""
        if not self._webhook_url:
            return
        
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self._webhook_url,
                    json=alert,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    logger.info("webhook_alert_sent", status=response.status)
        except Exception as e:
            logger.error("webhook_alert_failed", error=str(e))

    def configure_email(self, config: Dict) -> None:
        """Configure email channel."""
        self._email_config = config
        if AlertChannel.EMAIL not in self._enabled_channels:
            self._enabled_channels.append(AlertChannel.EMAIL)

    def configure_webhook(self, url: str) -> None:
        """Configure webhook channel."""
        self._webhook_url = url
        if AlertChannel.WEBHOOK not in self._enabled_channels:
            self._enabled_channels.append(AlertChannel.WEBHOOK)

    def get_recent_alerts(self, count: int = 100) -> List[Dict]:
        """Get recent alerts."""
        return self.alerts[-count:]

    def get_alerts_by_type(self, alert_type: str) -> List[Dict]:
        """Get alerts by type."""
        return [a for a in self.alerts if a["alert_type"] == alert_type]

    def get_critical_alerts(self) -> List[Dict]:
        """Get all critical alerts."""
        return [
            a for a in self.alerts
            if a["severity"] == AlertSeverity.CRITICAL.value
        ]

    @property
    def stats(self) -> Dict:
        """Get alert statistics."""
        severity_counts = {
            "INFO": 0,
            "WARNING": 0,
            "CRITICAL": 0,
        }
        
        for alert in self.alerts:
            severity = alert.get("severity", "INFO")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "total_alerts": len(self.alerts),
            "severity_breakdown": severity_counts,
            "enabled_channels": [c.value for c in self._enabled_channels],
        }
