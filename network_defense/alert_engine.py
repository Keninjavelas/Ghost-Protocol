"""
Module 7: Alert Engine
Multi-channel real-time alerting for detected threats.
"""

from typing import Dict, List, Optional
import structlog
import asyncio
import aiohttp
from datetime import datetime
from enum import Enum

logger = structlog.get_logger(__name__)


class AlertChannel(Enum):
    """Alert delivery channels."""
    DASHBOARD = "dashboard"
    EMAIL = "email"
    SYSLOG = "syslog"
    WEBHOOK = "webhook"
    SMS = "sms"


class AlertPriority(Enum):
    """Alert priority levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    URGENT = "urgent"


class AlertEngine:
    """
    Multi-channel alert engine for threat notifications.
    """

    def __init__(
        self,
        dashboard_callback=None,
        email_config: Optional[Dict] = None,
        webhook_url: Optional[str] = None,
        sms_config: Optional[Dict] = None
    ):
        """
        Initialize alert engine.
        
        Args:
            dashboard_callback: Async function to send dashboard alerts
            email_config: Email configuration dict
            webhook_url: Webhook URL for external alerts
            sms_config: SMS configuration dict
        """
        self.dashboard_callback = dashboard_callback
        self.email_config = email_config
        self.webhook_url = webhook_url
        self.sms_config = sms_config
        
        # Alert routing rules
        self.alert_rules = {
            "CRITICAL": [
                AlertChannel.DASHBOARD,
                AlertChannel.EMAIL,
                AlertChannel.WEBHOOK,
                AlertChannel.SMS,
                AlertChannel.SYSLOG
            ],
            "MALICIOUS": [
                AlertChannel.DASHBOARD,
                AlertChannel.EMAIL,
                AlertChannel.WEBHOOK,
                AlertChannel.SYSLOG
            ],
            "SUSPICIOUS": [
                AlertChannel.DASHBOARD,
                AlertChannel.SYSLOG
            ],
            "NORMAL": []
        }
        
        logger.info(
            "alert_engine_initialized",
            channels_configured=[
                channel.value for channel in AlertChannel
                if self._is_channel_configured(channel)
            ]
        )

    async def send_alert(
        self,
        threat_level: str,
        threat_data: Dict,
        session_id: Optional[str] = None
    ) -> None:
        """
        Send alert through appropriate channels based on threat level.
        
        Args:
            threat_level: NORMAL, SUSPICIOUS, MALICIOUS, or CRITICAL
            threat_data: Threat detection result
            session_id: Associated session ID if applicable
        """
        # Determine alert channels
        channels = self.alert_rules.get(threat_level, [AlertChannel.DASHBOARD])
        
        # Build alert payload
        alert = self._build_alert(threat_level, threat_data, session_id)
        
        logger.info(
            "sending_alert",
            threat_level=threat_level,
            channels=[c.value for c in channels],
            session_id=session_id
        )
        
        # Send to all channels
        tasks = []
        for channel in channels:
            if self._is_channel_configured(channel):
                tasks.append(self._send_to_channel(channel, alert))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_to_channel(
        self,
        channel: AlertChannel,
        alert: Dict
    ) -> None:
        """Send alert to specific channel."""
        try:
            if channel == AlertChannel.DASHBOARD:
                await self._send_dashboard_alert(alert)
            elif channel == AlertChannel.EMAIL:
                await self._send_email_alert(alert)
            elif channel == AlertChannel.WEBHOOK:
                await self._send_webhook_alert(alert)
            elif channel == AlertChannel.SMS:
                await self._send_sms_alert(alert)
            elif channel == AlertChannel.SYSLOG:
                await self._send_syslog_alert(alert)
            
            logger.debug("alert_sent", channel=channel.value)
        
        except Exception as e:
            logger.error(
                "alert_send_failed",
                channel=channel.value,
                error=str(e)
            )

    async def _send_dashboard_alert(self, alert: Dict) -> None:
        """Send alert to dashboard via callback."""
        if self.dashboard_callback:
            await self.dashboard_callback(alert)

    async def _send_email_alert(self, alert: Dict) -> None:
        """Send email alert."""
        if not self.email_config:
            return
        
        # TODO: Implement email sending via SMTP
        # For now, log the email that would be sent
        logger.info(
            "email_alert",
            to=self.email_config.get("recipients"),
            subject=f"[{alert['priority']}] Network Threat Detected: {alert['threat_level']}",
            body=alert["message"]
        )

    async def _send_webhook_alert(self, alert: Dict) -> None:
        """Send alert via webhook."""
        if not self.webhook_url:
            return
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=alert,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        logger.info("webhook_alert_sent", url=self.webhook_url)
                    else:
                        logger.warning(
                            "webhook_alert_failed",
                            status=response.status
                        )
        except Exception as e:
            logger.error("webhook_error", error=str(e))

    async def _send_sms_alert(self, alert: Dict) -> None:
        """Send SMS alert."""
        if not self.sms_config:
            return
        
        # TODO: Implement SMS via Twilio/AWS SNS
        logger.info(
            "sms_alert",
            to=self.sms_config.get("phone_number"),
            message=alert["short_message"]
        )

    async def _send_syslog_alert(self, alert: Dict) -> None:
        """Send alert to syslog."""
        # Use structlog to send to syslog
        log_func = logger.critical if alert["threat_level"] == "CRITICAL" else logger.warning
        
        log_func(
            "network_threat_alert",
            threat_level=alert["threat_level"],
            threat_score=alert["threat_score"],
            attacks=alert.get("attacks", []),
            source_ips=alert.get("source_ips", []),
            timestamp=alert["timestamp"]
        )

    def _build_alert(
        self,
        threat_level: str,
        threat_data: Dict,
        session_id: Optional[str]
    ) -> Dict:
        """Build standardized alert payload."""
        # Determine priority
        priority_map = {
            "NORMAL": AlertPriority.INFO,
            "SUSPICIOUS": AlertPriority.WARNING,
            "MALICIOUS": AlertPriority.CRITICAL,
            "CRITICAL": AlertPriority.URGENT
        }
        priority = priority_map.get(threat_level, AlertPriority.WARNING)
        
        # Extract attack details
        attacks = threat_data.get("attacks", [])
        attack_summary = ", ".join(
            f"{attack['type']} ({attack['severity']})"
            for attack in attacks[:3]  # First 3 attacks
        )
        
        # Extract source IPs
        source_ips = list(set(
            attack.get("source_ip", "unknown")
            for attack in attacks
        ))
        
        # Build message
        threat_score = threat_data.get("threat_score", 0)
        message = (
            f"Network threat detected: {threat_level} "
            f"(Score: {threat_score}/100)\n"
            f"Attacks: {attack_summary or 'See details'}\n"
            f"Source IPs: {', '.join(source_ips[:5])}\n"
            f"Recommended: {threat_data.get('recommended_action', 'Review logs')}"
        )
        
        short_message = (
            f"{threat_level}: {attack_summary or 'Network threat detected'} "
            f"(Score: {threat_score}/100)"
        )
        
        return {
            "alert_id": f"alert_{datetime.utcnow().timestamp()}",
            "timestamp": datetime.utcnow().isoformat(),
            "priority": priority.value,
            "threat_level": threat_level,
            "threat_score": threat_score,
            "session_id": session_id,
            "message": message,
            "short_message": short_message,
            "attacks": attacks,
            "source_ips": source_ips,
            "recommended_action": threat_data.get("recommended_action"),
            "ai_classification": threat_data.get("ai_classification"),
        }

    def _is_channel_configured(self, channel: AlertChannel) -> bool:
        """Check if alert channel is configured."""
        if channel == AlertChannel.DASHBOARD:
            return self.dashboard_callback is not None
        elif channel == AlertChannel.EMAIL:
            return self.email_config is not None
        elif channel == AlertChannel.WEBHOOK:
            return self.webhook_url is not None
        elif channel == AlertChannel.SMS:
            return self.sms_config is not None
        elif channel == AlertChannel.SYSLOG:
            return True  # Always available via structlog
        return False
