"""
Out-of-band alerting system for network seizure events.
Sends alerts via separate channels when primary network is compromised.
"""

import asyncio
from typing import Optional
import structlog
import aiohttp

logger = structlog.get_logger(__name__)


class OutOfBandAlert:
    """
    Multi-channel alert system using syslog, email, and external monitoring APIs.
    """

    def __init__(
        self,
        syslog_enabled: bool = True,
        external_monitor_url: Optional[str] = None
    ):
        """
        Initialize out-of-band alert system.
        
        Args:
            syslog_enabled: Whether to send alerts to syslog
            external_monitor_url: Optional external monitoring service URL
        """
        self.syslog_enabled = syslog_enabled
        self.external_monitor_url = external_monitor_url
        
        logger.info(
            "outofband_alert_initialized",
            syslog=syslog_enabled,
            external_monitor=bool(external_monitor_url)
        )

    async def send_alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        metadata: Optional[dict] = None
    ):
        """
        Send alert via all configured channels.
        
        Args:
            alert_type: Type of alert (e.g., "network_seizure", "anomaly")
            severity: Severity level ("low", "medium", "high", "critical")
            message: Human-readable alert message
            metadata: Optional additional metadata
        """
        alert_data = {
            "type": alert_type,
            "severity": severity,
            "message": message,
            "metadata": metadata or {}
        }
        
        # Syslog alert
        if self.syslog_enabled:
            self._send_syslog_alert(alert_data)
        
        # External monitoring alert
        if self.external_monitor_url:
            await self._send_external_alert(alert_data)

    def _send_syslog_alert(self, alert_data: dict):
        """Send alert to syslog."""
        try:
            # Use structlog for syslog-compatible logging
            if alert_data["severity"] == "critical":
                logger.critical("outofband_alert", **alert_data)
            elif alert_data["severity"] == "high":
                logger.error("outofband_alert", **alert_data)
            elif alert_data["severity"] == "medium":
                logger.warning("outofband_alert", **alert_data)
            else:
                logger.info("outofband_alert", **alert_data)
        except Exception as e:
            logger.error("syslog_alert_failed", error=str(e))

    async def _send_external_alert(self, alert_data: dict):
        """Send alert to external monitoring service."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.external_monitor_url,
                    json=alert_data,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        logger.info("external_alert_sent", url=self.external_monitor_url)
                    else:
                        logger.warning(
                            "external_alert_failed",
                            status=response.status,
                            url=self.external_monitor_url
                        )
        except asyncio.TimeoutError:
            logger.error("external_alert_timeout", url=self.external_monitor_url)
        except Exception as e:
            logger.error("external_alert_error", error=str(e))

    async def send_network_seizure_alert(self, session_ids: list):
        """Send emergency network seizure alert."""
        await self.send_alert(
            alert_type="network_seizure",
            severity="critical",
            message=f"Network seizure detected. {len(session_ids)} sessions cached offline.",
            metadata={"cached_sessions": session_ids}
        )
