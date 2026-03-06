"""
Dead man's switch heartbeat monitoring.
Detects network isolation by tracking heartbeat failures.
"""

import asyncio
from typing import Callable, Optional
from datetime import datetime, timedelta
import structlog

logger = structlog.get_logger(__name__)


class DeadMansSwitch:
    """
    Monitors heartbeat signals and triggers seizure detection on prolonged silence.
    """

    def __init__(
        self,
        heartbeat_interval: float = 30.0,
        failure_threshold: int = 4,
        on_network_seizure: Optional[Callable] = None
    ):
        """
        Initialize dead man's switch.
        
        Args:
            heartbeat_interval: Expected time between heartbeats (seconds)
            failure_threshold: Number of consecutive failures before triggering
            on_network_seizure: Callback function when seizure detected
        """
        self.heartbeat_interval = heartbeat_interval
        self.failure_threshold = failure_threshold
        self.on_network_seizure = on_network_seizure
        
        self._last_heartbeat: Optional[datetime] = None
        self._consecutive_failures = 0
        self._monitoring_task: Optional[asyncio.Task] = None
        self._seizure_detected = False
        
        logger.info(
            "deadmans_switch_initialized",
            interval_seconds=heartbeat_interval,
            threshold=failure_threshold
        )

    async def start(self):
        """Start heartbeat monitoring."""
        if self._monitoring_task is not None:
            logger.warning("deadmans_switch_already_running")
            return
        
        self._last_heartbeat = datetime.utcnow()
        self._consecutive_failures = 0
        self._seizure_detected = False
        
        self._monitoring_task = asyncio.create_task(self._monitor_loop())
        logger.info("deadmans_switch_started")

    async def stop(self):
        """Stop heartbeat monitoring."""
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
            self._monitoring_task = None
        logger.info("deadmans_switch_stopped")

    def heartbeat(self):
        """Record a heartbeat signal."""
        self._last_heartbeat = datetime.utcnow()
        self._consecutive_failures = 0
        
        if self._seizure_detected:
            logger.info("network_restored", note="Heartbeat received after seizure")
            self._seizure_detected = False

    async def _monitor_loop(self):
        """Background monitoring loop."""
        try:
            while True:
                await asyncio.sleep(self.heartbeat_interval)
                
                # Check if heartbeat is overdue
                time_since_last = (datetime.utcnow() - self._last_heartbeat).total_seconds()
                
                if time_since_last > self.heartbeat_interval * 1.5:
                    self._consecutive_failures += 1
                    
                    logger.warning(
                        "heartbeat_timeout",
                        consecutive_failures=self._consecutive_failures,
                        time_since_last_seconds=time_since_last
                    )
                    
                    # Trigger seizure detection if threshold exceeded
                    if self._consecutive_failures >= self.failure_threshold and not self._seizure_detected:
                        self._seizure_detected = True
                        await self._trigger_network_seizure()
                else:
                    self._consecutive_failures = 0
        
        except asyncio.CancelledError:
            logger.info("monitor_loop_cancelled")
            raise

    async def _trigger_network_seizure(self):
        """Trigger network seizure callback."""
        logger.critical(
            "network_seizure_detected",
            consecutive_failures=self._consecutive_failures,
            threshold=self.failure_threshold
        )
        
        if self.on_network_seizure:
            try:
                if asyncio.iscoroutinefunction(self.on_network_seizure):
                    await self.on_network_seizure()
                else:
                    self.on_network_seizure()
            except Exception as e:
                logger.error("network_seizure_callback_failed", error=str(e))

    @property
    def is_seized(self) -> bool:
        """Check if network seizure is currently detected."""
        return self._seizure_detected
