"""
Security event logging for compliance and forensics.
"""

from typing import List, Dict, Optional
from datetime import datetime, timezone
from pathlib import Path
import asyncio
import json

import structlog

logger = structlog.get_logger(__name__)


class SecurityLogger:
    """
    Logs all security events for compliance and forensic analysis.
    """

    def __init__(self, log_dir: str = "/var/ghost_protocol/security_logs"):
        """
        Initialize security logger.
        
        Args:
            log_dir: Directory for security logs
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory buffer
        self._buffer: List[Dict] = []
        self._buffer_size = 500
        
        logger.info("security_logger_initialized", log_dir=str(self.log_dir))

    async def log_threat(
        self,
        threat_type: str,
        source_ip: str,
        confidence: float,
        details: Dict
    ) -> None:
        """Log threat event."""
        entry = {
            "event_type": "THREAT",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "threat_type": threat_type,
            "source_ip": source_ip,
            "confidence": confidence,
            "details": details,
        }
        
        self._log_entry(entry)

    async def log_response(
        self,
        action: str,
        source_ip: str,
        reason: str
    ) -> None:
        """Log response action."""
        entry = {
            "event_type": "RESPONSE",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "target_ip": source_ip,
            "reason": reason,
        }
        
        self._log_entry(entry)

    async def log_access(
        self,
        user: str,
        action: str,
        resource: str,
        result: str
    ) -> None:
        """Log access event."""
        entry = {
            "event_type": "ACCESS",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": user,
            "action": action,
            "resource": resource,
            "result": result,
        }
        
        self._log_entry(entry)

    def _log_entry(self, entry: Dict) -> None:
        """Add entry to buffer."""
        self._buffer.append(entry)
        
        if len(self._buffer) >= self._buffer_size:
            asyncio.run(self.flush())

    async def flush(self) -> None:
        """Write buffer to disk."""
        if not self._buffer:
            return
        
        try:
            # Use date-based filename
            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            log_file = self.log_dir / f"security_{date_str}.jsonl"
            
            with open(log_file, "a") as f:
                for entry in self._buffer:
                    f.write(json.dumps(entry) + "\n")
            
            count = len(self._buffer)
            self._buffer.clear()
            logger.info("security_logs_flushed", count=count)
        
        except Exception as e:
            logger.error("security_log_flush_failed", error=str(e))

    def query_logs(
        self,
        event_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        days: int = 7
    ) -> List[Dict]:
        """Query security logs."""
        results = []
        
        try:
            # Read recent log files
            import glob
            log_files = sorted(
                self.log_dir.glob("security_*.jsonl"),
                reverse=True
            )[:days]
            
            for log_file in log_files:
                with open(log_file) as f:
                    for line in f:
                        try:
                            entry = json.loads(line)
                            
                            if event_type and entry.get("event_type") != event_type:
                                continue
                            
                            if source_ip and entry.get("source_ip") != source_ip:
                                continue
                            
                            results.append(entry)
                        
                        except json.JSONDecodeError:
                            continue
        
        except Exception as e:
            logger.error("query_failed", error=str(e))
        
        return results
