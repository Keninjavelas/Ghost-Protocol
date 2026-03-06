"""
Structured detection logging system.
Persists all threats and events for analytics and auditing.
"""

from typing import List, Dict, Optional
from datetime import datetime, timezone
from pathlib import Path
import json
import asyncio

import structlog

logger = structlog.get_logger(__name__)


class DetectionLogger:
    """
    Logs all detection events in structured format.
    Supports async writing and querying.
    """

    def __init__(self, log_dir: str = "/var/ghost_protocol/detection_logs"):
        """
        Initialize detection logger.
        
        Args:
            log_dir: Directory for log files
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory buffer before writing
        self._log_buffer: List[Dict] = []
        self._buffer_size = 100
        self._write_task: Optional[asyncio.Task] = None
        
        logger.info("detection_logger_initialized", log_dir=str(self.log_dir))

    async def log_threat(self, threat_result) -> None:
        """
        Log a threat detection event.
        
        Args:
            threat_result: ThreatDetectionResult object
        """
        log_entry = {
            "timestamp": threat_result.timestamp,
            "event_type": "threat_detection",
            "attack_type": threat_result.attack_type,
            "threat_level": threat_result.threat_level.value,
            "source_ip": threat_result.source_ip,
            "dest_ip": threat_result.dest_ip,
            "confidence": threat_result.confidence,
            "details": threat_result.details,
            "rules_triggered": threat_result.rules_triggered,
        }
        
        self._log_buffer.append(log_entry)
        
        # Flush buffer if needed
        if len(self._log_buffer) >= self._buffer_size:
            await self.flush()

    async def log_alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        metadata: Optional[Dict] = None
    ) -> None:
        """Log a security alert."""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "alert",
            "alert_type": alert_type,
            "severity": severity,
            "message": message,
            "metadata": metadata or {},
        }
        
        self._log_buffer.append(log_entry)
        
        if len(self._log_buffer) >= self._buffer_size:
            await self.flush()

    async def log_packet(
        self,
        packet,
        source_ip: str
    ) -> None:
        """Log packet event (verbose)."""
        log_entry = {
            "timestamp": packet.timestamp,
            "event_type": "packet",
            "source_ip": packet.source_ip,
            "dest_ip": packet.dest_ip,
            "protocol": packet.protocol,
            "packet_size": packet.packet_size,
        }
        
        self._log_buffer.append(log_entry)

    async def flush(self) -> None:
        """Write buffer to disk."""
        if not self._log_buffer:
            return
        
        try:
            # Create daily log file
            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            log_file = self.log_dir / f"threats_{date_str}.jsonl"
            
            # Append to file
            with open(log_file, "a") as f:
                for entry in self._log_buffer:
                    f.write(json.dumps(entry) + "\n")
            
            count = len(self._log_buffer)
            self._log_buffer.clear()
            
            logger.info("detection_logs_flushed", count=count, file=str(log_file))
        
        except Exception as e:
            logger.error("log_flush_failed", error=str(e))

    def query_threats(
        self,
        source_ip: Optional[str] = None,
        threat_type: Optional[str] = None,
        min_confidence: float = 0.0
    ) -> List[Dict]:
        """
        Query threat logs.
        
        Args:
            source_ip: Filter by source IP
            threat_type: Filter by attack type
            min_confidence: Minimum confidence threshold
            
        Returns:
            List of matching threat logs
        """
        results = []
        
        try:
            # Read all log files
            for log_file in self.log_dir.glob("threats_*.jsonl"):
                with open(log_file) as f:
                    for line in f:
                        try:
                            entry = json.loads(line)
                            
                            # Apply filters
                            if entry.get("event_type") != "threat_detection":
                                continue
                            
                            if source_ip and entry.get("source_ip") != source_ip:
                                continue
                            
                            if threat_type and entry.get("attack_type") != threat_type:
                                continue
                            
                            if entry.get("confidence", 0) < min_confidence:
                                continue
                            
                            results.append(entry)
                        
                        except json.JSONDecodeError:
                            continue
        
        except Exception as e:
            logger.error("query_failed", error=str(e))
        
        return results

    def get_statistics(self) -> Dict:
        """Get detection statistics from logs."""
        threats_by_type = {}
        threats_by_level = {"NORMAL": 0, "SUSPICIOUS": 0, "MALICIOUS": 0, "CRITICAL": 0}
        
        for log_file in self.log_dir.glob("threats_*.jsonl"):
            with open(log_file) as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        
                        if entry.get("event_type") == "threat_detection":
                            # Count by type
                            attack_type = entry.get("attack_type", "unknown")
                            threats_by_type[attack_type] = threats_by_type.get(attack_type, 0) + 1
                            
                            # Count by level
                            level = entry.get("threat_level", "NORMAL")
                            threats_by_level[level] = threats_by_level.get(level, 0) + 1
                    
                    except json.JSONDecodeError:
                        continue
        
        return {
            "threats_by_type": threats_by_type,
            "threats_by_level": threats_by_level,
            "total_threats": sum(threats_by_type.values()),
        }
