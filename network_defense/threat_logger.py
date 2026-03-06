"""
Module 9: Threat Logger
Structured logging for network threats and security events.
"""

from typing import Dict, List, Optional
import structlog
from datetime import datetime
from pathlib import Path
import json

logger = structlog.get_logger(__name__)


class ThreatLogger:
    """
    Structured threat logging system for network defense events.
    """

    def __init__(
        self,
        log_dir: str = "logs/threats",
        enable_packet_logging: bool = False,
        max_packets_per_threat: int = 100
    ):
        """
        Initialize threat logger.
        
        Args:
            log_dir: Directory for threat logs
            enable_packet_logging: Log full packet data (verbose)
            max_packets_per_threat: Max packets to log per threat
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.enable_packet_logging = enable_packet_logging
        self.max_packets_per_threat = max_packets_per_threat
        
        # Log files
        self.threat_log_file = self.log_dir / "threats.jsonl"
        self.packet_log_file = self.log_dir / "packets.jsonl"
        self.alert_log_file = self.log_dir / "alerts.jsonl"
        self.response_log_file = self.log_dir / "responses.jsonl"
        
        logger.info(
            "threat_logger_initialized",
            log_dir=str(self.log_dir),
            packet_logging=enable_packet_logging
        )

    async def log_threat(
        self,
        threat_level: str,
        threat_data: Dict,
        packets: Optional[List[Dict]] = None,
        session_id: Optional[str] = None
    ) -> None:
        """
        Log detected threat with full context.
        
        Args:
            threat_level: NORMAL, SUSPICIOUS, MALICIOUS, or CRITICAL
            threat_data: Threat detection result
            packets: Associated packets (if packet logging enabled)
            session_id: Associated session ID
        """
        timestamp = datetime.utcnow().isoformat()
        
        # Build threat log entry
        log_entry = {
            "timestamp": timestamp,
            "threat_level": threat_level,
            "threat_score": threat_data.get("threat_score", 0),
            "session_id": session_id,
            "ai_score": threat_data.get("ai_score", 0),
            "rule_score": threat_data.get("rule_score", 0),
            "attacks": threat_data.get("attacks", []),
            "confidence": threat_data.get("confidence", 0),
            "recommended_action": threat_data.get("recommended_action"),
        }
        
        # Add AI classification if available
        if "ai_classification" in threat_data:
            log_entry["ai_classification"] = threat_data["ai_classification"]
        
        # Write to threat log
        self._write_log(self.threat_log_file, log_entry)
        
        # Log packets if enabled
        if self.enable_packet_logging and packets:
            await self._log_packets(timestamp, packets, threat_level)
        
        logger.info(
            "threat_logged",
            threat_level=threat_level,
            threat_score=threat_data.get("threat_score"),
            attacks_count=len(threat_data.get("attacks", []))
        )

    async def log_alert(
        self,
        alert_data: Dict,
        channels: List[str]
    ) -> None:
        """
        Log alert sent to various channels.
        
        Args:
            alert_data: Alert payload
            channels: Channels alert was sent to
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "alert_id": alert_data.get("alert_id"),
            "threat_level": alert_data.get("threat_level"),
            "threat_score": alert_data.get("threat_score"),
            "channels": channels,
            "message": alert_data.get("short_message"),
            "source_ips": alert_data.get("source_ips", []),
        }
        
        self._write_log(self.alert_log_file, log_entry)
        
        logger.debug("alert_logged", alert_id=alert_data.get("alert_id"))

    async def log_response(
        self,
        action: str,
        threat_data: Dict,
        success: bool,
        dry_run: bool = False
    ) -> None:
        """
        Log automated response action.
        
        Args:
            action: Response action taken
            threat_data: Threat that triggered response
            success: Whether action succeeded
            dry_run: Whether this was a dry run
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "threat_level": threat_data.get("threat_level"),
            "threat_score": threat_data.get("threat_score"),
            "success": success,
            "dry_run": dry_run,
        }
        
        # Extract affected IPs
        source_ips = set()
        for attack in threat_data.get("attacks", []):
            if "source_ip" in attack:
                source_ips.add(attack["source_ip"])
        
        log_entry["affected_ips"] = list(source_ips)
        
        self._write_log(self.response_log_file, log_entry)
        
        logger.debug("response_logged", action=action, success=success)

    async def _log_packets(
        self,
        timestamp: str,
        packets: List[Dict],
        threat_level: str
    ) -> None:
        """Log packet data for threat analysis."""
        # Limit number of packets logged
        packets_to_log = packets[:self.max_packets_per_threat]
        
        log_entry = {
            "timestamp": timestamp,
            "threat_level": threat_level,
            "packet_count": len(packets),
            "packets_logged": len(packets_to_log),
            "packets": [
                self._sanitize_packet(packet)
                for packet in packets_to_log
            ]
        }
        
        self._write_log(self.packet_log_file, log_entry)

    def _sanitize_packet(self, packet: Dict) -> Dict:
        """Sanitize packet data for logging (remove sensitive info)."""
        return {
            "timestamp": packet.get("timestamp"),
            "src_ip": packet.get("src_ip"),
            "dst_ip": packet.get("dst_ip"),
            "src_port": packet.get("src_port"),
            "dst_port": packet.get("dst_port"),
            "protocol": packet.get("protocol"),
            "packet_size": packet.get("packet_size"),
            "payload_length": packet.get("payload_length"),
            # Do not log full payload - security risk
        }

    def _write_log(self, file_path: Path, log_entry: Dict) -> None:
        """Write log entry to JSONL file."""
        try:
            with open(file_path, "a") as f:
                json.dump(log_entry, f)
                f.write("\n")
        except Exception as e:
            logger.error("log_write_failed", file=str(file_path), error=str(e))

    def query_threats(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        threat_level: Optional[str] = None,
        min_score: Optional[float] = None,
        limit: int = 100
    ) -> List[Dict]:
        """
        Query threat logs with filters.
        
        Args:
            start_time: Filter by start time
            end_time: Filter by end time
            threat_level: Filter by threat level
            min_score: Minimum threat score
            limit: Maximum results
        
        Returns:
            List of matching threat log entries
        """
        results = []
        
        try:
            if not self.threat_log_file.exists():
                return results
            
            with open(self.threat_log_file, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        
                        # Apply filters
                        if start_time:
                            entry_time = datetime.fromisoformat(entry["timestamp"])
                            if entry_time < start_time:
                                continue
                        
                        if end_time:
                            entry_time = datetime.fromisoformat(entry["timestamp"])
                            if entry_time > end_time:
                                continue
                        
                        if threat_level and entry.get("threat_level") != threat_level:
                            continue
                        
                        if min_score and entry.get("threat_score", 0) < min_score:
                            continue
                        
                        results.append(entry)
                        
                        if len(results) >= limit:
                            break
                    
                    except json.JSONDecodeError:
                        continue
        
        except Exception as e:
            logger.error("query_threats_failed", error=str(e))
        
        return results

    def get_threat_statistics(
        self,
        hours: int = 24
    ) -> Dict:
        """
        Get threat statistics for last N hours.
        
        Returns:
            Statistics dict with counts by threat level
        """
        cutoff_time = datetime.utcnow().timestamp() - (hours * 3600)
        
        stats = {
            "total_threats": 0,
            "by_level": {
                "CRITICAL": 0,
                "MALICIOUS": 0,
                "SUSPICIOUS": 0,
                "NORMAL": 0
            },
            "unique_source_ips": set(),
            "attack_types": {},
        }
        
        try:
            if not self.threat_log_file.exists():
                return stats
            
            with open(self.threat_log_file, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        entry_time = datetime.fromisoformat(entry["timestamp"]).timestamp()
                        
                        if entry_time < cutoff_time:
                            continue
                        
                        stats["total_threats"] += 1
                        
                        threat_level = entry.get("threat_level", "NORMAL")
                        stats["by_level"][threat_level] += 1
                        
                        # Track source IPs
                        for attack in entry.get("attacks", []):
                            if "source_ip" in attack:
                                stats["unique_source_ips"].add(attack["source_ip"])
                            
                            # Track attack types
                            attack_type = attack.get("type", "unknown")
                            stats["attack_types"][attack_type] = stats["attack_types"].get(attack_type, 0) + 1
                    
                    except (json.JSONDecodeError, ValueError):
                        continue
        
        except Exception as e:
            logger.error("get_statistics_failed", error=str(e))
        
        # Convert set to count
        stats["unique_source_ips"] = len(stats["unique_source_ips"])
        
        return stats
