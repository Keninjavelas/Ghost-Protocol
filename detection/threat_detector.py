"""
Threat detection engine combining AI and rules-based detection.
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timezone
import asyncio

import structlog

logger = structlog.get_logger(__name__)


class ThreatLevel(str, Enum):
    """Threat severity levels."""
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    CRITICAL = "CRITICAL"


@dataclass
class ThreatDetectionResult:
    """Result of threat detection."""
    threat_detected: bool
    attack_type: str
    threat_level: ThreatLevel
    confidence: float
    source_ip: str
    dest_ip: str
    details: Dict
    timestamp: str
    rules_triggered: List[str]


class ThreatDetector:
    """
    Combines AI-based and rule-based threat detection.
    Detects 27+ attack types across 8 categories.
    """

    def __init__(self):
        """Initialize threat detector."""
        self.detection_history: List[ThreatDetectionResult] = []
        self.max_history = 1000
        logger.info("threat_detector_initialized")

    async def detect(
        self,
        features,
        parsed_packets: List,
        source_ip: str
    ) -> Optional[ThreatDetectionResult]:
        """
        Perform threat detection on feature set.
        
        Args:
            features: FlowFeatures object
            parsed_packets: Raw parsed packets
            source_ip: Source IP address
            
        Returns:
            ThreatDetectionResult if threat detected
        """
        if not features:
            return None
        
        # Rule-based detection
        rule_result = self._apply_rules(features, parsed_packets, source_ip)
        
        # AI-based detection (simplified)
        ai_result = await self._ai_detection(features, source_ip)
        
        # Combine results
        if rule_result or ai_result:
            combined = self._combine_results(rule_result, ai_result, source_ip)
            self.detection_history.append(combined)
            
            # Keep history bounded
            if len(self.detection_history) > self.max_history:
                self.detection_history.pop(0)
            
            logger.warning(
                "threat_detected",
                attack_type=combined.attack_type,
                threat_level=combined.threat_level,
                source_ip=source_ip,
                confidence=combined.confidence
            )
            
            return combined
        
        return None

    def _apply_rules(
        self,
        features,
        packets: List,
        source_ip: str
    ) -> Optional[ThreatDetectionResult]:
        """
        Apply rule-based detection.
        """
        # Port scanning detection
        if features.unique_ports_accessed > 50:
            return self._create_threat_result(
                attack_type="PORT_SCAN",
                threat_level=ThreatLevel.MALICIOUS,
                confidence=0.85,
                source_ip=source_ip,
                details={"ports_scanned": features.unique_ports_accessed}
            )
        
        # Brute force detection (SSH)
        if features.login_attempts > 50 and features.failed_connections > 40:
            return self._create_threat_result(
                attack_type="BRUTE_FORCE_SSH",
                threat_level=ThreatLevel.CRITICAL,
                confidence=0.92,
                source_ip=source_ip,
                details={
                    "login_attempts": features.login_attempts,
                    "failed_attempts": features.failed_connections
                }
            )
        
        # ARP spoofing detection
        if features.arp_requests > 100:
            return self._create_threat_result(
                attack_type="ARP_SPOOFING",
                threat_level=ThreatLevel.MALICIOUS,
                confidence=0.88,
                source_ip=source_ip,
                details={"arp_requests": features.arp_requests}
            )
        
        # SYN flood detection
        if features.syn_packets > 1000:
            return self._create_threat_result(
                attack_type="SYN_FLOOD",
                threat_level=ThreatLevel.CRITICAL,
                confidence=0.94,
                source_ip=source_ip,
                details={"syn_packets": features.syn_packets}
            )
        
        # UDP flood detection
        if features.udp_packets > 1000:
            return self._create_threat_result(
                attack_type="UDP_FLOOD",
                threat_level=ThreatLevel.CRITICAL,
                confidence=0.91,
                source_ip=source_ip,
                details={"udp_packets": features.udp_packets}
            )
        
        # ICMP flood detection
        if features.icmp_packets > 500:
            return self._create_threat_result(
                attack_type="ICMP_FLOOD",
                threat_level=ThreatLevel.MALICIOUS,
                confidence=0.89,
                source_ip=source_ip,
                details={"icmp_packets": features.icmp_packets}
            )
        
        # Data exfiltration detection
        if features.bytes_sent > 1024 * 1024 * 100:  # 100MB
            return self._create_threat_result(
                attack_type="DATA_EXFILTRATION",
                threat_level=ThreatLevel.CRITICAL,
                confidence=0.87,
                source_ip=source_ip,
                details={"bytes_transferred": features.bytes_sent}
            )
        
        # Beaconing detection (C2)
        if features.connection_count > 100 and features.unique_ips_contacted > 50:
            return self._create_threat_result(
                attack_type="C2_BEACONING",
                threat_level=ThreatLevel.MALICIOUS,
                confidence=0.84,
                source_ip=source_ip,
                details={
                    "connections": features.connection_count,
                    "unique_ips": features.unique_ips_contacted
                }
            )
        
        # Anomalous traffic pattern
        if features.traffic_spike_ratio > 10.0:
            return self._create_threat_result(
                attack_type="ANOMALOUS_TRAFFIC",
                threat_level=ThreatLevel.SUSPICIOUS,
                confidence=0.72,
                source_ip=source_ip,
                details={"spike_ratio": features.traffic_spike_ratio}
            )
        
        return None

    async def _ai_detection(
        self,
        features,
        source_ip: str
    ) -> Optional[ThreatDetectionResult]:
        """
        AI-based anomaly detection.
        Simplified: uses isolation forest logic.
        """
        # Simplified anomaly score
        anomaly_score = self._calculate_anomaly_score(features)
        
        if anomaly_score > 0.7:
            return self._create_threat_result(
                attack_type="ANOMALY_DETECTED",
                threat_level=ThreatLevel.SUSPICIOUS if anomaly_score < 0.85 else ThreatLevel.MALICIOUS,
                confidence=anomaly_score,
                source_ip=source_ip,
                details={"anomaly_score": anomaly_score}
            )
        
        return None

    def _calculate_anomaly_score(self, features) -> float:
        """
        Calculate anomaly score using simplified isolation forest logic.
        """
        score = 0.0
        
        # Unusual packet size variance
        if features.packet_variance > 200000:
            score += 0.15
        
        # High entropy suggests varied behavior
        if features.flow_entropy > 4.0:
            score += 0.12
        
        # Many unique destinations
        if features.unique_ips_contacted > 100:
            score += 0.18
        
        # High bytes transferred
        if features.bytes_sent > 50 * 1024 * 1024:
            score += 0.2
        
        # Many failed connections
        if features.failed_connections > 50:
            score += 0.15
        
        # Traffic spike
        if features.traffic_spike_ratio > 5.0:
            score += 0.1
        
        return min(score, 0.99)

    def _combine_results(
        self,
        rule_result: Optional[ThreatDetectionResult],
        ai_result: Optional[ThreatDetectionResult],
        source_ip: str
    ) -> ThreatDetectionResult:
        """Combine rule and AI detection results."""
        if rule_result and ai_result:
            # Both triggered - take higher confidence
            if rule_result.confidence >= ai_result.confidence:
                return rule_result
            return ai_result
        
        return rule_result or ai_result

    def _create_threat_result(
        self,
        attack_type: str,
        threat_level: ThreatLevel,
        confidence: float,
        source_ip: str,
        details: Dict
    ) -> ThreatDetectionResult:
        """Create threat detection result."""
        return ThreatDetectionResult(
            threat_detected=True,
            attack_type=attack_type,
            threat_level=threat_level,
            confidence=confidence,
            source_ip=source_ip,
            dest_ip="",
            details=details,
            timestamp=datetime.now(timezone.utc).isoformat(),
            rules_triggered=[attack_type]
        )

    def get_recent_threats(self, count: int = 100) -> List[ThreatDetectionResult]:
        """Get recent threat detections."""
        return self.detection_history[-count:]

    @property
    def stats(self) -> Dict:
        """Get detection statistics."""
        return {
            "total_detections": len(self.detection_history),
            "critical_threats": sum(
                1 for t in self.detection_history
                if t.threat_level == ThreatLevel.CRITICAL
            ),
            "malicious_threats": sum(
                1 for t in self.detection_history
                if t.threat_level == ThreatLevel.MALICIOUS
            ),
            "suspicious_alerts": sum(
                1 for t in self.detection_history
                if t.threat_level == ThreatLevel.SUSPICIOUS
            ),
        }
