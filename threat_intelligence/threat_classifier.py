"""
Threat classifier using machine learning patterns.
"""

from typing import Dict, List, Tuple
import numpy as np
import structlog

logger = structlog.get_logger(__name__)


class ThreatClassifier:
    """
    ML-based threat classification combining multiple signals.
    Uses Random Forest-like voting patterns.
    """

    def __init__(self):
        """Initialize threat classifier."""
        # Attack type classifiers (simplified)
        self.classifiers = self._build_classifiers()
        logger.info("threat_classifier_initialized")

    def _build_classifiers(self) -> Dict:
        """Build attack-specific classifiers."""
        return {
            "PORT_SCAN": self._classify_port_scan,
            "BRUTE_FORCE": self._classify_brute_force,
            "DDoS": self._classify_ddos,
            "DATA_EXFILTRATION": self._classify_exfiltration,
            "C2_BEACONING": self._classify_c2,
            "ANOMALY": self._classify_anomaly,
        }

    def classify(self, features) -> Tuple[str, float]:
        """
        Classify attack type from features.
        
        Returns:
            (attack_type, confidence)
        """
        scores = {}
        
        for attack_type, classifier in self.classifiers.items():
            score = classifier(features)
            if score > 0.5:  # Threshold
                scores[attack_type] = score
        
        if not scores:
            return "UNKNOWN", 0.0
        
        # Return highest scoring attack
        best_attack = max(scores.items(), key=lambda x: x[1])
        return best_attack

    def _classify_port_scan(self, features) -> float:
        """Port scan classifier."""
        score = 0.0
        
        if features.unique_ports_accessed > 50:
            score += 0.4
        
        if features.connection_duration < 5.0:
            score += 0.3
        
        if features.unique_ips_contacted > 1:
            score += 0.2
        
        return min(score, 1.0)

    def _classify_brute_force(self, features) -> float:
        """Brute force classifier."""
        score = 0.0
        
        if features.login_attempts > 50:
            score += 0.5
        
        if features.failed_connections > 40:
            score += 0.3
        
        if features.packet_rate > 10.0:
            score += 0.2
        
        return min(score, 1.0)

    def _classify_ddos(self, features) -> float:
        """DDoS classifier."""
        score = 0.0
        
        if features.syn_packets > 1000:
            score += 0.4
        
        if features.udp_packets > 1000:
            score += 0.4
        
        if features.icmp_packets > 500:
            score += 0.2
        
        return min(score, 1.0)

    def _classify_exfiltration(self, features) -> float:
        """Data exfiltration classifier."""
        score = 0.0
        
        if features.bytes_sent > 100 * 1024 * 1024:
            score += 0.5
        
        if features.unique_ips_contacted > 10:
            score += 0.25
        
        if features.connection_count > 50:
            score += 0.25
        
        return min(score, 1.0)

    def _classify_c2(self, features) -> float:
        """C2 beaconing classifier."""
        score = 0.0
        
        if features.connection_count > 100:
            score += 0.3
        
        if features.unique_ips_contacted > 50:
            score += 0.3
        
        if features.packet_rate > 5.0 and features.packet_rate < 100.0:
            score += 0.2  # Steady heartbeat
        
        if features.average_packet_size < 200:
            score += 0.2  # Small beacons
        
        return min(score, 1.0)

    def _classify_anomaly(self, features) -> float:
        """General anomaly classifier."""
        # Multi-factor anomaly detection
        factors = []
        
        # Unusual traffic volume
        if features.bytes_sent > 50 * 1024 * 1024:
            factors.append(0.15)
        
        # Unusual packet patterns
        if features.traffic_spike_ratio > 5.0:
            factors.append(0.15)
        
        # High entropy
        if features.flow_entropy > 3.0:
            factors.append(0.15)
        
        # Many failures
        if features.failed_connections > 50:
            factors.append(0.2)
        
        # Many unique destinations
        if features.unique_ips_contacted > 100:
            factors.append(0.2)
        
        return min(sum(factors), 1.0)
