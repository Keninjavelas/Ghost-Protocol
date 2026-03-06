"""
Module 4: Threat Detection Engine
Combines AI detection + rule-based detection for final threat classification.
"""

from typing import Dict, List, Optional
import structlog

logger = structlog.get_logger(__name__)


class ThreatDetectionEngine:
    """
    Main threat detection engine combining AI and rule-based detection.
    """

    def __init__(
        self,
        ml_model=None,
        attack_detector=None,
        ai_weight: float = 0.6,
        rule_weight: float = 0.4
    ):
        """
        Initialize threat detection engine.
        
        Args:
            ml_model: Machine learning classifier
            attack_detector: Rule-based attack detector
            ai_weight: Weight for AI detection score
            rule_weight: Weight for rule-based detection score
        """
        self.ml_model = ml_model
        self.attack_detector = attack_detector
        self.ai_weight = ai_weight
        self.rule_weight = rule_weight
        
        logger.info(
            "threat_detection_engine_initialized",
            ai_weight=ai_weight,
            rule_weight=rule_weight
        )

    def detect_threats(
        self,
        packets: List[Dict],
        features: Dict
    ) -> Dict:
        """
        Detect threats using combined AI + rule-based approach.
        
        Args:
            packets: List of parsed packets
            features: Extracted feature vector
        
        Returns:
            Detection result with threat classification
        """
        # AI-based detection
        ai_result = None
        if self.ml_model:
            ai_result = self.ml_model.predict(features)
        
        # Rule-based detection
        rule_attacks = []
        if self.attack_detector:
            rule_attacks = self.attack_detector.detect_attacks(packets, features)
        
        # Combine results
        combined_result = self._combine_detections(ai_result, rule_attacks, features)
        
        logger.info(
            "threat_detection_complete",
            threat_level=combined_result["threat_level"],
            threat_score=combined_result["threat_score"],
            attacks_detected=len(combined_result.get("attacks", []))
        )
        
        return combined_result

    def _combine_detections(
        self,
        ai_result: Optional[Dict],
        rule_attacks: List[Dict],
        features: Dict
    ) -> Dict:
        """
        Combine AI and rule-based detection results.
        
        Returns:
            Combined threat assessment
        """
        # Initialize scores
        ai_score = 0.0
        rule_score = 0.0
        
        # AI score
        if ai_result:
            ai_score = ai_result.get("threat_probability", 0.0)
        
        # Rule-based score
        if rule_attacks:
            # Calculate max severity from rule detections
            severity_map = {
                "low": 0.3,
                "medium": 0.6,
                "high": 0.8,
                "critical": 1.0
            }
            
            max_severity = max(
                severity_map.get(attack["severity"], 0.5)
                for attack in rule_attacks
            )
            rule_score = max_severity
        
        # Combined weighted score
        combined_score = (
            self.ai_weight * ai_score +
            self.rule_weight * rule_score
        )
        
        # Classify threat level
        threat_level = self._classify_threat_level(combined_score)
        
        # Build result
        result = {
            "threat_score": round(combined_score * 100, 2),  # 0-100 scale
            "threat_level": threat_level,
            "ai_score": round(ai_score *  100, 2),
            "rule_score": round(rule_score * 100, 2),
            "attacks": rule_attacks,
            "confidence": self._calculate_confidence(ai_result, rule_attacks),
            "recommended_action": self._recommend_action(threat_level),
        }
        
        # Add AI classification if available
        if ai_result:
            result["ai_classification"] = {
                "attack_type": ai_result.get("attack_type", "unknown"),
                "confidence": ai_result.get("confidence", 0.0),
                "anomaly_score": ai_result.get("anomaly_score", 0.0)
            }
        
        return result

    def _classify_threat_level(self, score: float) -> str:
        """
        Classify threat level from score.
        
        Returns:
            NORMAL, SUSPICIOUS, MALICIOUS, or CRITICAL
        """
        if score < 0.2:
            return "NORMAL"
        elif score < 0.5:
            return "SUSPICIOUS"
        elif score < 0.8:
            return "MALICIOUS"
        else:
            return "CRITICAL"

    def _calculate_confidence(
        self,
        ai_result: Optional[Dict],
        rule_attacks: List[Dict]
    ) -> float:
        """Calculate overall confidence in detection."""
        confidences = []
        
        if ai_result:
            confidences.append(ai_result.get("confidence", 0.0))
        
        if rule_attacks:
            for attack in rule_attacks:
                confidences.append(attack.get("confidence", 0.0))
        
        if confidences:
            return round(sum(confidences) / len(confidences), 2)
        
        return 0.0

    def _recommend_action(self, threat_level: str) -> str:
        """Recommend action based on threat level."""
        actions = {
            "NORMAL": "No action required. Continue monitoring.",
            "SUSPICIOUS": "Monitor closely. Review logs for context.",
            "MALICIOUS": "Alert SOC team. Consider blocking source IP.",
            "CRITICAL": "IMMEDIATE ACTION: Block traffic, isolate device, alert security team."
        }
        return actions.get(threat_level, "Review manually.")
