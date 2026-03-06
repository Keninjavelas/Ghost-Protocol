"""
Detection orchestrator - coordinates all detection modules.
"""

from typing import Dict, List, Optional
from datetime import datetime, timezone
import asyncio
from collections import defaultdict

import structlog

from detection import (
    PacketSniffer,
    TrafficParser,
    FeatureExtractor,
    ThreatDetector,
    DetectionLogger
)
from threat_intelligence import (
    AttackRuleEngine,
    ThreatClassifier,
    AnomalyDetector
)
from response_engine import (
    AlertEngine,
    ResponseOrchestrator,
    SecurityLogger
)

logger = structlog.get_logger(__name__)


class DetectionOrchestrator:
    """
    Orchestrates the complete threat detection pipeline.
    Manages all detection modules and coordinates threat response.
    """

    def __init__(self):
        """Initialize detection orchestrator."""
        # Core detection modules
        self.packet_sniffer = PacketSniffer()
        self.traffic_parser = TrafficParser()
        self.feature_extractor = FeatureExtractor(window_size_seconds=10)
        self.threat_detector = ThreatDetector()
        self.detection_logger = DetectionLogger()
        
        # Threat intelligence
        self.attack_rules = AttackRuleEngine()
        self.threat_classifier = ThreatClassifier()
        self.anomaly_detector = AnomalyDetector()
        
        # Response
        self.alert_engine = AlertEngine()
        self.response_orchestrator = ResponseOrchestrator()
        self.security_logger = SecurityLogger()
        
        # Processing state
        self._running = False
        self._process_task: Optional[asyncio.Task] = None
        self._packet_buffer: List = []
        self._threats: Dict[str, List] = defaultdict(list)
        
        logger.info("detection_orchestrator_initialized")

    async def start(self) -> None:
        """Start detection pipeline."""
        if self._running:
            logger.warning("detector_already_running")
            return
        
        self._running = True
        
        # Start packet sniffer
        await self.packet_sniffer.start(on_packet=self._on_packet)
        
        # Start processing loop
        self._process_task = asyncio.create_task(self._processing_loop())
        
        logger.info("detection_orchestrator_started")

    async def stop(self) -> None:
        """Stop detection pipeline."""
        self._running = False
        
        await self.packet_sniffer.stop()
        await self.detection_logger.flush()
        await self.security_logger.flush()
        
        if self._process_task:
            self._process_task.cancel()
            try:
                await self._process_task
            except asyncio.CancelledError:
                pass
        
        logger.info("detection_orchestrator_stopped")

    async def _on_packet(self, packet: dict) -> None:
        """Callback when packet captured."""
        self._packet_buffer.append(packet)
        
        # Process when buffer fills
        if len(self._packet_buffer) >= 100:
            await self._process_packet_batch()

    async def _processing_loop(self) -> None:
        """Background processing loop."""
        try:
            while self._running:
                await asyncio.sleep(5)  # Process every 5 seconds
                await self._process_packet_batch()
        except asyncio.CancelledError:
            logger.info("processing_loop_cancelled")
            raise

    async def _process_packet_batch(self) -> None:
        """Process batch of packets."""
        if not self._packet_buffer:
            return
        
        try:
            # Parse packets
            parsed_packets = [
                self.traffic_parser.parse(pkt)
                for pkt in self._packet_buffer
            ]
            
            # Group by source IP
            packets_by_ip = defaultdict(list)
            for pkt in parsed_packets:
                packets_by_ip[pkt.source_ip].append(pkt)
            
            # Extract features and detect threats
            for source_ip, packets in packets_by_ip.items():
                await self._analyze_source(source_ip, packets)
            
            self._packet_buffer.clear()
        
        except Exception as e:
            logger.error("batch_processing_failed", error=str(e))

    async def _analyze_source(self, source_ip: str, packets: List) -> None:
        """Analyze traffic from source IP."""
        # Extract features
        features = self.feature_extractor.extract_features(packets, source_ip)
        
        if not features:
            return
        
        # Check rules
        matched_rules = self.attack_rules.evaluate_all(features)
        
        # Threat detection
        threat_result = await self.threat_detector.detect(
            features,
            packets,
            source_ip
        )
        
        # Anomaly detection
        is_anomaly, anomaly_score = self.anomaly_detector.detect(features)
        
        # Threat classification
        attack_type, confidence = self.threat_classifier.classify(features)
        
        # Log and respond if threat detected
        if threat_result or is_anomaly:
            combined_result = threat_result or {
                "attack_type": attack_type or "ANOMALY",
                "threat_level": "SUSPICIOUS",
                "confidence": max(threat_result.confidence if threat_result else 0, anomaly_score),
                "source_ip": source_ip,
            }
            
            # Threat score (0-1)
            threat_score = min(
                (threat_result.confidence if threat_result else 0 + anomaly_score) / 2,
                1.0
            )
            
            # Store threat
            self._threats[source_ip].append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "attack_type": threat_result.attack_type if threat_result else attack_type,
                "threat_level": threat_result.threat_level.value if threat_result else "SUSPICIOUS",
                "confidence": threat_score,
                "rules_triggered": [r.name for r in matched_rules],
            })
            
            # Log threat
            if threat_result:
                await self.detection_logger.log_threat(threat_result)
            else:
                await self.detection_logger.log_alert(
                    alert_type=attack_type or "ANOMALY",
                    severity="warning",
                    message=f"Threat-like anomaly detected from {source_ip}",
                    metadata={
                        "source_ip": source_ip,
                        "threat_score": threat_score,
                        "rules_triggered": [r.name for r in matched_rules],
                    },
                )
            
            # Send alert
            from response_engine.alert_engine import AlertSeverity
            severity = (
                AlertSeverity.CRITICAL if threat_score > 0.9
                else AlertSeverity.WARNING
            )
            
            await self.alert_engine.send_alert(
                alert_type=threat_result.attack_type if threat_result else attack_type,
                severity=severity,
                message=f"Threat detected from {source_ip}",
                details={
                    "source_ip": source_ip,
                    "threat_score": threat_score,
                    "rules_triggered": [r.name for r in matched_rules],
                }
            )
            
            # Determine response (only when threat_result has structured threat metadata)
            response_action = None
            if threat_result:
                response_action = await self.response_orchestrator.respond_to_threat(
                    threat_result,
                    threat_score
                )
            
            # Log response decision
            await self.security_logger.log_response(
                action=response_action.value if response_action else "MONITOR",
                source_ip=source_ip,
                reason=threat_result.attack_type if threat_result else attack_type
            )

    def get_threats(
        self,
        source_ip: Optional[str] = None,
        limit: int = 100
    ) -> Dict[str, List]:
        """Get detected threats."""
        if source_ip:
            return {source_ip: self._threats.get(source_ip, [])[-limit:]}
        
        result = {}
        for ip, threats in self._threats.items():
            result[ip] = threats[-limit:]
        
        return result

    def get_network_status(self) -> Dict:
        """Get overall network security status."""
        return {
            "packets_captured": self.packet_sniffer.stats["packets_captured"],
            "threats_detected": sum(len(t) for t in self._threats.values()),
            "critical_threats": sum(
                1 for threats in self._threats.values()
                for t in threats if t["threat_level"] == "CRITICAL"
            ),
            "blocked_ips": len(self.response_orchestrator.blocked_ips),
            "detection_stats": self.threat_detector.stats,
            "alert_stats": self.alert_engine.stats,
            "response_stats": self.response_orchestrator.stats,
        }

    def get_dashboard_data(self) -> Dict:
        """Get data for security dashboard."""
        return {
            "network_status": self.get_network_status(),
            "recent_threats": self.get_threats(limit=50),
            "blocked_ips": self.response_orchestrator.get_blocked_ips(),
            "recent_alerts": self.alert_engine.get_recent_alerts(count=100),
            "attack_rules": {
                "total": len(self.attack_rules.rules),
                "by_category": self._count_rules_by_category(),
            },
        }

    def _count_rules_by_category(self) -> Dict[str, int]:
        """Count rules by category."""
        counts = defaultdict(int)
        for rule in self.attack_rules.rules:
            counts[rule.category.value] += 1
        return dict(counts)
