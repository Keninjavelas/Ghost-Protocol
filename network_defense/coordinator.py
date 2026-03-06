"""
Network Defense System - Main Coordinator
Integrates all network defense modules into unified threat detection platform.
"""

from typing import Dict, List, Optional, Callable
import structlog
import asyncio
from datetime import datetime

from .packet_capture import PacketCaptureEngine
from .traffic_parser import TrafficParser
from .feature_extractor import FeatureExtractor
from .detection_engine import ThreatDetectionEngine
from .attack_detector import AttackDetector
from .ml_model import ThreatClassifier
from .alert_engine import AlertEngine
from .automated_response import ResponseEngine
from .threat_logger import ThreatLogger

logger = structlog.get_logger(__name__)


class NetworkDefenseSystem:
    """
    Main coordinator for AI-powered network threat detection.
    
    This system combines:
    - Real-time packet capture
    - Multi-protocol traffic parsing
    - ML-based feature extraction
    - AI + rule-based threat detection
    - Multi-channel alerting
    - Automated response actions
    - Comprehensive threat logging
    """

    def __init__(
        self,
        interface: str = "any",
        enable_ml: bool = True,
        ml_model_path: Optional[str] = None,
        enable_automated_response: bool = False,
        response_dry_run: bool = True,
        dashboard_callback: Optional[Callable] = None,
        alert_webhook_url: Optional[str] = None,
        log_dir: str = "logs/threats"
    ):
        """
        Initialize network defense system.
        
        Args:
            interface: Network interface to monitor
            enable_ml: Enable ML-based detection
            ml_model_path: Path to pre-trained ML model
            enable_automated_response: Enable automated response actions
            response_dry_run: Run responses in dry-run mode (log only)
            dashboard_callback: Async callback for dashboard alerts
            alert_webhook_url: Webhook URL for external alerts
            log_dir: Directory for threat logs
        """
        self.interface = interface
        self.running = False
        self.dashboard_callback = dashboard_callback
        
        # Initialize components
        logger.info("initializing_network_defense_system")
        
        # 1. Packet Capture
        capture_interface = None if interface == "any" else interface
        self.packet_capture = PacketCaptureEngine(
            interface=capture_interface,
            packet_callback=self._process_packet_callback,
        )
        
        # 2. Traffic Parser
        self.traffic_parser = TrafficParser()
        
        # 3. Feature Extractor
        self.feature_extractor = FeatureExtractor(window_seconds=10)
        
        # 4. Attack Detector (Rule-based)
        self.attack_detector = AttackDetector()
        
        # 5. ML Threat Classifier
        self.ml_classifier = None
        if enable_ml:
            self.ml_classifier = ThreatClassifier(
                model_path=ml_model_path,
                use_isolation_forest=True
            )
        
        # 6. Threat Detection Engine (combines AI + rules)
        self.detection_engine = ThreatDetectionEngine(
            ml_model=self.ml_classifier,
            attack_detector=self.attack_detector,
            ai_weight=0.6,
            rule_weight=0.4
        )
        
        # 7. Alert Engine
        self.alert_engine = AlertEngine(
            dashboard_callback=self._dashboard_alert_callback,
            webhook_url=alert_webhook_url
        )
        
        # 8. Automated Response Engine
        self.response_engine = ResponseEngine(
            enabled=enable_automated_response,
            dry_run=response_dry_run,
            auto_block_threshold=80.0,
            auto_throttle_threshold=60.0,
            alert_callback=self._admin_alert_callback
        )
        
        # 9. Threat Logger
        self.threat_logger = ThreatLogger(
            log_dir=log_dir,
            enable_packet_logging=False,  # Disabled for performance
            max_packets_per_threat=100
        )
        
        logger.info(
            "network_defense_system_initialized",
            interface=interface,
            ml_enabled=enable_ml,
            automated_response=enable_automated_response,
            response_dry_run=response_dry_run
        )

    async def start(self) -> None:
        """Start network defense system."""
        if self.running:
            logger.warning("network_defense_already_running")
            return
        
        logger.info("starting_network_defense_system")
        
        # Start packet capture
        self.packet_capture.start_capture()
        
        # Start monitoring loop
        self.running = True
        asyncio.create_task(self._monitoring_loop())
        
        logger.info("network_defense_system_started")

    async def stop(self) -> None:
        """Stop network defense system."""
        if not self.running:
            return
        
        logger.info("stopping_network_defense_system")
        
        self.running = False
        self.packet_capture.stop_capture()
        
        logger.info("network_defense_system_stopped")

    def _process_packet_callback(self, packet_data: Dict) -> None:
        """
        Callback for real-time packet processing.
        
        This is called by packet capture engine for each packet.
        """
        try:
            # Parse packet
            parsed_packet = self.traffic_parser.parse_packet(packet_data)
            
            # Add to feature extractor
            self.feature_extractor.add_packet(parsed_packet)
        
        except Exception as e:
            logger.error("packet_processing_failed", error=str(e))

    async def _monitoring_loop(self) -> None:
        """
        Main monitoring loop - periodically analyzes traffic and detects threats.
        """
        logger.info("monitoring_loop_started")
        
        while self.running:
            try:
                # Wait for feature extraction window
                await asyncio.sleep(10)  # 10-second windows
                
                # Check if we should extract features
                if not self.feature_extractor.should_extract():
                    continue
                
                # Extract features
                features = self.feature_extractor.extract_features()
                
                # Get recent packets
                packets = self.packet_capture.get_buffered_packets(count=500)
                parsed_packets = [
                    self.traffic_parser.parse_packet(p)
                    for p in packets
                ]
                
                # Detect threats
                threat_result = self.detection_engine.detect_threats(
                    parsed_packets,
                    features
                )
                
                threat_level = threat_result["threat_level"]
                threat_score = threat_result["threat_score"]
                
                # Only process if threat detected
                if threat_level in ["SUSPICIOUS", "MALICIOUS", "CRITICAL"]:
                    await self._handle_threat(
                        threat_level,
                        threat_score,
                        threat_result,
                        parsed_packets
                    )
                
                # Log statistics
                stats = self.packet_capture.get_statistics()
                logger.debug(
                    "monitoring_cycle_complete",
                    threat_level=threat_level,
                    threat_score=threat_score,
                    packets_processed=stats["total_packets"]
                )
            
            except Exception as e:
                logger.error("monitoring_loop_error", error=str(e))
                await asyncio.sleep(5)  # Back off on error

    async def _handle_threat(
        self,
        threat_level: str,
        threat_score: float,
        threat_result: Dict,
        packets: List[Dict]
    ) -> None:
        """
        Handle detected threat through complete response pipeline.
        
        Pipeline:
        1. Log threat
        2. Send alerts
        3. Execute automated response
        4. Broadcast to dashboard
        """
        logger.warning(
            "threat_detected",
            threat_level=threat_level,
            threat_score=threat_score,
            attacks=len(threat_result.get("attacks", []))
        )
        
        # 1. Log threat
        await self.threat_logger.log_threat(
            threat_level,
            threat_result,
            packets=packets
        )
        
        # 2. Send alerts
        await self.alert_engine.send_alert(
            threat_level,
            threat_result
        )
        
        # 3. Execute automated response
        if self.response_engine.enabled:
            actions_taken = await self.response_engine.execute_response(
                threat_level,
                threat_score,
                threat_result
            )
            
            # Log responses
            for action in actions_taken:
                await self.threat_logger.log_response(
                    action.value,
                    threat_result,
                    success=True,
                    dry_run=self.response_engine.dry_run
                )

    async def _dashboard_alert_callback(self, alert: Dict) -> None:
        """Send alert to dashboard via callback."""
        if self.dashboard_callback:
            try:
                await self.dashboard_callback({
                    "type": "network_threat_alert",
                    "data": alert
                })
            except Exception as e:
                logger.error("dashboard_alert_failed", error=str(e))

    async def _admin_alert_callback(
        self,
        threat_data: Dict,
        session_id: Optional[str]
    ) -> None:
        """Send admin alert for critical threats."""
        logger.critical(
            "admin_alert",
            threat_level=threat_data.get("threat_level"),
            threat_score=threat_data.get("threat_score"),
            recommended_action=threat_data.get("recommended_action")
        )

    def get_status(self) -> Dict:
        """Get current system status."""
        stats = self.packet_capture.get_statistics()
        threat_stats = self.threat_logger.get_threat_statistics(hours=24)
        
        return {
            "running": self.running,
            "interface": self.interface,
            "packet_statistics": stats,
            "threat_statistics": threat_stats,
            "ml_enabled": self.ml_classifier is not None,
            "automated_response": {
                "enabled": self.response_engine.enabled,
                "dry_run": self.response_engine.dry_run,
                "blocked_ips": len(self.response_engine.blocked_ips),
                "throttled_ips": len(self.response_engine.throttled_ips),
            },
            "timestamp": datetime.utcnow().isoformat()
        }

    def get_recent_threats(self, limit: int = 20) -> List[Dict]:
        """Get recent threats."""
        return self.threat_logger.query_threats(limit=limit)

    def query_threats(
        self,
        threat_level: Optional[str] = None,
        min_score: Optional[float] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Query threats with filters."""
        return self.threat_logger.query_threats(
            threat_level=threat_level,
            min_score=min_score,
            limit=limit
        )
