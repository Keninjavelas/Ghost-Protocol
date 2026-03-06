"""
VPN Detector - VPN Traffic Identification Engine

Identifies VPN connections based on statistical traffic patterns and behavioral analysis.
Uses pattern matching and ML to detect encrypted VPN traffic.
"""

from enum import Enum
from typing import Optional
import structlog
from .feature_extractor import ExtractedFeatures
from .traffic_classifier import TrafficCategory


logger = structlog.get_logger(__name__)


class VPNDetectionMethod(Enum):
    """Methods used to detect VPN"""
    PORT_BASED = "port_based"
    BEHAVIORAL = "behavioral"
    STATISTICAL = "statistical"
    TLS_FINGERPRINT = "tls_fingerprint"
    TRAFFIC_PATTERN = "traffic_pattern"
    ML_CLASSIFICATION = "ml_classification"


class VPNDetectionResult:
    """Result of VPN detection analysis"""
    def __init__(
        self,
        is_vpn: bool,
        confidence: float,
        detection_methods: list[VPNDetectionMethod],
        indicators: list[str],
        protocol_hint: Optional[str] = None
    ):
        self.is_vpn = is_vpn
        self.confidence = confidence
        self.detection_methods = detection_methods
        self.indicators = indicators
        self.protocol_hint = protocol_hint


class VPNDetector:
    """
    VPN traffic detection engine.
    
    Identifies VPN connections using multiple detection methods:
    - Port-based detection
    - Behavioral analysis
    - Statistical pattern matching
    - TLS fingerprinting
    - Traffic timing analysis
    """
    
    def __init__(self, confidence_threshold: float = 0.6):
        """
        Initialize VPN detector.
        
        Args:
            confidence_threshold: Minimum confidence to classify as VPN
        """
        self.confidence_threshold = confidence_threshold
        
        # VPN port signatures
        self.vpn_port_map = {
            1194: "OpenVPN",
            443: "OpenVPN/HTTPS-VPN",
            500: "IPSec/IKE",
            4500: "IPSec NAT-T",
            1701: "L2TP",
            1723: "PPTP",
            51820: "WireGuard",
            1302: "Cisco-VPN",
            10000: "SoftEther",
        }
        
        # TLS cipher suites commonly used by VPNs
        self.vpn_cipher_patterns = [
            "TLS_ECDHE",
            "TLS_DHE",
            "AES_256_GCM",
            "CHACHA20_POLY1305"
        ]
        
        # Statistics
        self.detections_total = 0
        self.vpn_confirmed = 0
        self.false_positives = 0
        
        logger.info("vpn_detector_initialized", threshold=confidence_threshold)
    
    def detect(
        self,
        features: ExtractedFeatures,
        traffic_category: Optional[TrafficCategory] = None
    ) -> VPNDetectionResult:
        """
        Detect VPN usage in network flow.
        
        Args:
            features: Extracted behavioral features
            traffic_category: Pre-classified traffic category (optional)
            
        Returns:
            VPN detection result with confidence and indicators
        """
        self.detections_total += 1
        
        confidence_scores = []
        detection_methods = []
        indicators = []
        protocol_hint = None
        
        # Method 1: Port-based detection
        port_result = self._detect_by_port(features)
        if port_result['detected']:
            confidence_scores.append(port_result['confidence'])
            detection_methods.append(VPNDetectionMethod.PORT_BASED)
            indicators.extend(port_result['indicators'])
            protocol_hint = port_result.get('protocol')
        
        # Method 2: Behavioral analysis
        behavioral_result = self._detect_by_behavior(features)
        if behavioral_result['detected']:
            confidence_scores.append(behavioral_result['confidence'])
            detection_methods.append(VPNDetectionMethod.BEHAVIORAL)
            indicators.extend(behavioral_result['indicators'])
        
        # Method 3: Statistical patterns
        statistical_result = self._detect_by_statistics(features)
        if statistical_result['detected']:
            confidence_scores.append(statistical_result['confidence'])
            detection_methods.append(VPNDetectionMethod.STATISTICAL)
            indicators.extend(statistical_result['indicators'])
        
        # Method 4: TLS fingerprinting
        if features.is_encrypted:
            tls_result = self._detect_by_tls(features)
            if tls_result['detected']:
                confidence_scores.append(tls_result['confidence'])
                detection_methods.append(VPNDetectionMethod.TLS_FINGERPRINT)
                indicators.extend(tls_result['indicators'])
        
        # Method 5: Traffic timing patterns
        timing_result = self._detect_by_timing(features)
        if timing_result['detected']:
            confidence_scores.append(timing_result['confidence'])
            detection_methods.append(VPNDetectionMethod.TRAFFIC_PATTERN)
            indicators.extend(timing_result['indicators'])
        
        # Method 6: ML classification (if available)
        if traffic_category and traffic_category == TrafficCategory.VPN:
            confidence_scores.append(0.8)
            detection_methods.append(VPNDetectionMethod.ML_CLASSIFICATION)
            indicators.append("ml_classified_as_vpn")
        
        # Calculate combined confidence
        if confidence_scores:
            # Weighted average with diminishing returns
            combined_confidence = sum(confidence_scores) / (len(confidence_scores) + 1)
            combined_confidence = min(combined_confidence * 1.2, 0.98)
        else:
            combined_confidence = 0.0
        
        # Determine if VPN detected
        is_vpn = combined_confidence >= self.confidence_threshold
        
        if is_vpn:
            self.vpn_confirmed += 1
        
        result = VPNDetectionResult(
            is_vpn=is_vpn,
            confidence=combined_confidence,
            detection_methods=detection_methods,
            indicators=indicators,
            protocol_hint=protocol_hint
        )
        
        logger.debug(
            "vpn_detection_complete",
            flow_id=features.flow_id,
            is_vpn=is_vpn,
            confidence=combined_confidence,
            methods=len(detection_methods)
        )
        
        return result
    
    def _detect_by_port(self, features: ExtractedFeatures) -> dict:
        """Detect VPN by destination port"""
        result = {'detected': False, 'confidence': 0.0, 'indicators': []}
        
        dst_port = features.dst_port
        
        if dst_port in self.vpn_port_map:
            protocol = self.vpn_port_map[dst_port]
            result['detected'] = True
            result['protocol'] = protocol
            result['indicators'].append(f"vpn_port_{dst_port}_{protocol}")
            
            # Confidence based on port specificity
            if dst_port in [1194, 51820, 1723]:  # Highly specific VPN ports
                result['confidence'] = 0.9
            elif dst_port == 443:  # Shared with HTTPS
                result['confidence'] = 0.4
            else:
                result['confidence'] = 0.7
        
        return result
    
    def _detect_by_behavior(self, features: ExtractedFeatures) -> dict:
        """Detect VPN by behavioral characteristics"""
        result = {'detected': False, 'confidence': 0.0, 'indicators': []}
        
        vpn_behavior_score = 0
        max_score = 8
        
        # 1. Long-lived connection (VPNs maintain persistent tunnels)
        if features.session_duration > 300:  # > 5 minutes
            vpn_behavior_score += 1
            result['indicators'].append("long_lived_connection")
        
        # 2. Bidirectional traffic (VPNs route both directions)
        if features.is_bidirectional:
            vpn_behavior_score += 1
            result['indicators'].append("bidirectional")
        
        # 3. Consistent packet sizes (tunneling adds overhead)
        if features.packet_size_std_dev < 200:
            vpn_behavior_score += 1
            result['indicators'].append("consistent_packet_sizes")
        
        # 4. High volume (VPNs route all traffic)
        if features.total_bytes > 1_000_000:  # > 1 MB
            vpn_behavior_score += 1
            result['indicators'].append("high_volume")
        
        # 5. Burst traffic (keep-alive packets)
        if features.has_burst_traffic:
            vpn_behavior_score += 1
            result['indicators'].append("burst_keepalive")
        
        # 6. Encrypted
        if features.is_encrypted:
            vpn_behavior_score += 1
            result['indicators'].append("encrypted")
        
        # 7. Unusual port usage
        if features.unusual_port_usage:
            vpn_behavior_score += 1
            result['indicators'].append("unusual_port")
        
        # 8. Tunnel indicator
        if features.potential_tunnel:
            vpn_behavior_score += 1
            result['indicators'].append("tunnel_indicator")
        
        # Calculate confidence
        if vpn_behavior_score >= 4:
            result['detected'] = True
            result['confidence'] = min(0.5 + (vpn_behavior_score / max_score) * 0.4, 0.9)
        
        return result
    
    def _detect_by_statistics(self, features: ExtractedFeatures) -> dict:
        """Detect VPN by statistical traffic patterns"""
        result = {'detected': False, 'confidence': 0.0, 'indicators': []}
        
        # VPN statistical signatures
        statistical_score = 0
        
        # 1. High entropy (encrypted payload)
        if features.packet_size_entropy > 5.5:
            statistical_score += 1
            result['indicators'].append("high_entropy")
        
        # 2. Consistent inter-arrival times (tunneling)
        if features.inter_arrival_std_dev < 0.05:
            statistical_score += 1
            result['indicators'].append("consistent_timing")
        
        # 3. Low TCP flags diversity (established tunnel)
        if features.tcp_flags_diversity < 0.3:
            statistical_score += 1
            result['indicators'].append("low_tcp_diversity")
        
        # 4. Steady throughput (not bursty web traffic)
        if features.bytes_per_second > 1000 and features.burstiness_score < 0.3:
            statistical_score += 1
            result['indicators'].append("steady_throughput")
        
        # 5. Few SYN packets (persistent connection)
        if features.syn_count <= 2 and features.packet_count > 50:
            statistical_score += 1
            result['indicators'].append("persistent_connection")
        
        if statistical_score >= 3:
            result['detected'] = True
            result['confidence'] = 0.5 + (statistical_score / 5) * 0.3
        
        return result
    
    def _detect_by_tls(self, features: ExtractedFeatures) -> dict:
        """Detect VPN by TLS fingerprint"""
        result = {'detected': False, 'confidence': 0.0, 'indicators': []}
        
        if not features.is_encrypted:
            return result
        
        tls_score = 0
        
        # 1. TLS version (VPNs often use TLS 1.2/1.3)
        if features.tls_version in ["TLS 1.2", "TLS 1.3", "0x0303", "0x0304"]:
            tls_score += 1
            result['indicators'].append("modern_tls")
        
        # 2. Cipher suite (VPNs prefer strong ciphers)
        if features.cipher_suite:
            for pattern in self.vpn_cipher_patterns:
                if pattern in features.cipher_suite:
                    tls_score += 1
                    result['indicators'].append(f"vpn_cipher_{pattern}")
                    break
        
        # 3. No SNI or generic SNI (some VPNs don't use SNI)
        if not features.has_sni:
            tls_score += 1
            result['indicators'].append("no_sni")
        
        # 4. Port 443 with non-web behavior
        if features.dst_port == 443 and features.session_duration > 120:
            tls_score += 1
            result['indicators'].append("long_lived_443")
        
        if tls_score >= 2:
            result['detected'] = True
            result['confidence'] = 0.4 + (tls_score / 4) * 0.4
        
        return result
    
    def _detect_by_timing(self, features: ExtractedFeatures) -> dict:
        """Detect VPN by traffic timing patterns"""
        result = {'detected': False, 'confidence': 0.0, 'indicators': []}
        
        timing_score = 0
        
        # 1. Regular keep-alive pattern
        if features.has_burst_traffic and features.burstiness_score > 0.6:
            timing_score += 1
            result['indicators'].append("keepalive_pattern")
        
        # 2. Low inter-arrival variance (consistent routing)
        if features.inter_arrival_variance < 0.01:
            timing_score += 1
            result['indicators'].append("low_timing_variance")
        
        # 3. Continuous traffic flow
        if features.packets_per_second > 10 and features.session_duration > 60:
            timing_score += 1
            result['indicators'].append("continuous_flow")
        
        if timing_score >= 2:
            result['detected'] = True
            result['confidence'] = 0.5 + (timing_score / 3) * 0.3
        
        return result
    
    def get_statistics(self) -> dict:
        """Get detection statistics"""
        return {
            "detections_total": self.detections_total,
            "vpn_confirmed": self.vpn_confirmed,
            "false_positives": self.false_positives,
            "detection_rate": (
                self.vpn_confirmed / self.detections_total
                if self.detections_total > 0 else 0.0
            )
        }
