"""
Feature Extraction Engine - Behavioral Characteristic Derivation

Extracts behavioral features from network flow metadata for AI analysis.
Features include statistical patterns, timing characteristics, and protocol signatures.
"""

import math
from dataclasses import dataclass
from typing import Optional
import structlog
from .traffic_ingestion import FlowMetadata


logger = structlog.get_logger(__name__)


@dataclass
class ExtractedFeatures:
    """Behavioral features extracted from network flow"""
    flow_id: str
    
    # Basic flow characteristics
    protocol: str
    src_port: int
    dst_port: int
    duration: float
    packet_count: int
    total_bytes: int
    
    # Packet size patterns
    avg_packet_size: float
    packet_size_variance: float
    packet_size_std_dev: float
    min_packet_size: int
    max_packet_size: int
    packet_size_entropy: float
    
    # Timing patterns
    avg_inter_arrival_time: float
    inter_arrival_variance: float
    inter_arrival_std_dev: float
    burstiness_score: float
    
    # Session persistence
    session_duration: float
    packets_per_second: float
    bytes_per_second: float
    
    # TLS/Encryption indicators
    is_encrypted: bool
    tls_version: Optional[str]
    cipher_suite: Optional[str]
    has_sni: bool
    
    # Behavioral indicators
    is_long_lived: bool
    is_high_volume: bool
    is_bidirectional: bool
    has_burst_traffic: bool
    
    # Protocol-specific
    tcp_flags_diversity: float
    syn_count: int
    fin_count: int
    rst_count: int
    
    # Anomaly indicators
    unusual_port_usage: bool
    suspicious_packet_pattern: bool
    potential_tunnel: bool

class FeatureExtractor:
    """
    Extract behavioral features from network flow metadata.
    
    Converts raw flow statistics into ML-ready feature vectors
    for traffic classification and anomaly detection.
    """
    
    def __init__(self):
        """Initialize feature extractor"""
        # Thresholds for behavioral classification
        self.long_lived_threshold = 60.0  # seconds
        self.high_volume_threshold = 1_000_000  # bytes
        self.burst_threshold = 5  # burst events
        
        # Common port categories
        self.vpn_common_ports = {443, 1194, 500, 4500, 1701, 1723, 51820}
        self.web_ports = {80, 443, 8080, 8443}
        self.ssh_ports = {22, 2222}
        
        logger.info("feature_extractor_initialized")
    
    def extract_features(self, flow: FlowMetadata) -> ExtractedFeatures:
        """
        Extract comprehensive behavioral features from flow metadata.
        
        Args:
            flow: Network flow metadata
            
        Returns:
            Extracted behavioral features
        """
        # Calculate packet size statistics
        packet_sizes = flow.packet_sizes
        avg_size = flow.avg_packet_size
        size_variance = flow.packet_size_variance
        size_std_dev = math.sqrt(size_variance) if size_variance > 0 else 0.0
        min_size = min(packet_sizes) if packet_sizes else 0
        max_size = max(packet_sizes) if packet_sizes else 0
        
        # Calculate packet size entropy (randomness indicator)
        size_entropy = self._calculate_entropy(packet_sizes)
        
        # Calculate timing statistics
        inter_arrival_times = flow.inter_arrival_times
        avg_inter_arrival = flow.avg_inter_arrival
        
        if len(inter_arrival_times) > 1:
            ia_variance = sum((x - avg_inter_arrival) ** 2 for x in inter_arrival_times) / len(inter_arrival_times)
            ia_std_dev = math.sqrt(ia_variance)
        else:
            ia_variance = 0.0
            ia_std_dev = 0.0
        
        # Calculate burstiness score (higher = more bursty)
        burstiness = self._calculate_burstiness(inter_arrival_times)
        
        # Session persistence metrics
        duration = flow.session_duration
        pps = flow.packet_count / duration if duration > 0 else 0
        bps = flow.total_bytes / duration if duration > 0 else 0
        
        # TLS indicators
        has_sni = flow.sni_hostname is not None
        
        # Behavioral classifications
        is_long_lived = duration >= self.long_lived_threshold
        is_high_volume = flow.total_bytes >= self.high_volume_threshold
        is_bidirectional = flow.is_bidirectional
        has_burst = flow.burst_count >= self.burst_threshold
        
        # TCP flags analysis
        tcp_flags = flow.tcp_flags
        unique_flags = len(set(tcp_flags)) if tcp_flags else 0
        flags_diversity = unique_flags / len(tcp_flags) if tcp_flags else 0.0
        
        syn_count = sum(1 for f in tcp_flags if 'S' in str(f))
        fin_count = sum(1 for f in tcp_flags if 'F' in str(f))
        rst_count = sum(1 for f in tcp_flags if 'R' in str(f))
        
        # Anomaly indicators
        unusual_port = self._is_unusual_port(flow.dst_port)
        suspicious_pattern = self._detect_suspicious_pattern(flow)
        potential_tunnel = self._detect_potential_tunnel(flow)
        
        features = ExtractedFeatures(
            flow_id=flow.flow_id,
            protocol=flow.protocol,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            duration=duration,
            packet_count=flow.packet_count,
            total_bytes=flow.total_bytes,
            avg_packet_size=avg_size,
            packet_size_variance=size_variance,
            packet_size_std_dev=size_std_dev,
            min_packet_size=min_size,
            max_packet_size=max_size,
            packet_size_entropy=size_entropy,
            avg_inter_arrival_time=avg_inter_arrival,
            inter_arrival_variance=ia_variance,
            inter_arrival_std_dev=ia_std_dev,
            burstiness_score=burstiness,
            session_duration=duration,
            packets_per_second=pps,
            bytes_per_second=bps,
            is_encrypted=flow.is_encrypted,
            tls_version=flow.tls_version,
            cipher_suite=flow.cipher_suite,
            has_sni=has_sni,
            is_long_lived=is_long_lived,
            is_high_volume=is_high_volume,
            is_bidirectional=is_bidirectional,
            has_burst_traffic=has_burst,
            tcp_flags_diversity=flags_diversity,
            syn_count=syn_count,
            fin_count=fin_count,
            rst_count=rst_count,
            unusual_port_usage=unusual_port,
            suspicious_packet_pattern=suspicious_pattern,
            potential_tunnel=potential_tunnel
        )
        
        logger.debug(
            "features_extracted",
            flow_id=flow.flow_id,
            packet_count=flow.packet_count,
            duration=duration,
            is_encrypted=flow.is_encrypted
        )
        
        return features
    
    def extract_batch(self, flows: list[FlowMetadata]) -> list[ExtractedFeatures]:
        """Extract features from multiple flows"""
        return [self.extract_features(flow) for flow in flows]
    
    def _calculate_entropy(self, values: list[int]) -> float:
        """
        Calculate Shannon entropy of packet sizes.
        Higher entropy = more random/encrypted traffic.
        """
        if not values or len(values) < 2:
            return 0.0
        
        # Count frequencies
        freq_map = {}
        for val in values:
            freq_map[val] = freq_map.get(val, 0) + 1
        
        # Calculate entropy
        total = len(values)
        entropy = 0.0
        
        for count in freq_map.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _calculate_burstiness(self, inter_arrival_times: list[float]) -> float:
        """
        Calculate burstiness coefficient.
        Higher value = more bursty traffic pattern.
        """
        if not inter_arrival_times or len(inter_arrival_times) < 2:
            return 0.0
        
        # Coefficient of variation: std_dev / mean
        mean_ia = sum(inter_arrival_times) / len(inter_arrival_times)
        if mean_ia == 0:
            return 0.0
        
        variance = sum((x - mean_ia) ** 2 for x in inter_arrival_times) / len(inter_arrival_times)
        std_dev = math.sqrt(variance)
        
        cv = std_dev / mean_ia
        
        # Normalize to 0-1 scale
        burstiness = min(cv / 10.0, 1.0)
        
        return burstiness
    
    def _is_unusual_port(self, port: int) -> bool:
        """Detect unusual port usage"""
        # Common legitimate ports
        common_ports = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 8080, 8443}
        
        # High ports often used for P2P or tunnels
        is_high_port = port > 49152
        
        # Uncommon middle-range ports
        is_uncommon = port not in common_ports and 1024 < port < 49152
        
        return is_high_port or is_uncommon
    
    def _detect_suspicious_pattern(self, flow: FlowMetadata) -> bool:
        """
        Detect suspicious packet patterns indicating tunneling or covert channels.
        """
        # Consistent packet sizes (tunneling indicator)
        if len(flow.packet_sizes) >= 10:
            unique_sizes = len(set(flow.packet_sizes))
            size_diversity = unique_sizes / len(flow.packet_sizes)
            
            # Very low diversity = potential tunnel with fixed packet size
            if size_diversity < 0.1:
                return True
        
        # Consistent timing (automated/scripted traffic)
        if len(flow.inter_arrival_times) >= 10:
            ia_std_dev = math.sqrt(flow.packet_size_variance) if flow.packet_size_variance > 0 else 0
            ia_mean = flow.avg_inter_arrival
            
            if ia_mean > 0:
                cv = ia_std_dev / ia_mean
                # Very consistent timing
                if cv < 0.05:
                    return True
        
        return False
    
    def _detect_potential_tunnel(self, flow: FlowMetadata) -> bool:
        """
        Detect potential VPN/tunnel based on behavioral indicators.
        """
        indicators = []
        
        # Encrypted traffic
        if flow.is_encrypted:
            indicators.append(True)
        
        # Long-lived connection
        if flow.session_duration > 120:  # > 2 minutes
            indicators.append(True)
        
        # High volume
        if flow.total_bytes > 500_000:  # > 500 KB
            indicators.append(True)
        
        # Bidirectional traffic
        if flow.is_bidirectional:
            indicators.append(True)
        
        # VPN common ports
        if flow.dst_port in self.vpn_common_ports:
            indicators.append(True)
        
        # Require at least 3 indicators
        return len(indicators) >= 3
    
    def to_ml_vector(self, features: ExtractedFeatures) -> list[float]:
        """
        Convert extracted features to ML-ready numerical vector.
        
        Returns:
            Feature vector for ML models
        """
        vector = [
            float(features.duration),
            float(features.packet_count),
            float(features.total_bytes),
            features.avg_packet_size,
            features.packet_size_std_dev,
            features.packet_size_entropy,
            features.avg_inter_arrival_time,
            features.inter_arrival_std_dev,
            features.burstiness_score,
            features.packets_per_second,
            features.bytes_per_second,
            float(features.is_encrypted),
            float(features.has_sni),
            float(features.is_long_lived),
            float(features.is_high_volume),
            float(features.is_bidirectional),
            float(features.has_burst_traffic),
            features.tcp_flags_diversity,
            float(features.syn_count),
            float(features.fin_count),
            float(features.rst_count),
            float(features.unusual_port_usage),
            float(features.suspicious_packet_pattern),
            float(features.potential_tunnel),
        ]
        
        return vector
