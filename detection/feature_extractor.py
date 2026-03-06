"""
Feature extraction engine for ML-based threat detection.
Converts packets into numerical features within time windows.
"""

from typing import Dict, List, Optional
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class FlowFeatures:
    """Machine learning feature vector."""
    # Network flow features
    connection_count: int = 0
    packet_rate: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    connection_duration: float = 0.0
    failed_connections: int = 0
    unique_ports_accessed: int = 0
    unique_ips_contacted: int = 0
    
    # Behavioral features
    login_attempts: int = 0
    failed_logins: int = 0
    dns_requests: int = 0
    arp_requests: int = 0
    syn_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    
    # Statistical features
    average_packet_size: float = 0.0
    traffic_spike_ratio: float = 0.0
    packet_variance: float = 0.0
    flow_entropy: float = 0.0
    
    # Metadata
    source_ip: str = ""
    timestamp: str = ""
    window_duration_seconds: int = 0


class FeatureExtractor:
    """
    Extracts ML-ready features from parsed packets.
    Operates in time windows (default 10 seconds).
    """

    def __init__(self, window_size_seconds: int = 10):
        """
        Initialize feature extractor.
        
        Args:
            window_size_seconds: Time window for feature aggregation
        """
        self.window_size = timedelta(seconds=window_size_seconds)
        
        # Flow tracking per source IP
        self._flows: Dict[str, deque] = defaultdict(deque)
        self._window_features: Dict[str, FlowFeatures] = {}
        
        logger.info("feature_extractor_initialized", window_seconds=window_size_seconds)

    def extract_features(
        self,
        parsed_packets: List,
        source_ip: Optional[str] = None
    ) -> Optional[FlowFeatures]:
        """
        Extract features from packets.
        
        Args:
            parsed_packets: List of ParsedPacket objects
            source_ip: Filter by source IP (None = all)
            
        Returns:
            FlowFeatures dict for current window
        """
        if not parsed_packets:
            return None
        
        # Filter packets if needed
        packets_to_process = parsed_packets
        if source_ip:
            packets_to_process = [
                p for p in parsed_packets
                if p.source_ip == source_ip
            ]
        
        if not packets_to_process:
            return None
        
        # Extract timestamp from first packet
        first_packet_time = packets_to_process[0].timestamp
        
        # Build features
        features = FlowFeatures(
            source_ip=source_ip or packets_to_process[0].source_ip,
            timestamp=first_packet_time
        )
        
        # Network flow analysis
        features.connection_count = len(packets_to_process)
        features.packet_rate = self._calculate_packet_rate(packets_to_process)
        features = self._extract_flow_features(features, packets_to_process)
        
        # Behavioral analysis
        features = self._extract_behavioral_features(features, packets_to_process)
        
        # Statistical analysis
        features = self._extract_statistical_features(features, packets_to_process)
        
        return features

    def _extract_flow_features(
        self,
        features: FlowFeatures,
        packets: List
    ) -> FlowFeatures:
        """Extract network flow features."""
        unique_ports = set()
        unique_ips = set()
        total_bytes = 0
        
        for pkt in packets:
            # Bytes accounting
            total_bytes += pkt.packet_size
            
            # Port tracking
            if pkt.dest_port > 0:
                unique_ports.add(pkt.dest_port)
            
            # IP tracking
            unique_ips.add(pkt.dest_ip)
            
            # Connection status (simplistic)
            if "RST" in pkt.flags or "FIN" in pkt.flags:
                features.failed_connections += 1
        
        features.bytes_sent = total_bytes
        features.unique_ports_accessed = len(unique_ports)
        features.unique_ips_contacted = len(unique_ips)
        
        return features

    def _extract_behavioral_features(
        self,
        features: FlowFeatures,
        packets: List
    ) -> FlowFeatures:
        """Extract behavioral features."""
        for pkt in packets:
            # Protocol-specific behaviors
            if pkt.protocol == "TCP":
                if "SYN" in pkt.flags:
                    features.syn_packets += 1
            elif pkt.protocol == "UDP":
                features.udp_packets += 1
            elif pkt.protocol == "ICMP":
                features.icmp_packets += 1
            elif pkt.protocol == "DNS":
                features.dns_requests += 1
            elif pkt.protocol == "ARP":
                features.arp_requests += 1
            
            # Port 22 = SSH (login attempts)
            if pkt.dest_port == 22:
                features.login_attempts += 1
        
        return features

    def _extract_statistical_features(
        self,
        features: FlowFeatures,
        packets: List
    ) -> FlowFeatures:
        """Extract statistical features."""
        if not packets:
            return features
        
        packet_sizes = [p.packet_size for p in packets]
        
        # Average packet size
        features.average_packet_size = sum(packet_sizes) / len(packet_sizes)
        
        # Packet variance (spread)
        mean = features.average_packet_size
        variance = sum((x - mean) ** 2 for x in packet_sizes) / len(packet_sizes)
        features.packet_variance = variance
        
        # Traffic spike ratio (max/min)
        if min(packet_sizes) > 0:
            features.traffic_spike_ratio = max(packet_sizes) / min(packet_sizes)
        
        # Entropy (diversity of packet sizes)
        features.flow_entropy = self._calculate_entropy(packet_sizes)
        
        return features

    def _calculate_packet_rate(self, packets: List) -> float:
        """Calculate packets per second."""
        if not packets or len(packets) < 2:
            return 0.0
        
        # Simplified: just count
        return float(len(packets))

    def _calculate_entropy(self, values: List[int]) -> float:
        """Calculate Shannon entropy of values."""
        if not values:
            return 0.0
        
        from collections import Counter
        import math
        
        counts = Counter(values)
        total = len(values)
        entropy = 0.0
        
        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability + 1e-10)
        
        return entropy

    def extract_batch_features(
        self,
        packets_by_ip: Dict[str, List]
    ) -> Dict[str, FlowFeatures]:
        """
        Extract features for multiple sources.
        
        Args:
            packets_by_ip: Dict of IP -> list of packets
            
        Returns:
            Dict of IP -> FlowFeatures
        """
        features_dict = {}
        for source_ip, packets in packets_by_ip.items():
            features = self.extract_features(packets, source_ip)
            if features:
                features_dict[source_ip] = features
        
        return features_dict

    def stream_features(self, packet) -> Optional[FlowFeatures]:
        """
        Process streaming packets and return features when window completes.
        
        Args:
            packet: ParsedPacket to add to stream
            
        Returns:
            FlowFeatures if window boundary crossed, None otherwise
        """
        source_ip = packet.source_ip
        
        # Add to flow
        self._flows[source_ip].append(packet)
        
        # Check if we have a complete window
        flow_list = list(self._flows[source_ip])
        if len(flow_list) >= 10:  # Arbitrary threshold
            features = self.extract_features(flow_list, source_ip)
            self._flows[source_ip].clear()
            return features
        
        return None
