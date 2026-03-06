"""
Module 3: Feature Extraction Engine
Converts raw packets into machine learning features for threat detection.
"""

from typing import Dict, List
from collections import defaultdict
from datetime import datetime, timedelta
import statistics
import structlog

logger = structlog.get_logger(__name__)


class FeatureExtractor:
    """
    Feature extraction engine for ML-based threat detection.
    Operates on time windows (default: 10 seconds).
    """

    def __init__(self, window_seconds: int = 10):
        """
        Initialize feature extractor.
        
        Args:
            window_seconds: Time window for feature aggregation
        """
        self.window_seconds = window_seconds
        self.window_start = datetime.utcnow()
        
        # Aggregated metrics per window
        self.window_data = {
            "packets": [],
            "connections": defaultdict(int),
            "ports": set(),
            "ips": set(),
            "protocols": defaultdict(int),
            "packet_sizes": [],
            "failed_connections": 0,
            "login_attempts": 0,
            "dns_requests": 0,
            "arp_requests": 0,
            "syn_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
        }
        
        logger.info("feature_extractor_initialized", window_seconds=window_seconds)

    def add_packet(self, packet: Dict) -> None:
        """Add packet to current window."""
        self.window_data["packets"].append(packet)
        
        # Track connections
        conn_tuple = (
            packet.get("src_ip"),
            packet.get("dst_ip"),
            packet.get("dst_port", 0)
        )
        self.window_data["connections"][conn_tuple] += 1
        
        # Track ports and IPs
        if packet.get("dst_port"):
            self.window_data["ports"].add(packet["dst_port"])
        if packet.get("src_ip"):
            self.window_data["ips"].add(packet["src_ip"])
        if packet.get("dst_ip"):
            self.window_data["ips"].add(packet["dst_ip"])
        
        # Track protocols
        protocol = packet.get("protocol", "unknown")
        self.window_data["protocols"][protocol] += 1
        
        # Track packet sizes
        size = packet.get("packet_size", 0)
        if size > 0:
            self.window_data["packet_sizes"].append(size)
        
        # Protocol-specific tracking
        if protocol == "TCP" and packet.get("is_syn"):
            self.window_data["syn_packets"] += 1
            if packet.get("is_rst"):
                self.window_data["failed_connections"] += 1
        
        if protocol == "UDP":
            self.window_data["udp_packets"] += 1
        
        if protocol == "ICMP":
            self.window_data["icmp_packets"] += 1
        
        if protocol == "DNS":
            self.window_data["dns_requests"] += 1
        
        if protocol == "ARP" and packet.get("arp_operation") == "request":
            self.window_data["arp_requests"] += 1
        
        # Detect login attempts (SSH, RDP, etc.)
        dst_port = packet.get("dst_port", 0)
        if dst_port in {22, 23, 3389}:
            self.window_data["login_attempts"] += 1

    def extract_features(self) -> Dict:
        """
        Extract feature vector from current window.
        
        Returns:
            Dictionary of features for ML model
        """
        packets = self.window_data["packets"]
        
        if not packets:
            return self._empty_features()
        
        # Network flow features
        features = {
            "connection_count": len(self.window_data["connections"]),
            "packet_count": len(packets),
            "packet_rate": len(packets) / self.window_seconds,
            "unique_ports_accessed": len(self.window_data["ports"]),
            "unique_ips_contacted": len(self.window_data["ips"]),
            "failed_connections": self.window_data["failed_connections"],
        }
        
        # Behavioral features
        features.update({
            "login_attempts": self.window_data["login_attempts"],
            "failed_logins": self.window_data["failed_connections"],  # Approximation
            "dns_requests": self.window_data["dns_requests"],
            "arp_requests": self.window_data["arp_requests"],
            "syn_packets": self.window_data["syn_packets"],
            "udp_packets": self.window_data["udp_packets"],
            "icmp_packets": self.window_data["icmp_packets"],
        })
        
        # Statistical features
        if self.window_data["packet_sizes"]:
            features.update({
                "average_packet_size": statistics.mean(self.window_data["packet_sizes"]),
                "packet_size_variance": statistics.variance(self.window_data["packet_sizes"]) if len(self.window_data["packet_sizes"]) > 1 else 0,
                "max_packet_size": max(self.window_data["packet_sizes"]),
                "min_packet_size": min(self.window_data["packet_sizes"]),
            })
        else:
            features.update({
                "average_packet_size": 0,
                "packet_size_variance": 0,
                "max_packet_size": 0,
                "min_packet_size": 0,
            })
        
        # Traffic composition
        total_packets = len(packets)
        for protocol, count in self.window_data["protocols"].items():
            features[f"{protocol.lower()}_ratio"] = count / total_packets
        
        # Byte statistics
        bytes_sent = sum(p.get("packet_size", 0) for p in packets)
        features["bytes_sent"] = bytes_sent
        features["bytes_per_second"] = bytes_sent / self.window_seconds
        
        # Connection duration (approximation)
        if len(packets) > 1:
            first = datetime.fromisoformat(packets[0]["timestamp"])
            last = datetime.fromisoformat(packets[-1]["timestamp"])
            features["connection_duration"] = (last - first).total_seconds()
        else:
            features["connection_duration"] = 0
        
        # Flow entropy (measure of randomness)
        features["flow_entropy"] = self._calculate_entropy(self.window_data["connections"])
        
        # Port scan indicators
        features["port_scan_indicator"] = self._detect_port_scan()
        
        # Traffic spike detection
        features["traffic_spike_ratio"] = self._calculate_traffic_spike()
        
        logger.debug("features_extracted", feature_count=len(features))
        return features

    def _empty_features(self) -> Dict:
        """Return empty feature vector."""
        return {
            "connection_count": 0,
            "packet_count": 0,
            "packet_rate": 0,
            "unique_ports_accessed": 0,
            "unique_ips_contacted": 0,
            "failed_connections": 0,
            "login_attempts": 0,
            "failed_logins": 0,
            "dns_requests": 0,
            "arp_requests": 0,
            "syn_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "average_packet_size": 0,
            "packet_size_variance": 0,
            "max_packet_size": 0,
            "min_packet_size": 0,
            "bytes_sent": 0,
            "bytes_per_second": 0,
            "connection_duration": 0,
            "flow_entropy": 0,
            "port_scan_indicator": 0,
            "traffic_spike_ratio": 0,
        }

    def _calculate_entropy(self, connections: Dict) -> float:
        """Calculate Shannon entropy of connection distribution."""
        if not connections:
            return 0.0
        
        import math
        total = sum(connections.values())
        entropy = 0.0
        
        for count in connections.values():
            if count > 0:
                prob = count / total
                entropy -= prob * math.log2(prob)
        
        return entropy

    def _detect_port_scan(self) -> float:
        """
        Detect port scanning behavior.
        Returns indicator score (0-1).
        """
        unique_ports = len(self.window_data["ports"])
        unique_ips = len(self.window_data["ips"])
        
        # High port-to-IP ratio indicates scanning
        if unique_ips > 0:
            ratio = unique_ports / unique_ips
            # Normalize to 0-1 scale (10+ ports per IP = 1.0)
            return min(ratio / 10, 1.0)
        
        return 0.0

    def _calculate_traffic_spike(self) -> float:
        """
        Calculate traffic spike ratio compared to baseline.
        Returns multiplier (e.g., 2.5 = 2.5x normal traffic).
        """
        # Simple baseline: average 100 packets per window
        baseline_pps = 10  # packets per second
        current_pps = len(self.window_data["packets"]) / self.window_seconds
        
        if baseline_pps > 0:
            return current_pps / baseline_pps
        
        return 1.0

    def reset_window(self) -> None:
        """Reset window for next time period."""
        self.window_start = datetime.utcnow()
        self.window_data = {
            "packets": [],
            "connections": defaultdict(int),
            "ports": set(),
            "ips": set(),
            "protocols": defaultdict(int),
            "packet_sizes": [],
            "failed_connections": 0,
            "login_attempts": 0,
            "dns_requests": 0,
            "arp_requests": 0,
            "syn_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
        }

    def should_extract(self) -> bool:
        """Check if window duration has elapsed."""
        elapsed = (datetime.utcnow() - self.window_start).total_seconds()
        return elapsed >= self.window_seconds
