"""
Network-level anomaly detection for MITM, DNS hijacking, and exfiltration.
"""

import asyncio
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import structlog

logger = structlog.get_logger(__name__)


class NetworkAnomalyDetector:
    """
    Monitors network traffic patterns to detect anomalies indicating compromise.
    """

    def __init__(
        self,
        baseline_window_seconds: int = 300,
        anomaly_threshold: float = 2.5
    ):
        """
        Initialize network anomaly detector.
        
        Args:
            baseline_window_seconds: Time window for baseline calculation
            anomaly_threshold: Multiplier for detecting anomalies (e.g., 2.5x baseline)
        """
        self.baseline_window = timedelta(seconds=baseline_window_seconds)
        self.anomaly_threshold = anomaly_threshold
        
        # Traffic metrics
        self._packet_counts: Dict[str, List[Tuple[datetime, int]]] = defaultdict(list)
        self._byte_counts: Dict[str, List[Tuple[datetime, int]]] = defaultdict(list)
        self._dns_queries: List[Tuple[datetime, str]] = []
        self._connection_timeouts: List[datetime] = []
        
        logger.info(
            "network_monitor_initialized",
            baseline_window_seconds=baseline_window_seconds,
            threshold=anomaly_threshold
        )

    def record_traffic(self, source_ip: str, packet_count: int, byte_count: int):
        """Record traffic metrics for anomaly detection."""
        now = datetime.utcnow()
        
        self._packet_counts[source_ip].append((now, packet_count))
        self._byte_counts[source_ip].append((now, byte_count))
        
        # Clean old entries outside baseline window
        cutoff = now - self.baseline_window
        self._packet_counts[source_ip] = [
            (t, c) for t, c in self._packet_counts[source_ip] if t > cutoff
        ]
        self._byte_counts[source_ip] = [
            (t, c) for t, c in self._byte_counts[source_ip] if t > cutoff
        ]

    def record_dns_query(self, query: str):
        """Record DNS query for hijacking detection."""
        now = datetime.utcnow()
        self._dns_queries.append((now, query))
        
        # Clean old queries
        cutoff = now - self.baseline_window
        self._dns_queries = [(t, q) for t, q in self._dns_queries if t > cutoff]

    def record_connection_timeout(self):
        """Record connection timeout for MITM detection."""
        now = datetime.utcnow()
        self._connection_timeouts.append(now)
        
        # Clean old timeouts
        cutoff = now - self.baseline_window
        self._connection_timeouts = [t for t in self._connection_timeouts if t > cutoff]

    def detect_anomalies(self) -> List[Dict[str, any]]:
        """
        Analyze metrics and detect anomalies.
        
        Returns:
            List of anomaly dictionaries with type, severity, and details
        """
        anomalies = []
        
        # Exfiltration detection (high traffic volume)
        for source_ip, byte_history in self._byte_counts.items():
            if len(byte_history) < 2:
                continue
            
            total_bytes = sum(c for _, c in byte_history)
            avg_bytes = total_bytes / len(byte_history)
            
            # Check for spikes
            recent_bytes = sum(c for t, c in byte_history if t > datetime.utcnow() - timedelta(seconds=60))
            
            if recent_bytes > avg_bytes * self.anomaly_threshold:
                anomalies.append({
                    "type": "exfiltration",
                    "severity": "high",
                    "source_ip": source_ip,
                    "recent_bytes": recent_bytes,
                    "baseline_bytes": avg_bytes,
                    "threshold": self.anomaly_threshold
                })
                logger.warning(
                    "exfiltration_detected",
                    source_ip=source_ip,
                    recent_bytes=recent_bytes,
                    baseline=avg_bytes
                )
        
        # DNS hijacking detection (repeated unusual queries)
        dns_query_counts = defaultdict(int)
        for _, query in self._dns_queries:
            dns_query_counts[query] += 1
        
        for query, count in dns_query_counts.items():
            if count > 10:  # Repeated queries (possible hijack attempt)
                anomalies.append({
                    "type": "dns_hijack",
                    "severity": "medium",
                    "query": query,
                    "count": count
                })
                logger.warning("dns_hijack_detected", query=query, count=count)
        
        # MITM detection (connection timeouts)
        recent_timeouts = len(self._connection_timeouts)
        if recent_timeouts > 5:
            anomalies.append({
                "type": "mitm",
                "severity": "medium",
                "timeout_count": recent_timeouts,
                "window_seconds": self.baseline_window.total_seconds()
            })
            logger.warning("mitm_detected", timeout_count=recent_timeouts)
        
        # DDoS detection (high packet counts from single source)
        for source_ip, packet_history in self._packet_counts.items():
            total_packets = sum(c for _, c in packet_history)
            
            if total_packets > 1000:  # Arbitrary threshold
                anomalies.append({
                    "type": "ddos",
                    "severity": "high",
                    "source_ip": source_ip,
                    "packet_count": total_packets
                })
                logger.warning("ddos_detected", source_ip=source_ip, packets=total_packets)
        
        return anomalies
