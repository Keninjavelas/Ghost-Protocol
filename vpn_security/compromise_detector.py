"""
Compromise Detector - VPN Infrastructure Compromise Detection

Detects compromised VPN gateway/credentials through:
- Anomalous login patterns
- Traffic volume changes
- Geographic access analysis  
- Privilege escalation attempts
- Unauthorized data transfers
"""

import time
from collections import defaultdict
from typing import Optional
import structlog
from .feature_extractor import ExtractedFeatures


logger = structlog.get_logger(__name__)


class CompromiseIndicator:
    """Indicator of potential compromise"""
    def __init__(
        self,
        indicator_type: str,
        severity: str,
        description: str,
        evidence: dict,
        timestamp: float
    ):
        self.indicator_type = indicator_type
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.timestamp = timestamp


class CompromiseDetector:
    """
    VPN compromise detection engine.
    
    Monitors for signs of compromised VPN infrastructure including:
    - Credential theft
    - Gateway compromise
    - Session hijacking
    - Data exfiltration
    """
    
    def __init__(self):
        """Initialize compromise detector"""
        # User session tracking
        self.user_sessions = defaultdict(list)
        self.user_baselines = {}
        
        # IP tracking
        self.ip_volumes = defaultdict(int)
        self.ip_first_seen = {}
        self.ip_locations = {}  # Would integrate with GeoIP
        
        # Anomaly thresholds
        self.volume_spike_threshold = 5.0  # 5x normal
        self.rapid_login_threshold = 300  # 5 minutes
        self.unusual_hours_start = 22  # 10 PM
        self.unusual_hours_end = 6  # 6 AM
        
        # Statistics
        self.compromises_detected = 0
        self.false_positive_rate = 0.0
        
        logger.info("compromise_detector_initialized")
    
    def analyze(
        self,
        features: ExtractedFeatures,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> tuple[bool, list[CompromiseIndicator]]:
        """
        Analyze traffic for compromise indicators.
        
        Args:
            features: Extracted traffic features
            user_id: User identifier (if available)
            session_id: Session identifier
            
        Returns:
            Tuple of (is_compromised, indicators)
        """
        indicators = []
        
        # Check traffic volume anomalies
        volume_indicators = self._detect_volume_anomalies(features)
        indicators.extend(volume_indicators)
        
        # Check geographic anomalies
        geo_indicators = self._detect_geographic_anomalies(features, user_id)
        indicators.extend(geo_indicators)
        
        # Check temporal anomalies
        temporal_indicators = self._detect_temporal_anomalies(features, user_id)
        indicators.extend(temporal_indicators)
        
        # Check for data exfiltration
        exfil_indicators = self._detect_exfiltration(features)
        indicators.extend(exfil_indicators)
        
        # Check for privilege escalation attempts
        priv_indicators = self._detect_privilege_escalation(features)
        indicators.extend(priv_indicators)
        
        # Check for suspicious connection patterns
        conn_indicators = self._detect_suspicious_connections(features)
        indicators.extend(conn_indicators)
        
        # Determine if compromised
        critical_indicators = [i for i in indicators if i.severity == "critical"]
        high_indicators = [i for i in indicators if i.severity == "high"]
        
        is_compromised = (
            len(critical_indicators) >= 1 or
            len(high_indicators) >= 2 or
            len(indicators) >= 4
        )
        
        if is_compromised:
            self.compromises_detected += 1
            logger.warning(
                "potential_compromise_detected",
                flow_id=features.flow_id,
                indicators=len(indicators),
                user_id=user_id
            )
        
        return is_compromised, indicators
    
    def _detect_volume_anomalies(self, features: ExtractedFeatures) -> list[CompromiseIndicator]:
        """Detect unusual traffic volume (potential data exfiltration)"""
        indicators = []
        
        src_ip = features.flow_id.split(":")[0]
        
        # Track historical volume
        if src_ip not in self.ip_first_seen:
            self.ip_first_seen[src_ip] = time.time()
            self.ip_volumes[src_ip] = features.total_bytes
            return indicators
        
        # Calculate baseline
        historical_volume = self.ip_volumes[src_ip]
        if historical_volume == 0:
            historical_volume = 1
        
        volume_ratio = features.total_bytes / historical_volume
        
        # Significant volume spike
        if volume_ratio > self.volume_spike_threshold:
            indicators.append(CompromiseIndicator(
                indicator_type="volume_spike",
                severity="high",
                description=f"Traffic volume {volume_ratio:.1f}x higher than baseline",
                evidence={
                    "current_bytes": features.total_bytes,
                    "baseline_bytes": historical_volume,
                    "ratio": volume_ratio
                },
                timestamp=time.time()
            ))
        
        # Update tracking
        self.ip_volumes[src_ip] += features.total_bytes
        
        return indicators
    
    def _detect_geographic_anomalies(
        self,
        features: ExtractedFeatures,
        user_id: Optional[str]
    ) -> list[CompromiseIndicator]:
        """Detect impossible travel / geographic anomalies"""
        indicators = []
        
        if not user_id:
            return indicators
        
        # In production, integrate with GeoIP database
        # For now, detect rapid IP changes as proxy
        
        src_ip = features.flow_id.split(":")[0]
        current_time = time.time()
        
        if user_id in self.user_sessions:
            recent_sessions = [
                s for s in self.user_sessions[user_id]
                if current_time - s['timestamp'] < 3600  # Last hour
            ]
            
            if recent_sessions:
                # Check for rapid location changes
                unique_ips = set(s['ip'] for s in recent_sessions)
                unique_ips.add(src_ip)
                
                if len(unique_ips) > 3:  # More than 3 IPs in 1 hour
                    indicators.append(CompromiseIndicator(
                        indicator_type="rapid_ip_changes",
                        severity="high",
                        description="Multiple IP addresses used within short timeframe",
                        evidence={
                            "unique_ips": len(unique_ips),
                            "timeframe_seconds": 3600,
                            "ips": list(unique_ips)
                        },
                        timestamp=current_time
                    ))
        
        # Track session
        self.user_sessions[user_id].append({
            'ip': src_ip,
            'timestamp': current_time
        })
        
        return indicators
    
    def _detect_temporal_anomalies(
        self,
        features: ExtractedFeatures,
        user_id: Optional[str]
    ) -> list[CompromiseIndicator]:
        """Detect unusual access times"""
        indicators = []
        
        import datetime
        current_hour = datetime.datetime.now().hour
        
        # Access during unusual hours
        if self.unusual_hours_start <= current_hour or current_hour < self.unusual_hours_end:
            # Check if user typically accesses during these hours
            if user_id and user_id in self.user_baselines:
                baseline = self.user_baselines[user_id]
                if not baseline.get('off_hours_access', False):
                    indicators.append(CompromiseIndicator(
                        indicator_type="unusual_access_time",
                        severity="medium",
                        description="Access during unusual hours",
                        evidence={
                            "hour": current_hour,
                            "user_baseline": "business_hours_only"
                        },
                        timestamp=time.time()
                    ))
        
        return indicators
    
    def _detect_exfiltration(self, features: ExtractedFeatures) -> list[CompromiseIndicator]:
        """Detect potential data exfiltration"""
        indicators = []
        
        # Large outbound transfer
        if features.total_bytes > 10_000_000:  # > 10 MB
            if features.session_duration < 60:  # In < 1 minute
                indicators.append(CompromiseIndicator(
                    indicator_type="rapid_large_transfer",
                    severity="critical",
                    description="Large data transfer in short timeframe",
                    evidence={
                        "bytes": features.total_bytes,
                        "duration": features.session_duration,
                        "rate_mbps": (features.total_bytes * 8) / (features.session_duration * 1_000_000)
                    },
                    timestamp=time.time()
                ))
        
        # Sustained high throughput
        if features.bytes_per_second > 1_000_000:  # > 1 MB/s sustained
            if features.session_duration > 300:  # For > 5 minutes
                indicators.append(CompromiseIndicator(
                    indicator_type="sustained_exfiltration",
                    severity="high",
                    description="Sustained high-throughput data transfer",
                    evidence={
                        "bytes_per_second": features.bytes_per_second,
                        "duration": features.session_duration,
                        "total_bytes": features.total_bytes
                    },
                    timestamp=time.time()
                ))
        
        return indicators
    
    def _detect_privilege_escalation(self, features: ExtractedFeatures) -> list[CompromiseIndicator]:
        """Detect privilege escalation attempts"""
        indicators = []
        
        # Unusual port scanning behavior through VPN
        if features.syn_count > 100 and features.session_duration < 60:
            indicators.append(CompromiseIndicator(
                indicator_type="port_scanning",
                severity="high",
                description="Rapid port scanning detected through VPN",
                evidence={
                    "syn_packets": features.syn_count,
                    "duration": features.session_duration,
                    "scan_rate": features.syn_count / features.session_duration
                },
                timestamp=time.time()
            ))
        
        return indicators
    
    def _detect_suspicious_connections(self, features: ExtractedFeatures) -> list[CompromiseIndicator]:
        """Detect suspicious connection patterns"""
        indicators = []
        
        # Connection to suspicious ports
        suspicious_ports = {6667, 6668, 6669}  # IRC ports
        if features.dst_port in suspicious_ports:
            indicators.append(CompromiseIndicator(
                indicator_type="suspicious_port",
                severity="medium",
                description=f"Connection to suspicious port {features.dst_port}",
                evidence={
                    "port": features.dst_port,
                    "port_type": "IRC/Command-and-Control"
                },
                timestamp=time.time()
            ))
        
        # Multiple failed connections
        if features.rst_count > 10 and features.syn_count > 10:
            indicators.append(CompromiseIndicator(
                indicator_type="connection_failures",
                severity="medium",
                description="Multiple failed connection attempts",
                evidence={
                    "rst_count": features.rst_count,
                    "syn_count": features.syn_count,
                    "failure_rate": features.rst_count / features.syn_count
                },
                timestamp=time.time()
            ))
        
        return indicators
    
    def update_baseline(self, user_id: str, characteristics: dict):
        """Update user baseline characteristics"""
        self.user_baselines[user_id] = characteristics
        logger.debug("baseline_updated", user_id=user_id)
    
    def get_statistics(self) -> dict:
        """Get detection statistics"""
        return {
            "compromises_detected": self.compromises_detected,
            "tracked_users": len(self.user_baselines),
            "tracked_ips": len(self.ip_first_seen),
            "false_positive_rate": self.false_positive_rate
        }
