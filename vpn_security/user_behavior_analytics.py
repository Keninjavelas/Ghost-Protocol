"""
User Behavior Analytics (UBA) - Behavioral Profiling and Anomaly Detection

Builds behavioral profiles for users/devices and detects anomalies indicating:
- Insider threats
- Compromised accounts
- Abnormal access patterns
- Policy violations
"""

import time
import math
from collections import defaultdict, deque
from typing import Optional
import structlog
from .feature_extractor import ExtractedFeatures


logger = structlog.get_logger(__name__)


class UserProfile:
    """Behavioral profile for a user/device"""
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.first_seen = time.time()
        self.last_seen = time.time()
        
        # Behavioral characteristics
        self.typical_hours = set()
        self.typical_ips = set()
        self.typical_ports = set()
        self.typical_volume = deque(maxlen=100)  # Last 100 sessions
        self.typical_duration = deque(maxlen=100)
        
        # Activity patterns
        self.total_sessions = 0
        self.total_bytes_transferred = 0
        self.avg_session_duration = 0.0
        self.avg_bytes_per_session = 0.0
        
        # Risk indicators
        self.anomaly_score = 0.0
        self.risk_score = 0.0
        self.violations = []


class BehavioralAnomaly:
    """Detected behavioral anomaly"""
    def __init__(
        self,
        anomaly_type: str,
        severity: str,
        description: str,
        deviation_score: float,
        evidence: dict
    ):
        self.anomaly_type = anomaly_type
        self.severity = severity
        self.description = description
        self.deviation_score = deviation_score
        self.evidence = evidence
        self.timestamp = time.time()


class UserBehaviorAnalytics:
    """
    User Behavior Analytics engine.
    
    Analyzes user behavior patterns to detect:
    - Insider threats
    - Compromised credentials
    - Policy violations
    - Anomalous activity
    """
    
    def __init__(self, learning_period: int = 604800):  # 7 days
        """
        Initialize UBA engine.
        
        Args:
            learning_period: Time to establish baseline (seconds)
        """
        self.learning_period = learning_period
        
        # User profiles
        self.profiles: dict[str, UserProfile] = {}
        
        # Anomaly thresholds
        self.volume_deviation_threshold = 3.0  # 3 standard deviations
        self.duration_deviation_threshold = 3.0
        self.new_behavior_threshold = 0.7  # 70% confidence
        
        # Statistics
        self.anomalies_detected = 0
        self.insider_threats_flagged = 0
        
        logger.info("uba_initialized", learning_period=learning_period)
    
    def analyze_user(
        self,
        user_id: str,
        features: ExtractedFeatures,
        session_metadata: Optional[dict] = None
    ) -> tuple[UserProfile, list[BehavioralAnomaly]]:
        """
        Analyze user behavior and detect anomalies.
        
        Args:
            user_id: User identifier
            features: Extracted traffic features
            session_metadata: Additional session info
            
        Returns:
            Tuple of (updated_profile, anomalies)
        """
        # Get or create profile
        if user_id not in self.profiles:
            self.profiles[user_id] = UserProfile(user_id)
        
        profile = self.profiles[user_id]
        anomalies = []
        
        # Check if still in learning period
        profile_age = time.time() - profile.first_seen
        is_learning = profile_age < self.learning_period
        
        if not is_learning:
            # Detect anomalies
            volume_anomalies = self._detect_volume_anomalies(profile, features)
            anomalies.extend(volume_anomalies)
            
            duration_anomalies = self._detect_duration_anomalies(profile, features)
            anomalies.extend(duration_anomalies)
            
            temporal_anomalies = self._detect_temporal_anomalies(profile, features)
            anomalies.extend(temporal_anomalies)
            
            access_anomalies = self._detect_access_anomalies(profile, features)
            anomalies.extend(access_anomalies)
            
            behavioral_anomalies = self._detect_behavioral_changes(profile, features)
            anomalies.extend(behavioral_anomalies)
        
        # Update profile
        self._update_profile(profile, features, session_metadata)
        
        # Calculate risk scores
        self._update_risk_scores(profile, anomalies)
        
        if anomalies:
            self.anomalies_detected += len(anomalies)
            
            # Check for insider threat indicators
            if self._is_insider_threat(profile, anomalies):
                self.insider_threats_flagged += 1
                logger.warning(
                    "potential_insider_threat",
                    user_id=user_id,
                    anomalies=len(anomalies),
                    risk_score=profile.risk_score
                )
        
        return profile, anomalies
    
    def _detect_volume_anomalies(
        self,
        profile: UserProfile,
        features: ExtractedFeatures
    ) -> list[BehavioralAnomaly]:
        """Detect unusual data volume"""
        anomalies = []
        
        if len(profile.typical_volume) < 10:
            return anomalies
        
        # Calculate baseline statistics
        volumes = list(profile.typical_volume)
        mean_volume = sum(volumes) / len(volumes)
        variance = sum((x - mean_volume) ** 2 for x in volumes) / len(volumes)
        std_dev = math.sqrt(variance)
        
        if std_dev == 0:
            return anomalies
        
        # Calculate z-score
        z_score = (features.total_bytes - mean_volume) / std_dev
        
        if abs(z_score) > self.volume_deviation_threshold:
            severity = "critical" if abs(z_score) > 4 else "high"
            anomalies.append(BehavioralAnomaly(
                anomaly_type="volume_anomaly",
                severity=severity,
                description=f"Data volume {z_score:.1f} standard deviations from baseline",
                deviation_score=abs(z_score),
                evidence={
                    "current_bytes": features.total_bytes,
                    "mean_bytes": mean_volume,
                    "std_dev": std_dev,
                    "z_score": z_score
                }
            ))
        
        return anomalies
    
    def _detect_duration_anomalies(
        self,
        profile: UserProfile,
        features: ExtractedFeatures
    ) -> list[BehavioralAnomaly]:
        """Detect unusual session duration"""
        anomalies = []
        
        if len(profile.typical_duration) < 10:
            return anomalies
        
        durations = list(profile.typical_duration)
        mean_duration = sum(durations) / len(durations)
        variance = sum((x - mean_duration) ** 2 for x in durations) / len(durations)
        std_dev = math.sqrt(variance)
        
        if std_dev == 0:
            return anomalies
        
        z_score = (features.session_duration - mean_duration) / std_dev
        
        if abs(z_score) > self.duration_deviation_threshold:
            anomalies.append(BehavioralAnomaly(
                anomaly_type="duration_anomaly",
                severity="medium",
                description=f"Session duration {z_score:.1f} standard deviations from baseline",
                deviation_score=abs(z_score),
                evidence={
                    "current_duration": features.session_duration,
                    "mean_duration": mean_duration,
                    "z_score": z_score
                }
            ))
        
        return anomalies
    
    def _detect_temporal_anomalies(
        self,
        profile: UserProfile,
        features: ExtractedFeatures
    ) -> list[BehavioralAnomaly]:
        """Detect unusual access times"""
        anomalies = []
        
        import datetime
        current_hour = datetime.datetime.now().hour
        
        # Check if user typically accesses at this hour
        if profile.total_sessions >= 20:  # Sufficient data
            if current_hour not in profile.typical_hours:
                anomalies.append(BehavioralAnomaly(
                    anomaly_type="unusual_access_time",
                    severity="medium",
                    description=f"Access at atypical hour: {current_hour}:00",
                    deviation_score=1.0,
                    evidence={
                        "current_hour": current_hour,
                        "typical_hours": sorted(list(profile.typical_hours))
                    }
                ))
        
        return anomalies
    
    def _detect_access_anomalies(
        self,
        profile: UserProfile,
        features: ExtractedFeatures
    ) -> list[BehavioralAnomaly]:
        """Detect unusual access patterns"""
        anomalies = []
        
        src_ip = features.flow_id.split(":")[0]
        
        # New IP address
        if src_ip not in profile.typical_ips and len(profile.typical_ips) >= 5:
            anomalies.append(BehavioralAnomaly(
                anomaly_type="new_ip_address",
                severity="high",
                description=f"Access from new IP address: {src_ip}",
                deviation_score=1.0,
                evidence={
                    "new_ip": src_ip,
                    "known_ips": list(profile.typical_ips)[:5]
                }
            ))
        
        # Unusual destination port
        if features.dst_port not in profile.typical_ports and len(profile.typical_ports) >= 10:
            anomalies.append(BehavioralAnomaly(
                anomaly_type="unusual_port",
                severity="medium",
                description=f"Connection to atypical port: {features.dst_port}",
                deviation_score=0.8,
                evidence={
                    "port": features.dst_port,
                    "typical_ports": sorted(list(profile.typical_ports))[:10]
                }
            ))
        
        return anomalies
    
    def _detect_behavioral_changes(
        self,
        profile: UserProfile,
        features: ExtractedFeatures
    ) -> list[BehavioralAnomaly]:
        """Detect sudden behavioral changes"""
        anomalies = []
        
        # Sudden increase in activity frequency
        if profile.total_sessions >= 50:
            # Calculate recent session rate
            recent_window = 3600  # 1 hour
            current_time = time.time()
            
            # Would track recent session timestamps in production
            # For now, detect based on burst indicators
            if features.has_burst_traffic and not profile.anomaly_score > 0:
                anomalies.append(BehavioralAnomaly(
                    anomaly_type="activity_spike",
                    severity="medium",
                    description="Sudden increase in activity frequency",
                    deviation_score=1.5,
                    evidence={
                        "burst_traffic": True,
                        "burstiness_score": features.burstiness_score
                    }
                ))
        
        return anomalies
    
    def _update_profile(
        self,
        profile: UserProfile,
        features: ExtractedFeatures,
        metadata: Optional[dict]
    ):
        """Update user behavioral profile"""
        import datetime
        
        profile.last_seen = time.time()
        profile.total_sessions += 1
        profile.total_bytes_transferred += features.total_bytes
        
        # Update typical hours
        current_hour = datetime.datetime.now().hour
        profile.typical_hours.add(current_hour)
        
        # Update typical IPs
        src_ip = features.flow_id.split(":")[0]
        profile.typical_ips.add(src_ip)
        if len(profile.typical_ips) > 20:  # Keep recent 20
            profile.typical_ips = set(list(profile.typical_ips)[-20:])
        
        # Update typical ports
        profile.typical_ports.add(features.dst_port)
        
        # Update volume tracking
        profile.typical_volume.append(features.total_bytes)
        profile.typical_duration.append(features.session_duration)
        
        # Update averages
        profile.avg_session_duration = sum(profile.typical_duration) / len(profile.typical_duration)
        profile.avg_bytes_per_session = sum(profile.typical_volume) / len(profile.typical_volume)
    
    def _update_risk_scores(self, profile: UserProfile, anomalies: list[BehavioralAnomaly]):
        """Update profile risk scores"""
        # Calculate anomaly score
        if anomalies:
            severity_weights = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5}
            total_weight = sum(severity_weights.get(a.severity, 0) for a in anomalies)
            profile.anomaly_score = min(total_weight / 10.0, 1.0)
        else:
            # Decay anomaly score
            profile.anomaly_score = max(profile.anomaly_score * 0.9, 0.0)
        
        # Calculate overall risk score (0-100)
        base_risk = profile.anomaly_score * 50
        historical_risk = len(profile.violations) * 5
        profile.risk_score = min(base_risk + historical_risk, 100.0)
    
    def _is_insider_threat(self, profile: UserProfile, anomalies: list[BehavioralAnomaly]) -> bool:
        """Determine if behavior indicates insider threat"""
        # High-risk indicators
        data_exfil = any(a.anomaly_type == "volume_anomaly" for a in anomalies)
        unusual_access = any(a.anomaly_type in ["new_ip_address", "unusual_access_time"] for a in anomalies)
        critical_anomaly = any(a.severity == "critical" for a in anomalies)
        
        # Insider threat if multiple high-risk indicators
        return (
            (data_exfil and unusual_access) or
            (critical_anomaly and len(anomalies) >= 2) or
            profile.risk_score > 75
        )
    
    def get_user_profile(self, user_id: str) -> Optional[UserProfile]:
        """Get user profile"""
        return self.profiles.get(user_id)
    
    def get_high_risk_users(self, threshold: float = 60.0) -> list[UserProfile]:
        """Get users with risk score above threshold"""
        return [
            profile for profile in self.profiles.values()
            if profile.risk_score >= threshold
        ]
    
    def get_statistics(self) -> dict:
        """Get UBA statistics"""
        return {
            "profiles_created": len(self.profiles),
            "anomalies_detected": self.anomalies_detected,
            "insider_threats_flagged": self.insider_threats_flagged,
            "high_risk_users": len(self.get_high_risk_users())
        }
