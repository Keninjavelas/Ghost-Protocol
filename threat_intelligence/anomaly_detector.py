"""
Anomaly detection using isolation forest patterns.
"""

from typing import Dict, List, Tuple
from collections import deque
from datetime import datetime, timezone, timedelta
import statistics

import structlog

logger = structlog.get_logger(__name__)


class AnomalyDetector:
    """
    Unsupervised anomaly detection using statistical deviations.
    Tracks baselines and detects outliers.
    """

    def __init__(self, baseline_window: int = 100):
        """
        Initialize anomaly detector.
        
        Args:
            baseline_window: Number of samples for baseline
        """
        self.baseline_window = baseline_window
        
        # Baseline statistics per feature
        self._baselines: Dict[str, Dict] = {}
        self._feature_history: Dict[str, deque] = {
            "packet_rate": deque(maxlen=baseline_window),
            "bytes_sent": deque(maxlen=baseline_window),
            "connection_count": deque(maxlen=baseline_window),
            "unique_ips": deque(maxlen=baseline_window),
        }
        
        logger.info(
            "anomaly_detector_initialized",
            baseline_window=baseline_window
        )

    def detect(self, features) -> Tuple[bool, float]:
        """
        Detect anomalies in feature set.
        
        Returns:
            (is_anomaly, anomaly_score)
        """
        anomaly_scores = []
        
        # Update baselines
        self._update_baselines(features)
        
        # Check each feature
        anomaly_scores.append(
            self._check_feature_anomaly(features.packet_rate, "packet_rate")
        )
        anomaly_scores.append(
            self._check_feature_anomaly(features.bytes_sent, "bytes_sent")
        )
        anomaly_scores.append(
            self._check_feature_anomaly(features.connection_count, "connection_count")
        )
        anomaly_scores.append(
            self._check_feature_anomaly(features.unique_ips_contacted, "unique_ips")
        )
        
        # Check multivariate anomalies
        anomaly_scores.append(self._check_multivariate(features))
        
        # Aggregate scores
        final_score = sum(anomaly_scores) / len(anomaly_scores)
        is_anomaly = final_score > 0.6
        
        return is_anomaly, final_score

    def _update_baselines(self, features) -> None:
        """Update baseline statistics."""
        self._feature_history["packet_rate"].append(features.packet_rate)
        self._feature_history["bytes_sent"].append(features.bytes_sent)
        self._feature_history["connection_count"].append(features.connection_count)
        self._feature_history["unique_ips"].append(features.unique_ips_contacted)

    def _check_feature_anomaly(self, value: float, feature_name: str) -> float:
        """Check if single feature is anomalous."""
        history = self._feature_history.get(feature_name, deque())
        
        if len(history) < 5:  # Not enough baseline data
            return 0.0
        
        history_list = list(history)
        mean = statistics.mean(history_list)
        
        if mean == 0:
            return 0.0
        
        try:
            stdev = statistics.stdev(history_list)
        except:
            return 0.0
        
        if stdev == 0:
            return 0.0
        
        # Z-score
        z_score = abs((value - mean) / stdev)
        
        # Convert to anomaly score
        if z_score > 3:
            return 0.9  # Strong anomaly
        elif z_score > 2:
            return 0.6  # Moderate anomaly
        else:
            return 0.0  # Normal

    def _check_multivariate(self, features) -> float:
        """Check for multivariate anomalies."""
        score = 0.0
        
        # Combination indicators
        if (features.bytes_sent > 50 * 1024 * 1024 and
            features.unique_ips_contacted > 50):
            score += 0.3
        
        if (features.connection_count > 200 and
            features.traffic_spike_ratio > 5.0):
            score += 0.3
        
        if (features.failed_connections > 100 and
            features.login_attempts > 80):
            score += 0.4
        
        # Entropy-based
        if features.flow_entropy > 4.0:
            score += 0.2
        
        return min(score, 1.0)

    def get_baseline_stats(self, feature_name: str) -> Dict:
        """Get baseline statistics for a feature."""
        history = self._feature_history.get(feature_name, deque())
        
        if not history:
            return {}
        
        history_list = list(history)
        
        return {
            "feature": feature_name,
            "mean": statistics.mean(history_list),
            "median": statistics.median(history_list),
            "stdev": statistics.stdev(history_list) if len(history_list) > 1 else 0,
            "min": min(history_list),
            "max": max(history_list),
            "samples": len(history_list),
        }
