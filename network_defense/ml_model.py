"""
Module 6: ML-Based Threat Classifier
Machine learning models for threat detection and anomaly detection.
"""

from typing import Dict, Optional, List
import structlog
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path

logger = structlog.get_logger(__name__)


class ThreatClassifier:
    """
    ML-based threat classifier using Random Forest and Isolation Forest.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        use_isolation_forest: bool = True
    ):
        """
        Initialize threat classifier.
        
        Args:
            model_path: Path to pre-trained model (None = train new model)
            use_isolation_forest: Enable anomaly detection
        """
        self.model_path = model_path
        self.use_isolation_forest = use_isolation_forest
        
        # Models
        self.classifier: Optional[RandomForestClassifier] = None
        self.anomaly_detector: Optional[IsolationForest] = None
        self.scaler = StandardScaler()
        
        # Feature names (must match feature extractor output)
        self.feature_names = [
            "connection_count",
            "packet_count",
            "packet_rate",
            "unique_ports_accessed",
            "unique_ips_contacted",
            "failed_connections",
            "login_attempts",
            "failed_logins",
            "dns_requests",
            "arp_requests",
            "syn_packets",
            "udp_packets",
            "icmp_packets",
            "average_packet_size",
            "packet_size_variance",
            "max_packet_size",
            "min_packet_size",
            "bytes_sent",
            "bytes_per_second",
            "connection_duration",
            "flow_entropy",
            "port_scan_indicator",
            "traffic_spike_ratio",
        ]
        
        # Load or initialize models
        if model_path and Path(model_path).exists():
            self._load_model(model_path)
        else:
            self._initialize_models()
        
        logger.info(
            "threat_classifier_initialized",
            model_loaded=model_path is not None,
            anomaly_detection=use_isolation_forest
        )

    def _initialize_models(self) -> None:
        """Initialize ML models with default parameters."""
        # Random Forest for classification
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        
        # Isolation Forest for anomaly detection
        if self.use_isolation_forest:
            self.anomaly_detector = IsolationForest(
                contamination=0.1,  # 10% anomaly rate
                random_state=42,
                n_jobs=-1
            )
        
        logger.info("ml_models_initialized")

    def predict(self, features: Dict) -> Dict:
        """
        Predict threat from feature vector.
        
        Args:
            features: Feature dictionary from feature extractor
        
        Returns:
            Prediction result with threat probability and attack type
        """
        try:
            # Convert features to array
            feature_vector = self._features_to_vector(features)
            
            # Normalize features
            feature_vector_scaled = self.scaler.transform([feature_vector])
            
            # Classification prediction (if model is trained)
            attack_type = "unknown"
            confidence = 0.0
            threat_probability = 0.0
            
            if self.classifier and hasattr(self.classifier, "classes_"):
                # Model is trained
                proba = self.classifier.predict_proba(feature_vector_scaled)[0]
                predicted_class = self.classifier.predict(feature_vector_scaled)[0]
                
                attack_type = self._map_class_to_attack(predicted_class)
                confidence = float(max(proba))
                threat_probability = float(proba[-1]) if len(proba) > 1 else confidence
            else:
                # Model not trained - use heuristic
                threat_probability = self._heuristic_threat_score(features)
                confidence = 0.5
                attack_type = self._heuristic_attack_type(features)
            
            # Anomaly detection
            anomaly_score = 0.0
            is_anomaly = False
            
            if self.anomaly_detector and hasattr(self.anomaly_detector, "offset_"):
                anomaly_pred = self.anomaly_detector.predict(feature_vector_scaled)[0]
                is_anomaly = anomaly_pred == -1
                
                # Get anomaly score
                anomaly_scores = self.anomaly_detector.score_samples(feature_vector_scaled)
                anomaly_score = float(-anomaly_scores[0])  # Higher = more anomalous
            
            result = {
                "threat_probability": threat_probability,
                "attack_type": attack_type,
                "confidence": confidence,
                "is_anomaly": is_anomaly,
                "anomaly_score": anomaly_score,
            }
            
            logger.debug(
                "prediction_complete",
                threat_probability=threat_probability,
                attack_type=attack_type,
                is_anomaly=is_anomaly
            )
            
            return result
        
        except Exception as e:
            logger.error("prediction_failed", error=str(e))
            return {
                "threat_probability": 0.0,
                "attack_type": "error",
                "confidence": 0.0,
                "is_anomaly": False,
                "anomaly_score": 0.0,
            }

    def train(
        self,
        X: List[Dict],
        y: List[str],
        save_path: Optional[str] = None
    ) -> None:
        """
        Train the classifier on labeled data.
        
        Args:
            X: List of feature dictionaries
            y: List of attack type labels
            save_path: Path to save trained model
        """
        try:
            # Convert features to array
            X_array = np.array([self._features_to_vector(features) for features in X])
            
            # Fit scaler
            self.scaler.fit(X_array)
            X_scaled = self.scaler.transform(X_array)
            
            # Train classifier
            self.classifier.fit(X_scaled, y)
            
            # Train anomaly detector (unsupervised)
            if self.anomaly_detector:
                self.anomaly_detector.fit(X_scaled)
            
            logger.info(
                "model_trained",
                samples=len(X),
                classes=len(set(y))
            )
            
            # Save model
            if save_path:
                self.save_model(save_path)
        
        except Exception as e:
            logger.error("training_failed", error=str(e))

    def _features_to_vector(self, features: Dict) -> np.ndarray:
        """Convert feature dictionary to numpy array."""
        return np.array([
            features.get(name, 0.0)
            for name in self.feature_names
        ])

    def _heuristic_threat_score(self, features: Dict) -> float:
        """Calculate threat score using heuristics (when model not trained)."""
        score = 0.0
        
        # High port scanning indicator
        if features.get("port_scan_indicator", 0) > 0.5:
            score += 0.3
        
        # High login attempts
        if features.get("login_attempts", 0) > 20:
            score += 0.2
        
        # High traffic spike
        if features.get("traffic_spike_ratio", 0) > 3.0:
            score += 0.2
        
        # High SYN packets (potential SYN flood)
        if features.get("syn_packets", 0) > 100:
            score += 0.2
        
        # High failed connections
        if features.get("failed_connections", 0) > 50:
            score += 0.1
        
        return min(score, 1.0)

    def _heuristic_attack_type(self, features: Dict) -> str:
        """Determine attack type using heuristics."""
        if features.get("port_scan_indicator", 0) > 0.5:
            return "port_scan"
        elif features.get("login_attempts", 0) > 50:
            return "brute_force"
        elif features.get("syn_packets", 0) > 100:
            return "syn_flood"
        elif features.get("udp_packets", 0) > 100:
            return "udp_flood"
        elif features.get("icmp_packets", 0) > 50:
            return "icmp_flood"
        else:
            return "suspicious_activity"

    def _map_class_to_attack(self, predicted_class: int) -> str:
        """Map classifier output class to attack type name."""
        # This mapping would be defined during training
        attack_types = [
            "normal",
            "port_scan",
            "brute_force",
            "dos",
            "ddos",
            "malware",
            "exfiltration",
            "reconnaissance"
        ]
        
        if 0 <= predicted_class < len(attack_types):
            return attack_types[predicted_class]
        
        return "unknown"

    def save_model(self, path: str) -> None:
        """Save trained model to disk."""
        try:
            model_data = {
                "classifier": self.classifier,
                "anomaly_detector": self.anomaly_detector,
                "scaler": self.scaler,
                "feature_names": self.feature_names,
            }
            joblib.dump(model_data, path)
            logger.info("model_saved", path=path)
        except Exception as e:
            logger.error("model_save_failed", error=str(e))

    def _load_model(self, path: str) -> None:
        """Load trained model from disk."""
        try:
            model_data = joblib.load(path)
            self.classifier = model_data["classifier"]
            self.anomaly_detector = model_data.get("anomaly_detector")
            self.scaler = model_data["scaler"]
            self.feature_names = model_data["feature_names"]
            logger.info("model_loaded", path=path)
        except Exception as e:
            logger.error("model_load_failed", error=str(e))
            self._initialize_models()
