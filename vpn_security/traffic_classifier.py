"""
Traffic Classifier - ML-Based Traffic Classification Engine

Classifies network traffic into categories: NORMAL, VPN, ENCRYPTED_UNKNOWN, SUSPICIOUS.
Uses Random Forest and behavioral pattern matching for classification.
"""

import os
from enum import Enum
from typing import Optional
import structlog
from .feature_extractor import ExtractedFeatures

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


logger = structlog.get_logger(__name__)


class TrafficCategory(Enum):
    """Traffic classification categories"""
    NORMAL = "normal"
    VPN = "vpn"
    ENCRYPTED_UNKNOWN = "encrypted_unknown"
    SUSPICIOUS = "suspicious"
    TUNNEL = "tunnel"


class TrafficClassifier:
    """
    ML-powered traffic classification engine.
    
    Classifies network flows using Random Forest and pattern matching.
    Falls back to heuristic rules when ML model unavailable.
    """
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        confidence_threshold: float = 0.7
    ):
        """
        Initialize traffic classifier.
        
        Args:
            model_path: Path to trained model file
            confidence_threshold: Minimum confidence for classification
        """
        self.model_path = model_path
        self.confidence_threshold = confidence_threshold
        
        # ML components
        self.model: Optional[RandomForestClassifier] = None
        self.scaler: Optional[StandardScaler] = None
        self.model_trained = False
        
        # Load model if available
        if model_path and os.path.exists(model_path):
            self._load_model()
        else:
            self._initialize_model()
        
        # Classification statistics
        self.classifications_total = 0
        self.vpn_detected = 0
        self.suspicious_detected = 0
        self.normal_traffic = 0
        
        logger.info(
            "traffic_classifier_initialized",
            model_trained=self.model_trained,
            ml_available=ML_AVAILABLE
        )
    
    def classify(self, features: ExtractedFeatures) -> tuple[TrafficCategory, float]:
        """
        Classify traffic based on extracted features.
        
        Args:
            features: Extracted behavioral features
            
        Returns:
            Tuple of (category, confidence_score)
        """
        self.classifications_total += 1
        
        # Use ML model if trained
        if self.model_trained and ML_AVAILABLE:
            category, confidence = self._ml_classify(features)
        else:
            category, confidence = self._heuristic_classify(features)
        
        # Update statistics
        if category == TrafficCategory.VPN:
            self.vpn_detected += 1
        elif category == TrafficCategory.SUSPICIOUS:
            self.suspicious_detected += 1
        elif category == TrafficCategory.NORMAL:
            self.normal_traffic += 1
        
        logger.debug(
            "traffic_classified",
            flow_id=features.flow_id,
            category=category.value,
            confidence=confidence
        )
        
        return category, confidence
    
    def _ml_classify(self, features: ExtractedFeatures) -> tuple[TrafficCategory, float]:
        """Classify using ML model"""
        try:
            # Convert features to vector
            from .feature_extractor import FeatureExtractor
            extractor = FeatureExtractor()
            feature_vector = extractor.to_ml_vector(features)
            
            # Scale features
            X = np.array([feature_vector])
            if self.scaler:
                X = self.scaler.transform(X)
            
            # Predict
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            confidence = float(max(probabilities))
            
            # Map prediction to category
            category_map = {
                0: TrafficCategory.NORMAL,
                1: TrafficCategory.VPN,
                2: TrafficCategory.ENCRYPTED_UNKNOWN,
                3: TrafficCategory.SUSPICIOUS,
                4: TrafficCategory.TUNNEL
            }
            
            category = category_map.get(prediction, TrafficCategory.NORMAL)
            
            return category, confidence
        
        except Exception as e:
            logger.error("ml_classification_error", error=str(e))
            return self._heuristic_classify(features)
    
    def _heuristic_classify(self, features: ExtractedFeatures) -> tuple[TrafficCategory, float]:
        """
        Classify using heuristic rules (fallback when ML unavailable).
        
        Rule-based classification using behavioral indicators.
        """
        confidence = 0.0
        indicators = []
        
        # VPN indicators
        vpn_indicators = 0
        
        # 1. Encrypted traffic
        if features.is_encrypted:
            vpn_indicators += 1
            indicators.append("encrypted")
        
        # 2. Long-lived connection
        if features.is_long_lived:
            vpn_indicators += 1
            indicators.append("long_lived")
        
        # 3. High volume
        if features.is_high_volume:
            vpn_indicators += 1
            indicators.append("high_volume")
        
        # 4. Bidirectional
        if features.is_bidirectional:
            vpn_indicators += 1
            indicators.append("bidirectional")
        
        # 5. VPN common ports
        vpn_ports = {443, 1194, 500, 4500, 1701, 1723, 51820}
        if features.dst_port in vpn_ports:
            vpn_indicators += 2  # Strong indicator
            indicators.append(f"vpn_port_{features.dst_port}")
        
        # 6. Consistent packet sizes (tunneling)
        if features.packet_size_variance < 100:
            vpn_indicators += 1
            indicators.append("consistent_packets")
        
        # 7. Burst traffic (keep-alive pattern)
        if features.has_burst_traffic:
            vpn_indicators += 1
            indicators.append("burst_traffic")
        
        # 8. High entropy (encrypted payload)
        if features.packet_size_entropy > 6.0:
            vpn_indicators += 1
            indicators.append("high_entropy")
        
        # Suspicious indicators
        suspicious_score = 0
        
        if features.unusual_port_usage:
            suspicious_score += 1
            indicators.append("unusual_port")
        
        if features.suspicious_packet_pattern:
            suspicious_score += 2
            indicators.append("suspicious_pattern")
        
        if features.potential_tunnel:
            suspicious_score += 2
            indicators.append("potential_tunnel")
        
        # Classification logic
        if vpn_indicators >= 5:
            # Strong VPN signature
            category = TrafficCategory.VPN
            confidence = min(0.6 + (vpn_indicators * 0.05), 0.95)
        
        elif vpn_indicators >= 3 and features.is_encrypted:
            # Likely VPN or encrypted tunnel
            category = TrafficCategory.VPN
            confidence = 0.5 + (vpn_indicators * 0.05)
        
        elif features.is_encrypted and suspicious_score >= 2:
            # Encrypted but suspicious
            category = TrafficCategory.SUSPICIOUS
            confidence = 0.6 + (suspicious_score * 0.1)
        
        elif features.is_encrypted:
            # Encrypted but unclear
            category = TrafficCategory.ENCRYPTED_UNKNOWN
            confidence = 0.5
        
        elif suspicious_score >= 3:
            # Not encrypted but highly suspicious
            category = TrafficCategory.SUSPICIOUS
            confidence = 0.7
        
        elif features.potential_tunnel:
            # Tunnel indicators without encryption
            category = TrafficCategory.TUNNEL
            confidence = 0.6
        
        else:
            # Normal traffic
            category = TrafficCategory.NORMAL
            confidence = 0.8
        
        logger.debug(
            "heuristic_classification",
            flow_id=features.flow_id,
            category=category.value,
            vpn_indicators=vpn_indicators,
            suspicious_score=suspicious_score,
            indicators=indicators
        )
        
        return category, confidence
    
    def train(self, X_train: list[list[float]], y_train: list[int]) -> bool:
        """
        Train the classifier on labeled data.
        
        Args:
            X_train: Feature vectors
            y_train: Labels (0=normal, 1=vpn, 2=encrypted, 3=suspicious, 4=tunnel)
            
        Returns:
            True if training successful
        """
        if not ML_AVAILABLE:
            logger.warning("ml_not_available", msg="Cannot train model")
            return False
        
        try:
            X = np.array(X_train)
            y = np.array(y_train)
            
            # Scale features
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Random Forest
            self.model.fit(X_scaled, y)
            self.model_trained = True
            
            logger.info(
                "model_trained",
                samples=len(X_train),
                features=X.shape[1]
            )
            
            return True
        
        except Exception as e:
            logger.error("training_error", error=str(e))
            return False
    
    def save_model(self, path: str):
        """Save trained model to disk"""
        if not self.model_trained:
            logger.warning("no_model_to_save")
            return
        
        try:
            joblib.dump({
                'model': self.model,
                'scaler': self.scaler
            }, path)
            logger.info("model_saved", path=path)
        except Exception as e:
            logger.error("model_save_error", error=str(e))
    
    def _load_model(self):
        """Load pre-trained model from disk"""
        try:
            data = joblib.load(self.model_path)
            self.model = data['model']
            self.scaler = data['scaler']
            self.model_trained = True
            logger.info("model_loaded", path=self.model_path)
        except Exception as e:
            logger.error("model_load_error", error=str(e))
            self._initialize_model()
    
    def _initialize_model(self):
        """Initialize untrained model"""
        if ML_AVAILABLE:
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42
            )
            self.scaler = StandardScaler()
            logger.debug("model_initialized")
    
    def get_statistics(self) -> dict:
        """Get classification statistics"""
        return {
            "total_classifications": self.classifications_total,
            "vpn_detected": self.vpn_detected,
            "suspicious_detected": self.suspicious_detected,
            "normal_traffic": self.normal_traffic,
            "model_trained": self.model_trained,
            "ml_available": ML_AVAILABLE
        }
