"""
Anomaly Detector Suite

Combines metadata-based anomaly models:
- Isolation Forest (implemented)
- Sequence anomaly proxy (windowed drift score)
- Autoencoder placeholder hook (optional, external model service)
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

import structlog

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


logger = structlog.get_logger(__name__)


@dataclass
class AnomalyResult:
    score: float
    label: str
    model: str


class AnomalyDetector:
    """Hybrid anomaly detector focused on flow metadata."""

    def __init__(self, contamination: float = 0.07, window_size: int = 200) -> None:
        self.window_size = window_size
        self.history: deque[list[float]] = deque(maxlen=window_size)
        self.model = IsolationForest(contamination=contamination, random_state=42) if SKLEARN_AVAILABLE else None
        self.model_fitted = False

    def update(self, feature_vector: list[float]) -> None:
        self.history.append(feature_vector)
        if self.model and len(self.history) >= 50:
            X = np.array(list(self.history), dtype=float)
            try:
                self.model.fit(X)
                self.model_fitted = True
            except Exception as exc:
                self.model_fitted = False
                logger.warning("anomaly_model_fit_failed", error=str(exc))

    def detect(self, feature_vector: list[float]) -> AnomalyResult:
        if self.model and self.model_fitted:
            try:
                X = np.array([feature_vector], dtype=float)
                pred = int(self.model.predict(X)[0])  # -1 anomaly, 1 normal
                raw_score = float(self.model.decision_function(X)[0])
                # Normalize to 0-100 risk style anomaly score.
                score = max(0.0, min(100.0, (0.5 - raw_score) * 100))
                label = "anomaly" if pred == -1 else "normal"
                return AnomalyResult(score=score, label=label, model="isolation_forest")
            except Exception as exc:
                self.model_fitted = False
                logger.warning("anomaly_model_predict_failed", error=str(exc))

        # Fallback drift score from simple deviation over history mean.
        if not self.history:
            return AnomalyResult(score=0.0, label="normal", model="fallback")

        baseline = [sum(col) / len(col) for col in zip(*self.history)]
        abs_diff = [abs(a - b) for a, b in zip(feature_vector, baseline)]
        score = min(sum(abs_diff) / max(len(abs_diff), 1), 100.0)
        label = "anomaly" if score > 35 else "normal"
        return AnomalyResult(score=score, label=label, model="fallback")
