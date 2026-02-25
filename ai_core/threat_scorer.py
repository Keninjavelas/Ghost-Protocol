"""
ai_core/threat_scorer.py
Aggregates intent inference + MITRE mapping + behavioral signals
into a structured threat score. Pure computation – no LLM call needed.

Output schema:
{
  "risk_score": float,          // 0.0 – 100.0
  "threat_level": str,          // LOW | MEDIUM | HIGH | CRITICAL
  "attacker_category": str,
  "likelihood_APT": float       // 0.0 – 1.0
}
"""
from __future__ import annotations

from typing import Any

import structlog

log = structlog.get_logger(__name__)

# Weights for each signal
_SOPHISTICATION_WEIGHTS = {
    "low": 0.1,
    "medium": 0.3,
    "high": 0.6,
    "nation-state": 1.0,
}

_OBJECTIVE_WEIGHTS = {
    "reconnaissance": 0.2,
    "credential-harvesting": 0.5,
    "data-exfiltration": 0.7,
    "persistence": 0.8,
    "lateral-movement": 0.75,
    "ransomware": 0.95,
    "unknown": 0.1,
}

_ATTACKER_APT_LIKELIHOOD = {
    "script-kiddie": 0.05,
    "opportunist": 0.1,
    "professional": 0.4,
    "apt": 0.9,
    "insider": 0.6,
    "unknown": 0.05,
}


class ThreatScorer:
    """
    Deterministic threat scorer.
    No LLM – uses weighted heuristics over structured AI outputs.
    """

    def score(
        self,
        intent: dict[str, Any],
        mitre_result: dict[str, Any],
        command_count: int = 0,
    ) -> dict[str, Any]:
        """Compute and return a threat score dict."""

        attacker_type = intent.get("attacker_type", "unknown").lower()
        objective = intent.get("primary_objective", "unknown").lower()
        sophistication = intent.get("sophistication_level", "low").lower()
        confidence = float(intent.get("confidence", 0.0))

        techniques = mitre_result.get("techniques", [])
        avg_mitre_confidence = (
            sum(float(t.get("confidence", 0)) for t in techniques) / len(techniques)
            if techniques
            else 0.0
        )

        # Component weights
        soph_w = _SOPHISTICATION_WEIGHTS.get(sophistication, 0.1)
        obj_w = _OBJECTIVE_WEIGHTS.get(objective, 0.1)
        mitre_w = avg_mitre_confidence
        cmd_w = min(command_count / 50.0, 1.0)  # caps at 50 commands

        # Weighted risk score (0–100)
        raw = (
            soph_w * 30
            + obj_w * 35
            + mitre_w * 25
            + cmd_w * 10
        ) * confidence
        risk_score = round(min(raw, 100.0), 2)

        # Threat level buckets
        if risk_score < 20:
            threat_level = "LOW"
        elif risk_score < 45:
            threat_level = "MEDIUM"
        elif risk_score < 70:
            threat_level = "HIGH"
        else:
            threat_level = "CRITICAL"

        likelihood_apt = round(
            _ATTACKER_APT_LIKELIHOOD.get(attacker_type, 0.05) * confidence, 3
        )

        result = {
            "risk_score": risk_score,
            "threat_level": threat_level,
            "attacker_category": attacker_type,
            "likelihood_APT": likelihood_apt,
        }

        log.info(
            "threat_scored",
            risk_score=risk_score,
            threat_level=threat_level,
            likelihood_apt=likelihood_apt,
        )
        return result
