"""
Zero Trust Engine

Continuously evaluates access trust using behavioral, device, and policy signals.
"""

from __future__ import annotations

from dataclasses import dataclass
import time

from .mfa_manager import MFAManager


@dataclass
class AccessDecision:
    allowed: bool
    trust_score: float
    action: str
    reasons: list[str]


class ZeroTrustEngine:
    """Zero-Trust policy evaluator for each observed access/session event."""

    def __init__(self, min_trust_score: float = 55.0) -> None:
        self.min_trust_score = min_trust_score
        self.mfa_manager = MFAManager()
        self.decisions_total = 0

    def evaluate_access(
        self,
        user_id: str,
        role: str,
        device_validated: bool,
        risk_score: float,
        anomaly_score: float,
        is_vpn_access: bool,
        provided_mfa_methods: list[str] | None = None,
    ) -> AccessDecision:
        self.decisions_total += 1

        reasons: list[str] = []
        trust_score = 100.0

        if not device_validated:
            trust_score -= 30
            reasons.append("device_not_validated")

        trust_score -= min(max(risk_score, 0.0), 100.0) * 0.35
        trust_score -= min(max(anomaly_score, 0.0), 100.0) * 0.25

        mfa_result = self.mfa_manager.evaluate(role, provided_mfa_methods, is_vpn_access)
        if mfa_result.required and not mfa_result.passed:
            trust_score -= 35
            reasons.append("mfa_failed")

        trust_score = max(0.0, min(100.0, trust_score))

        if trust_score < self.min_trust_score:
            action = "deny_or_step_up_auth"
            allowed = False
        elif trust_score < (self.min_trust_score + 15):
            action = "allow_limited_segment_access"
            allowed = True
        else:
            action = "allow"
            allowed = True

        return AccessDecision(allowed=allowed, trust_score=trust_score, action=action, reasons=reasons)

    def segment_policy(self, role: str) -> list[str]:
        """Return least-privilege segment allow-list for role."""
        role_map = {
            "admin": ["admin_interface", "monitoring", "audit"],
            "security_admin": ["monitoring", "audit", "ai_processing"],
            "analyst": ["monitoring", "ai_processing"],
            "db_readonly": ["database_readonly"],
            "default": ["monitoring"],
        }
        return role_map.get(role, role_map["default"])

    def get_statistics(self) -> dict:
        return {"decisions_total": self.decisions_total, "min_trust_score": self.min_trust_score, "updated_at": time.time()}
