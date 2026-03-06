"""
Traffic Leak Detector

Detects DNS leaks, IPv6 leaks, and routing/tunnel bypass anomalies using
flow metadata only (no payload inspection).
"""

from __future__ import annotations

from dataclasses import dataclass
import structlog

from .feature_extractor import ExtractedFeatures


logger = structlog.get_logger(__name__)


@dataclass
class LeakFinding:
    leak_type: str
    severity: str
    confidence: float
    details: str


class LeakDetector:
    """Leak detection for VPN-protected sessions."""

    def __init__(self) -> None:
        self.findings_total = 0

    def analyze(self, features: ExtractedFeatures, vpn_detected: bool) -> list[LeakFinding]:
        findings: list[LeakFinding] = []

        if not vpn_detected:
            return findings

        # DNS leak heuristic: DNS traffic pattern while VPN tunnel active.
        if features.dst_port == 53 and not features.is_encrypted:
            findings.append(
                LeakFinding(
                    leak_type="dns_leak",
                    severity="high",
                    confidence=0.8,
                    details="Observed plaintext DNS flow during VPN activity.",
                )
            )

        # Tunnel bypass heuristic: direct high-volume non-encrypted traffic.
        if not features.is_encrypted and features.total_bytes > 2_000_000 and features.unusual_port_usage:
            findings.append(
                LeakFinding(
                    leak_type="tunnel_bypass",
                    severity="critical",
                    confidence=0.77,
                    details="High-volume direct flow indicates potential VPN tunnel bypass.",
                )
            )

        # IPv6 leak heuristic: detect IPv6 endpoint in flow id while VPN traffic profile active.
        # Flow IDs are generated from endpoint strings, so ':' abundance is a weak signal for IPv6.
        if features.flow_id.count(":") >= 6 and not features.is_encrypted:
            findings.append(
                LeakFinding(
                    leak_type="ipv6_leak",
                    severity="medium",
                    confidence=0.62,
                    details="Potential IPv6 direct route outside VPN tunnel.",
                )
            )

        self.findings_total += len(findings)
        return findings

    def get_statistics(self) -> dict:
        return {"findings_total": self.findings_total}
