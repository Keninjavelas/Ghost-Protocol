"""
VPN Fingerprinting Engine

Detects identifiable VPN traffic fingerprints based on encrypted metadata,
packet size distributions, timing signatures, and protocol response patterns.
"""

from __future__ import annotations

from dataclasses import dataclass
import structlog

from .feature_extractor import ExtractedFeatures


logger = structlog.get_logger(__name__)


@dataclass
class FingerprintMatch:
    """Fingerprint match result."""

    family: str
    confidence: float
    indicators: list[str]


class VPNFingerprinter:
    """Fingerprint-based VPN family detector."""

    def __init__(self) -> None:
        self._matches = 0
        self._attempts = 0

    def analyze(self, features: ExtractedFeatures) -> FingerprintMatch | None:
        self._attempts += 1
        indicators: list[str] = []

        # WireGuard-like: UDP + very stable packet size/timing.
        if (
            features.protocol == "UDP"
            and features.packet_size_std_dev < 80
            and features.inter_arrival_std_dev < 0.03
            and features.avg_packet_size <= 220
        ):
            indicators.extend(["udp", "stable_size", "stable_timing", "small_packets"])
            self._matches += 1
            return FingerprintMatch("wireguard_like", 0.82, indicators)

        # OpenVPN/TLS-like: long-lived encrypted flow with variable payload.
        if (
            features.is_encrypted
            and features.session_duration > 120
            and features.packet_size_entropy > 4.5
            and features.dst_port in {1194, 443}
        ):
            indicators.extend(["encrypted", "long_lived", "entropy_high", "vpn_port"])
            self._matches += 1
            return FingerprintMatch("openvpn_tls_like", 0.76, indicators)

        # IPSec-like: UDP 500/4500 with larger packet average.
        if features.protocol == "UDP" and features.dst_port in {500, 4500} and features.avg_packet_size > 600:
            indicators.extend(["udp", "ipsec_ports", "large_packets"])
            self._matches += 1
            return FingerprintMatch("ipsec_like", 0.79, indicators)

        # Unknown tunnel-like behavior.
        if features.potential_tunnel and features.unusual_port_usage and features.is_encrypted:
            indicators.extend(["potential_tunnel", "unusual_port", "encrypted"])
            self._matches += 1
            return FingerprintMatch("custom_tunnel_like", 0.63, indicators)

        return None

    def get_statistics(self) -> dict:
        return {
            "attempts": self._attempts,
            "matches": self._matches,
            "match_rate": (self._matches / self._attempts) if self._attempts else 0.0,
        }
