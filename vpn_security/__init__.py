"""
VPN Security Module - Advanced Threat Detection Platform

This module provides comprehensive VPN security analysis including:
- VPN traffic detection and protocol identification
- Compromise detection and behavioral analytics
- Traffic fingerprinting and leak detection
- Zero-Trust access control and MFA enforcement
- AI-powered anomaly detection

Designed for production-grade cybersecurity platforms.
"""

from .vpn_security_coordinator import VPNSecurityCoordinator
from .traffic_classifier import TrafficClassifier
from .vpn_detector import VPNDetector
from .protocol_identifier import ProtocolIdentifier
from .compromise_detector import CompromiseDetector
from .user_behavior_analytics import UserBehaviorAnalytics
from .vpn_fingerprinter import VPNFingerprinter
from .leak_detector import LeakDetector
from .mfa_manager import MFAManager
from .zero_trust_engine import ZeroTrustEngine
from .anomaly_detector import AnomalyDetector

__all__ = [
    "VPNSecurityCoordinator",
    "TrafficClassifier",
    "VPNDetector",
    "ProtocolIdentifier",
    "CompromiseDetector",
    "UserBehaviorAnalytics",
    "VPNFingerprinter",
    "LeakDetector",
    "MFAManager",
    "ZeroTrustEngine",
    "AnomalyDetector",
]

__version__ = "1.0.0"
