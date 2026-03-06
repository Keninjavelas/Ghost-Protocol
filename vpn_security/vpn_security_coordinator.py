"""
VPN Security Coordinator

Production-style orchestrator for VPN misuse and encrypted threat detection.
Pipeline:
1) Traffic ingestion
2) Feature extraction
3) Traffic classification
4) VPN detection & protocol ID
5) Misconfiguration / compromise / UBA / fingerprint / leak analysis
6) Zero-trust decisioning
7) Anomaly scoring
8) Alert/event publication
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional, Callable

import structlog

from .traffic_ingestion import TrafficIngestion, FlowMetadata
from .feature_extractor import FeatureExtractor
from .traffic_classifier import TrafficClassifier, TrafficCategory
from .vpn_detector import VPNDetector
from .protocol_identifier import ProtocolIdentifier
from .misconfiguration_detector import MisconfigurationDetector
from .compromise_detector import CompromiseDetector
from .user_behavior_analytics import UserBehaviorAnalytics
from .vpn_fingerprinter import VPNFingerprinter
from .leak_detector import LeakDetector
from .zero_trust_engine import ZeroTrustEngine
from .anomaly_detector import AnomalyDetector, AnomalyResult


logger = structlog.get_logger(__name__)


class VPNSecurityCoordinator:
    """End-to-end coordinator for VPN-focused security analysis."""

    def __init__(
        self,
        interface: str = "any",
        poll_interval_seconds: float = 5.0,
        dashboard_callback: Optional[Callable[[dict], Any]] = None,
    ) -> None:
        self.interface = interface
        self.poll_interval_seconds = poll_interval_seconds
        self.dashboard_callback = dashboard_callback

        self.ingestion = TrafficIngestion(interface=interface)
        self.feature_extractor = FeatureExtractor()
        self.classifier = TrafficClassifier()
        self.vpn_detector = VPNDetector()
        self.protocol_identifier = ProtocolIdentifier()
        self.misconfiguration_detector = MisconfigurationDetector()
        self.compromise_detector = CompromiseDetector()
        self.uba = UserBehaviorAnalytics()
        self.fingerprinter = VPNFingerprinter()
        self.leak_detector = LeakDetector()
        self.zero_trust = ZeroTrustEngine()
        self.anomaly_detector = AnomalyDetector()

        self.running = False
        self._task: asyncio.Task | None = None
        self._recent_findings: list[dict[str, Any]] = []
        self._max_findings = 500
        self._anomaly_disabled = False

    async def start(self) -> None:
        if self.running:
            return
        await self.ingestion.start()
        self.running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("vpn_security_started", interface=self.interface)

    async def stop(self) -> None:
        if not self.running:
            return
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self.ingestion.stop()
        logger.info("vpn_security_stopped")

    async def _loop(self) -> None:
        while self.running:
            try:
                await asyncio.sleep(self.poll_interval_seconds)
                flows = self.ingestion.get_recent_flows(limit=100)
                if not flows:
                    continue
                for flow in flows:
                    finding = self._analyze_flow(flow)
                    if finding:
                        self._append_finding(finding)
                        await self._publish_dashboard_event(finding)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("vpn_security_loop_error", error=str(exc))

    def _analyze_flow(self, flow: FlowMetadata) -> dict[str, Any] | None:
        features = self.feature_extractor.extract_features(flow)
        vector = self.feature_extractor.to_ml_vector(features)

        category, category_conf = self.classifier.classify(features)
        vpn_result = self.vpn_detector.detect(features, traffic_category=category)
        protocol = self.protocol_identifier.identify(features, vpn_confirmed=vpn_result.is_vpn)
        misconfig = self.misconfiguration_detector.analyze(features, protocol.protocol)

        user_id = f"{flow.src_ip}:{flow.src_port}"
        _, behavior_anomalies = self.uba.analyze_user(user_id, features)
        compromised, compromise_indicators = self.compromise_detector.analyze(features, user_id=user_id)
        fingerprint = self.fingerprinter.analyze(features)
        leak_findings = self.leak_detector.analyze(features, vpn_detected=vpn_result.is_vpn)

        if self._anomaly_disabled:
            anomaly = AnomalyResult(score=0.0, label="normal", model="fallback")
        else:
            try:
                self.anomaly_detector.update(vector)
                anomaly = self.anomaly_detector.detect(vector)
            except Exception as exc:
                self._anomaly_disabled = True
                logger.warning("vpn_anomaly_detection_disabled", error=str(exc))
                anomaly = AnomalyResult(score=0.0, label="normal", model="fallback")

        zt = self.zero_trust.evaluate_access(
            user_id=user_id,
            role="default",
            device_validated=True,
            risk_score=min(misconfig.risk_score + (30 if compromised else 0), 100.0),
            anomaly_score=min(anomaly.score, 100.0),
            is_vpn_access=vpn_result.is_vpn,
            provided_mfa_methods=["password"],
        )

        should_emit = (
            vpn_result.is_vpn
            or compromised
            or misconfig.has_issues
            or anomaly.label == "anomaly"
            or len(leak_findings) > 0
            or category in {TrafficCategory.SUSPICIOUS, TrafficCategory.TUNNEL}
        )
        if not should_emit:
            return None

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "flow_id": flow.flow_id,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "traffic_category": category.value,
            "traffic_category_confidence": round(category_conf, 3),
            "vpn_detected": vpn_result.is_vpn,
            "vpn_confidence": round(vpn_result.confidence, 3),
            "protocol": protocol.protocol.value,
            "protocol_confidence": round(protocol.confidence, 3),
            "fingerprint": fingerprint.family if fingerprint else None,
            "fingerprint_confidence": round(fingerprint.confidence, 3) if fingerprint else 0.0,
            "misconfiguration_risk": round(misconfig.risk_score, 2),
            "misconfiguration_issues": [
                {
                    "type": i.issue_type,
                    "severity": i.severity.value,
                    "description": i.description,
                    "recommendation": i.recommendation,
                }
                for i in misconfig.issues
            ],
            "compromised": compromised,
            "compromise_indicators": [
                {
                    "type": i.indicator_type,
                    "severity": i.severity,
                    "description": i.description,
                }
                for i in compromise_indicators
            ],
            "behavior_anomalies": [
                {
                    "type": a.anomaly_type,
                    "severity": a.severity,
                    "description": a.description,
                    "deviation": round(a.deviation_score, 3),
                }
                for a in behavior_anomalies
            ],
            "leak_findings": [
                {
                    "type": l.leak_type,
                    "severity": l.severity,
                    "confidence": round(l.confidence, 3),
                    "details": l.details,
                }
                for l in leak_findings
            ],
            "anomaly_score": round(anomaly.score, 3),
            "anomaly_label": anomaly.label,
            "zero_trust": {
                "allowed": zt.allowed,
                "trust_score": round(zt.trust_score, 3),
                "action": zt.action,
                "reasons": zt.reasons,
                "segments": self.zero_trust.segment_policy("default"),
            },
        }

    def _append_finding(self, finding: dict[str, Any]) -> None:
        self._recent_findings.append(finding)
        if len(self._recent_findings) > self._max_findings:
            self._recent_findings = self._recent_findings[-self._max_findings :]

    async def _publish_dashboard_event(self, finding: dict[str, Any]) -> None:
        if not self.dashboard_callback:
            return
        event = {
            "type": "vpn_security_alert",
            "session_id": finding.get("flow_id", "vpn-security"),
            "timestamp": finding["timestamp"],
            "data": finding,
        }
        try:
            await self.dashboard_callback(event)
        except Exception as exc:
            logger.error("vpn_security_dashboard_callback_failed", error=str(exc))

    def get_status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "interface": self.interface,
            "poll_interval_seconds": self.poll_interval_seconds,
            "ingestion": self.ingestion.get_statistics(),
            "classifier": self.classifier.get_statistics(),
            "vpn_detector": self.vpn_detector.get_statistics(),
            "protocol_identifier": self.protocol_identifier.get_statistics(),
            "misconfiguration_detector": self.misconfiguration_detector.get_statistics(),
            "compromise_detector": self.compromise_detector.get_statistics(),
            "uba": self.uba.get_statistics(),
            "fingerprinter": self.fingerprinter.get_statistics(),
            "leak_detector": self.leak_detector.get_statistics(),
            "zero_trust": self.zero_trust.get_statistics(),
            "findings_count": len(self._recent_findings),
        }

    def get_recent_findings(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._recent_findings[-limit:]

    def query_findings(
        self,
        vpn_only: bool = False,
        compromised_only: bool = False,
        leak_only: bool = False,
        min_anomaly_score: float | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        data = self._recent_findings
        if vpn_only:
            data = [x for x in data if x.get("vpn_detected")]
        if compromised_only:
            data = [x for x in data if x.get("compromised")]
        if leak_only:
            data = [x for x in data if x.get("leak_findings")]
        if min_anomaly_score is not None:
            data = [x for x in data if float(x.get("anomaly_score", 0)) >= min_anomaly_score]
        return data[-limit:]
