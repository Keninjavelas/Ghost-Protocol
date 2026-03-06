"""
Misconfiguration Detector - VPN Security Configuration Analysis

Detects VPN misconfigurations and security weaknesses including:
- Outdated encryption standards
- Deprecated cipher suites
- Missing certificate validation
- Insecure authentication methods
- Legacy protocols
"""

from enum import Enum
from typing import Optional
import structlog
from .feature_extractor import ExtractedFeatures
from .protocol_identifier import VPNProtocol


logger = structlog.get_logger(__name__)


class MisconfigurationSeverity(Enum):
    """Severity levels for misconfigurations"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MisconfigurationIssue:
    """Detected misconfiguration issue"""
    def __init__(
        self,
        issue_type: str,
        severity: MisconfigurationSeverity,
        description: str,
        recommendation: str,
        cve_references: list[str] = None
    ):
        self.issue_type = issue_type
        self.severity = severity
        self.description = description
        self.recommendation = recommendation
        self.cve_references = cve_references or []


class MisconfigurationResult:
    """Result of misconfiguration analysis"""
    def __init__(
        self,
        has_issues: bool,
        issues: list[MisconfigurationIssue],
        risk_score: float
    ):
        self.has_issues = has_issues
        self.issues = issues
        self.risk_score = risk_score


class MisconfigurationDetector:
    """
    VPN misconfiguration detection engine.
    
    Analyzes VPN configurations for security weaknesses based on:
    - NIST cryptographic standards
    - OWASP security guidelines
    - CVE databases
    - Industry best practices
    """
    
    def __init__(self):
        """Initialize misconfiguration detector"""
        # Weak/deprecated TLS versions
        self.weak_tls_versions = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "0x0300", "0x0301", "0x0302"}
        
        # Weak/deprecated cipher suites
        self.weak_ciphers = {
            "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT",
            "ANON", "ADH", "AECDH"
        }
        
        # Insecure VPN protocols
        self.insecure_protocols = {VPNProtocol.PPTP}
        
        # Deprecated protocols
        self.deprecated_protocols = {VPNProtocol.L2TP}
        
        # Statistics
        self.scans_total = 0
        self.critical_issues_found = 0
        self.high_issues_found = 0
        
        logger.info("misconfiguration_detector_initialized")
    
    def analyze(
        self,
        features: ExtractedFeatures,
        protocol: Optional[VPNProtocol] = None
    ) -> MisconfigurationResult:
        """
        Analyze VPN configuration for security issues.
        
        Args:
            features: Extracted traffic features
            protocol: Identified VPN protocol
            
        Returns:
            Misconfiguration analysis result
        """
        self.scans_total += 1
        
        issues = []
        
        # Check TLS version
        if features.tls_version:
            tls_issues = self._check_tls_version(features.tls_version)
            issues.extend(tls_issues)
        
        # Check cipher suite
        if features.cipher_suite:
            cipher_issues = self._check_cipher_suite(features.cipher_suite)
            issues.extend(cipher_issues)
        
        # Check protocol security
        if protocol:
            protocol_issues = self._check_protocol_security(protocol)
            issues.extend(protocol_issues)
        
        # Check certificate validation
        if features.is_encrypted and not features.has_sni:
            cert_issues = self._check_certificate_validation(features)
            issues.extend(cert_issues)
        
        # Check authentication weaknesses
        auth_issues = self._check_authentication(features, protocol)
        issues.extend(auth_issues)
        
        # Check port configuration
        port_issues = self._check_port_configuration(features, protocol)
        issues.extend(port_issues)
        
        # Check for tunnel leaks
        leak_issues = self._check_tunnel_configuration(features)
        issues.extend(leak_issues)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(issues)
        
        # Update statistics
        for issue in issues:
            if issue.severity == MisconfigurationSeverity.CRITICAL:
                self.critical_issues_found += 1
            elif issue.severity == MisconfigurationSeverity.HIGH:
                self.high_issues_found += 1
        
        result = MisconfigurationResult(
            has_issues=len(issues) > 0,
            issues=issues,
            risk_score=risk_score
        )
        
        logger.debug(
            "misconfiguration_analysis_complete",
            flow_id=features.flow_id,
            issues_found=len(issues),
            risk_score=risk_score
        )
        
        return result
    
    def _check_tls_version(self, tls_version: str) -> list[MisconfigurationIssue]:
        """Check for weak/deprecated TLS versions"""
        issues = []
        
        for weak_version in self.weak_tls_versions:
            if weak_version in tls_version:
                if weak_version in ["SSL 2.0", "SSL 3.0"]:
                    severity = MisconfigurationSeverity.CRITICAL
                    cve_refs = ["CVE-2014-3566", "CVE-2015-0204"]
                else:
                    severity = MisconfigurationSeverity.HIGH
                    cve_refs = ["CVE-2011-3389"]
                
                issues.append(MisconfigurationIssue(
                    issue_type="weak_tls_version",
                    severity=severity,
                    description=f"Weak/deprecated TLS version detected: {tls_version}",
                    recommendation="Upgrade to TLS 1.2 or TLS 1.3. Disable older versions.",
                    cve_references=cve_refs
                ))
        
        return issues
    
    def _check_cipher_suite(self, cipher_suite: str) -> list[MisconfigurationIssue]:
        """Check for weak/deprecated ciphers"""
        issues = []
        
        for weak_cipher in self.weak_ciphers:
            if weak_cipher in cipher_suite:
                if weak_cipher in ["NULL", "EXPORT", "ANON"]:
                    severity = MisconfigurationSeverity.CRITICAL
                elif weak_cipher in ["RC4", "DES", "MD5"]:
                    severity = MisconfigurationSeverity.HIGH
                else:
                    severity = MisconfigurationSeverity.MEDIUM
                
                issues.append(MisconfigurationIssue(
                    issue_type="weak_cipher",
                    severity=severity,
                    description=f"Weak cipher suite detected: {weak_cipher} in {cipher_suite}",
                    recommendation=(
                        "Use strong cipher suites: AES-256-GCM, CHACHA20-POLY1305, "
                        "AES-128-GCM. Disable weak ciphers."
                    ),
                    cve_references=["CVE-2013-2566", "CVE-2015-2808"]
                ))
        
        return issues
    
    def _check_protocol_security(self, protocol: VPNProtocol) -> list[MisconfigurationIssue]:
        """Check protocol security level"""
        issues = []
        
        if protocol in self.insecure_protocols:
            issues.append(MisconfigurationIssue(
                issue_type="insecure_protocol",
                severity=MisconfigurationSeverity.CRITICAL,
                description=f"Insecure VPN protocol detected: {protocol.value}",
                recommendation=(
                    f"{protocol.value} has known security vulnerabilities. "
                    "Migrate to OpenVPN, WireGuard, or IPSec."
                ),
                cve_references=["CVE-2012-0147", "CVE-2012-0152"]
            ))
        
        elif protocol in self.deprecated_protocols:
            issues.append(MisconfigurationIssue(
                issue_type="deprecated_protocol",
                severity=MisconfigurationSeverity.MEDIUM,
                description=f"Deprecated VPN protocol detected: {protocol.value}",
                recommendation=(
                    f"{protocol.value} is deprecated. Consider migrating to "
                    "modern alternatives like WireGuard or OpenVPN."
                )
            ))
        
        return issues
    
    def _check_certificate_validation(self, features: ExtractedFeatures) -> list[MisconfigurationIssue]:
        """Check certificate validation configuration"""
        issues = []
        
        # Missing SNI could indicate certificate validation bypass
        if not features.has_sni and features.is_encrypted:
            issues.append(MisconfigurationIssue(
                issue_type="missing_sni",
                severity=MisconfigurationSeverity.MEDIUM,
                description="TLS connection without SNI detected",
                recommendation=(
                    "Ensure certificate validation is properly configured. "
                    "Missing SNI may indicate certificate pinning bypass."
                )
            ))
        
        return issues
    
    def _check_authentication(
        self,
        features: ExtractedFeatures,
        protocol: Optional[VPNProtocol]
    ) -> list[MisconfigurationIssue]:
        """Check authentication configuration"""
        issues = []
        
        # PPTP uses weak MS-CHAPv2 authentication
        if protocol == VPNProtocol.PPTP:
            issues.append(MisconfigurationIssue(
                issue_type="weak_authentication",
                severity=MisconfigurationSeverity.CRITICAL,
                description="PPTP uses weak MS-CHAPv2 authentication",
                recommendation="Use certificate-based authentication with modern VPN protocols",
                cve_references=["CVE-2012-0147"]
            ))
        
        return issues
    
    def _check_port_configuration(
        self,
        features: ExtractedFeatures,
        protocol: Optional[VPNProtocol]
    ) -> list[MisconfigurationIssue]:
        """Check port configuration best practices"""
        issues = []
        
        # OpenVPN on default port is easily blocked
        if protocol == VPNProtocol.OPENVPN and features.dst_port == 1194:
            issues.append(MisconfigurationIssue(
                issue_type="default_port",
                severity=MisconfigurationSeverity.LOW,
                description="OpenVPN running on default port 1194",
                recommendation=(
                    "Consider using port 443 for OpenVPN to avoid firewall blocking "
                    "and improve traffic obfuscation."
                )
            ))
        
        return issues
    
    def _check_tunnel_configuration(self, features: ExtractedFeatures) -> list[MisconfigurationIssue]:
        """Check tunnel configuration for leaks"""
        issues = []
        
        # High burstiness might indicate DNS leaks
        if features.has_burst_traffic and features.burstiness_score > 0.8:
            issues.append(MisconfigurationIssue(
                issue_type="potential_leak",
                severity=MisconfigurationSeverity.MEDIUM,
                description="Unusual traffic pattern may indicate tunnel leaks",
                recommendation=(
                    "Verify DNS leak protection is enabled. "
                    "Ensure all traffic routed through VPN tunnel."
                )
            ))
        
        return issues
    
    def _calculate_risk_score(self, issues: list[MisconfigurationIssue]) -> float:
        """Calculate overall risk score (0-100)"""
        if not issues:
            return 0.0
        
        severity_weights = {
            MisconfigurationSeverity.CRITICAL: 25,
            MisconfigurationSeverity.HIGH: 15,
            MisconfigurationSeverity.MEDIUM: 10,
            MisconfigurationSeverity.LOW: 5,
            MisconfigurationSeverity.INFO: 1
        }
        
        total_score = sum(severity_weights[issue.severity] for issue in issues)
        
        # Cap at 100
        return min(total_score, 100.0)
    
    def get_statistics(self) -> dict:
        """Get detection statistics"""
        return {
            "scans_total": self.scans_total,
            "critical_issues_found": self.critical_issues_found,
            "high_issues_found": self.high_issues_found
        }
