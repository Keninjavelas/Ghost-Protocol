"""
Protocol Identifier - VPN Protocol Classification Module

Identifies specific VPN protocols: OpenVPN, WireGuard, IPSec, SSTP, L2TP, custom tunnels.
Uses port analysis, TLS fingerprinting, and packet behavior patterns.
"""

from enum import Enum
from typing import Optional
import structlog
from .feature_extractor import ExtractedFeatures


logger = structlog.get_logger(__name__)


class VPNProtocol(Enum):
    """Supported VPN protocols"""
    OPENVPN = "OpenVPN"
    WIREGUARD = "WireGuard"
    IPSEC = "IPSec"
    SSTP = "SSTP"
    L2TP = "L2TP"
    PPTP = "PPTP"
    SOFTETHER = "SoftEther"
    CISCO_ANYCONNECT = "Cisco AnyConnect"
    CUSTOM_TUNNEL = "Custom Tunnel"
    UNKNOWN = "Unknown"


class ProtocolIdentificationResult:
    """Result of protocol identification"""
    def __init__(
        self,
        protocol: VPNProtocol,
        confidence: float,
        indicators: list[str],
        characteristics: dict
    ):
        self.protocol = protocol
        self.confidence = confidence
        self.indicators = indicators
        self.characteristics = characteristics


class ProtocolIdentifier:
    """
    VPN protocol identification engine.
    
    Identifies VPN protocols using:
    - Port-based signatures
    - TLS handshake fingerprints
    - Packet size patterns
    - Protocol-specific behaviors
    - Server response characteristics
    """
    
    def __init__(self):
        """Initialize protocol identifier"""
        # Port-to-protocol mappings
        self.port_signatures = {
            1194: VPNProtocol.OPENVPN,
            51820: VPNProtocol.WIREGUARD,
            500: VPNProtocol.IPSEC,
            4500: VPNProtocol.IPSEC,
            1701: VPNProtocol.L2TP,
            1723: VPNProtocol.PPTP,
            10000: VPNProtocol.SOFTETHER,
            1302: VPNProtocol.CISCO_ANYCONNECT,
            443: None  # Shared - needs further analysis
        }
        
        # Protocol packet size signatures (typical ranges)
        self.packet_size_signatures = {
            VPNProtocol.WIREGUARD: (140, 160),  # Small, consistent packets
            VPNProtocol.OPENVPN: (100, 1400),    # Variable sizes
            VPNProtocol.IPSEC: (80, 1500),       # Wide range
            VPNProtocol.L2TP: (60, 1400),        # L2TP overhead
        }
        
        # TLS cipher preferences by protocol
        self.tls_cipher_hints = {
            "AES_256_GCM": [VPNProtocol.OPENVPN, VPNProtocol.SSTP],
            "CHACHA20_POLY1305": [VPNProtocol.WIREGUARD, VPNProtocol.OPENVPN],
            "AES_128_GCM": [VPNProtocol.IPSEC, VPNProtocol.OPENVPN],
        }
        
        # Statistics
        self.identifications_total = 0
        self.protocol_counts = {protocol: 0 for protocol in VPNProtocol}
        
        logger.info("protocol_identifier_initialized")
    
    def identify(
        self,
        features: ExtractedFeatures,
        vpn_confirmed: bool = False
    ) -> ProtocolIdentificationResult:
        """
        Identify VPN protocol from traffic features.
        
        Args:
            features: Extracted behavioral features
            vpn_confirmed: Whether VPN already confirmed by detector
            
        Returns:
            Protocol identification result with confidence
        """
        self.identifications_total += 1
        
        protocol_scores = {}
        indicators = []
        characteristics = {}
        
        # Method 1: Port-based identification
        port_protocol = self._identify_by_port(features)
        if port_protocol:
            protocol_scores[port_protocol] = protocol_scores.get(port_protocol, 0) + 0.7
            indicators.append(f"port_{features.dst_port}")
        
        # Method 2: Packet size analysis
        size_protocols = self._identify_by_packet_size(features)
        for protocol, score in size_protocols.items():
            protocol_scores[protocol] = protocol_scores.get(protocol, 0) + score
            indicators.append(f"packet_size_match_{protocol.value}")
        
        # Method 3: TLS fingerprinting (if encrypted)
        if features.is_encrypted and features.cipher_suite:
            tls_protocols = self._identify_by_tls(features)
            for protocol, score in tls_protocols.items():
                protocol_scores[protocol] = protocol_scores.get(protocol, 0) + score
                indicators.append(f"tls_cipher_{protocol.value}")
        
        # Method 4: Behavioral patterns
        behavior_protocols = self._identify_by_behavior(features)
        for protocol, score in behavior_protocols.items():
            protocol_scores[protocol] = protocol_scores.get(protocol, 0) + score
            indicators.append(f"behavior_{protocol.value}")
        
        # Method 5: Statistical characteristics
        stats_protocols = self._identify_by_statistics(features)
        for protocol, score in stats_protocols.items():
            protocol_scores[protocol] = protocol_scores.get(protocol, 0) + score
            indicators.append(f"stats_{protocol.value}")
        
        # Determine best match
        if protocol_scores:
            best_protocol = max(protocol_scores, key=protocol_scores.get)
            confidence = min(protocol_scores[best_protocol], 0.95)
            
            # Normalize confidence
            if confidence > 1.0:
                confidence = confidence / (1.0 + confidence)
        else:
            # Unable to identify specific protocol
            if vpn_confirmed:
                best_protocol = VPNProtocol.CUSTOM_TUNNEL
                confidence = 0.5
                indicators.append("unknown_vpn_protocol")
            else:
                best_protocol = VPNProtocol.UNKNOWN
                confidence = 0.0
        
        # Extract characteristics
        characteristics = {
            "dst_port": features.dst_port,
            "is_encrypted": features.is_encrypted,
            "avg_packet_size": features.avg_packet_size,
            "session_duration": features.session_duration,
            "tls_version": features.tls_version,
            "cipher_suite": features.cipher_suite
        }
        
        self.protocol_counts[best_protocol] += 1
        
        result = ProtocolIdentificationResult(
            protocol=best_protocol,
            confidence=confidence,
            indicators=indicators,
            characteristics=characteristics
        )
        
        logger.debug(
            "protocol_identified",
            flow_id=features.flow_id,
            protocol=best_protocol.value,
            confidence=confidence
        )
        
        return result
    
    def _identify_by_port(self, features: ExtractedFeatures) -> Optional[VPNProtocol]:
        """Identify protocol by destination port"""
        dst_port = features.dst_port
        
        if dst_port in self.port_signatures:
            protocol = self.port_signatures[dst_port]
            
            # Port 443 requires further analysis
            if protocol is None and dst_port == 443:
                # Check if likely OpenVPN or SSTP on 443
                if features.is_long_lived and features.is_high_volume:
                    return VPNProtocol.OPENVPN
                return None
            
            return protocol
        
        return None
    
    def _identify_by_packet_size(self, features: ExtractedFeatures) -> dict:
        """Identify protocol by packet size patterns"""
        scores = {}
        avg_size = features.avg_packet_size
        
        # WireGuard: Small, consistent packets (~148 bytes typical)
        if 130 <= avg_size <= 170 and features.packet_size_std_dev < 50:
            scores[VPNProtocol.WIREGUARD] = 0.6
        
        # OpenVPN: Variable packet sizes
        if 200 <= avg_size <= 1400 and features.packet_size_std_dev > 200:
            scores[VPNProtocol.OPENVPN] = 0.4
        
        # IPSec: Often larger packets
        if avg_size > 1000 and features.protocol == "UDP":
            scores[VPNProtocol.IPSEC] = 0.3
        
        # L2TP: Medium-sized packets
        if 400 <= avg_size <= 800:
            scores[VPNProtocol.L2TP] = 0.3
        
        return scores
    
    def _identify_by_tls(self, features: ExtractedFeatures) -> dict:
        """Identify protocol by TLS characteristics"""
        scores = {}
        
        if not features.cipher_suite:
            return scores
        
        cipher = features.cipher_suite
        
        # Check cipher suite preferences
        for cipher_pattern, protocols in self.tls_cipher_hints.items():
            if cipher_pattern in cipher:
                for protocol in protocols:
                    scores[protocol] = scores.get(protocol, 0) + 0.3
        
        # SSTP always uses TLS over TCP 443
        if features.dst_port == 443 and features.protocol == "TCP":
            if "TLS" in str(features.tls_version):
                scores[VPNProtocol.SSTP] = scores.get(VPNProtocol.SSTP, 0) + 0.4
        
        # OpenVPN commonly uses TLS 1.2/1.3
        if features.tls_version in ["TLS 1.2", "TLS 1.3"]:
            scores[VPNProtocol.OPENVPN] = scores.get(VPNProtocol.OPENVPN, 0) + 0.2
        
        return scores
    
    def _identify_by_behavior(self, features: ExtractedFeatures) -> dict:
        """Identify protocol by behavioral characteristics"""
        scores = {}
        
        # WireGuard: UDP, consistent timing, minimal metadata
        if features.protocol == "UDP":
            if features.inter_arrival_std_dev < 0.02 and features.packet_size_std_dev < 100:
                scores[VPNProtocol.WIREGUARD] = 0.5
            else:
                # Generic UDP VPN (OpenVPN-UDP or IPSec)
                scores[VPNProtocol.OPENVPN] = 0.3
                scores[VPNProtocol.IPSEC] = 0.3
        
        # OpenVPN: Can use TCP or UDP, long-lived
        if features.is_long_lived and features.is_high_volume:
            scores[VPNProtocol.OPENVPN] = scores.get(VPNProtocol.OPENVPN, 0) + 0.3
        
        # IPSec: Often uses UDP 500/4500
        if features.protocol == "UDP" and features.dst_port in [500, 4500]:
            scores[VPNProtocol.IPSEC] = 0.7
        
        # SSTP: TCP 443, long-lived, encrypted
        if (features.protocol == "TCP" and features.dst_port == 443 and
                features.is_encrypted and features.is_long_lived):
            scores[VPNProtocol.SSTP] = 0.4
        
        # PPTP: TCP 1723, characteristic GRE protocol
        if features.dst_port == 1723:
            scores[VPNProtocol.PPTP] = 0.7
        
        return scores
    
    def _identify_by_statistics(self, features: ExtractedFeatures) -> dict:
        """Identify protocol by statistical patterns"""
        scores = {}
        
        # WireGuard: Very consistent packet sizes and timing
        if features.packet_size_entropy < 3.0 and features.inter_arrival_std_dev < 0.01:
            scores[VPNProtocol.WIREGUARD] = 0.4
        
        # OpenVPN: More variable patterns
        if features.packet_size_entropy > 4.0 and features.burstiness_score > 0.3:
            scores[VPNProtocol.OPENVPN] = 0.3
        
        # IPSec: Can be bursty, larger packets
        if features.has_burst_traffic and features.avg_packet_size > 800:
            scores[VPNProtocol.IPSEC] = 0.3
        
        # Custom tunnel: Unusual characteristics
        if features.suspicious_packet_pattern and features.unusual_port_usage:
            scores[VPNProtocol.CUSTOM_TUNNEL] = 0.4
        
        return scores
    
    def get_protocol_name(self, protocol: VPNProtocol) -> str:
        """Get human-readable protocol name"""
        return protocol.value
    
    def get_protocol_description(self, protocol: VPNProtocol) -> str:
        """Get protocol description"""
        descriptions = {
            VPNProtocol.OPENVPN: "OpenVPN - Popular open-source VPN protocol supporting TCP/UDP",
            VPNProtocol.WIREGUARD: "WireGuard - Modern, fast VPN protocol with minimal overhead",
            VPNProtocol.IPSEC: "IPSec - Suite of protocols for IP network security",
            VPNProtocol.SSTP: "SSTP - Microsoft's Secure Socket Tunneling Protocol over HTTPS",
            VPNProtocol.L2TP: "L2TP - Layer 2 Tunneling Protocol (often with IPSec)",
            VPNProtocol.PPTP: "PPTP - Point-to-Point Tunneling Protocol (deprecated)",
            VPNProtocol.SOFTETHER: "SoftEther - Multi-protocol VPN software",
            VPNProtocol.CISCO_ANYCONNECT: "Cisco AnyConnect - Enterprise VPN solution",
            VPNProtocol.CUSTOM_TUNNEL: "Custom/Proprietary tunnel implementation",
            VPNProtocol.UNKNOWN: "Unknown or unidentified protocol"
        }
        return descriptions.get(protocol, "No description available")
    
    def get_statistics(self) -> dict:
        """Get identification statistics"""
        return {
            "identifications_total": self.identifications_total,
            "protocol_counts": {
                protocol.value: count
                for protocol, count in self.protocol_counts.items()
                if count > 0
            }
        }
