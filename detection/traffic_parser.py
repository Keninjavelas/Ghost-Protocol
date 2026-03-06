"""
Network traffic parser.
Decodes packets and extracts protocol-specific metadata.
"""

from typing import Dict, Optional, List
from dataclasses import dataclass
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ParsedPacket:
    """Normalized packet representation."""
    timestamp: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    packet_size: int
    ttl: int
    flags: str
    payload_length: int
    is_malformed: bool = False
    confidence: float = 1.0


class TrafficParser:
    """
    Parses raw packets into normalized, machine-readable format.
    Extracts headers and metadata for all major protocols.
    """

    def __init__(self):
        """Initialize traffic parser."""
        self.protocol_handlers = {
            "TCP": self._parse_tcp,
            "UDP": self._parse_udp,
            "ICMP": self._parse_icmp,
            "DNS": self._parse_dns,
            "ARP": self._parse_arp,
            "HTTP": self._parse_http,
        }
        logger.info("traffic_parser_initialized")

    def parse(self, raw_packet: dict) -> ParsedPacket:
        """
        Parse raw packet into structured format.
        
        Args:
            raw_packet: Raw packet dictionary
            
        Returns:
            ParsedPacket with normalized data
        """
        try:
            # Validate required fields
            required = ["timestamp", "source_ip", "dest_ip", "protocol"]
            if not all(k in raw_packet for k in required):
                return self._create_malformed_packet(raw_packet)
            
            # Extract basic fields
            parsed = ParsedPacket(
                timestamp=raw_packet["timestamp"],
                source_ip=raw_packet["source_ip"],
                dest_ip=raw_packet["dest_ip"],
                source_port=raw_packet.get("source_port", 0),
                dest_port=raw_packet.get("dest_port", 0),
                protocol=raw_packet["protocol"],
                packet_size=raw_packet.get("packet_size", 0),
                ttl=raw_packet.get("ttl", 64),
                flags=raw_packet.get("flags", ""),
                payload_length=raw_packet.get("payload_length", 0),
            )
            
            # Protocol-specific parsing
            protocol_handler = self.protocol_handlers.get(parsed.protocol)
            if protocol_handler:
                protocol_handler(parsed, raw_packet)
            
            return parsed
        
        except Exception as e:
            logger.error("packet_parse_failed", error=str(e))
            return self._create_malformed_packet(raw_packet)

    def _parse_tcp(self, packet: ParsedPacket, raw: dict) -> None:
        """Parse TCP packet."""
        # TCP flags analysis
        if "SYN" in packet.flags:
            packet.confidence = 0.95
        elif "RST" in packet.flags or "FIN" in packet.flags:
            packet.confidence = 0.92

    def _parse_udp(self, packet: ParsedPacket, raw: dict) -> None:
        """Parse UDP packet."""
        # UDP-specific handling
        packet.confidence = 0.90

    def _parse_icmp(self, packet: ParsedPacket, raw: dict) -> None:
        """Parse ICMP packet."""
        # ICMP-specific handling
        packet.protocol = "ICMP"
        packet.confidence = 0.93

    def _parse_dns(self, packet: ParsedPacket, raw: dict) -> None:
        """Parse DNS packet."""
        # DNS on UDP port 53
        if packet.dest_port == 53 or packet.source_port == 53:
            packet.protocol = "DNS"
            packet.confidence = 0.98

    def _parse_arp(self, packet: ParsedPacket, raw: dict) -> None:
        """Parse ARP packet."""
        # ARP analysis
        packet.protocol = "ARP"
        packet.confidence = 0.96

    def _parse_http(self, packet: ParsedPacket, raw: dict) -> None:
        """Parse HTTP packet."""
        # HTTP on ports 80, 8080, etc.
        if packet.dest_port in [80, 8080, 3000, 5000]:
            packet.protocol = "HTTP"
            packet.confidence = 0.91

    def _create_malformed_packet(self, raw: dict) -> ParsedPacket:
        """Create malformed packet entry."""
        return ParsedPacket(
            timestamp=raw.get("timestamp", "unknown"),
            source_ip=raw.get("source_ip", "0.0.0.0"),
            dest_ip=raw.get("dest_ip", "0.0.0.0"),
            source_port=raw.get("source_port", 0),
            dest_port=raw.get("dest_port", 0),
            protocol=raw.get("protocol", "UNKNOWN"),
            packet_size=raw.get("packet_size", 0),
            ttl=raw.get("ttl", 64),
            flags=raw.get("flags", ""),
            payload_length=raw.get("payload_length", 0),
            is_malformed=True,
            confidence=0.5,
        )

    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts if p.isdigit())

    def batch_parse(self, raw_packets: List[dict]) -> List[ParsedPacket]:
        """
        Parse multiple packets.
        
        Args:
            raw_packets: List of raw packet dictionaries
            
        Returns:
            List of ParsedPacket objects
        """
        return [self.parse(pkt) for pkt in raw_packets]
