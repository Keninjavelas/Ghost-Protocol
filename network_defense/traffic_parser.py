"""
Module 2: Traffic Parser
Decodes and normalizes network packets for threat detection.
"""

from typing import Dict, List, Optional
from datetime import datetime
import structlog

logger = structlog.get_logger(__name__)


class TrafficParser:
    """
    Traffic parsing engine for protocol normalization.
    Supports: TCP, UDP, ICMP, DNS, HTTP, ARP
    """

    def __init__(self):
        """Initialize traffic parser."""
        self.protocol_handlers = {
            "TCP": self._parse_tcp,
            "UDP": self._parse_udp,
            "ICMP": self._parse_icmp,
            "DNS": self._parse_dns,
            "HTTP": self._parse_http,
            "ARP": self._parse_arp,
        }
        logger.info("traffic_parser_initialized")

    def parse_packet(self, raw_packet: Dict) -> Optional[Dict]:
        """
        Parse and normalize a raw packet dictionary.
        
        Args:
            raw_packet: Raw packet from packet capture engine
        
        Returns:
            Normalized packet dictionary with standardized fields
        """
        try:
            protocol = raw_packet.get("protocol", "UNKNOWN")
            
            # Base normalized packet
            normalized = {
                "timestamp": raw_packet.get("timestamp"),
                "src_ip": raw_packet.get("src_ip", "0.0.0.0"),
                "dst_ip": raw_packet.get("dst_ip", "0.0.0.0"),
                "protocol": protocol,
                "packet_size": raw_packet.get("packet_size", 0),
                "payload_length": raw_packet.get("payload_length", 0),
            }
            
            # Protocol-specific parsing
            handler = self.protocol_handlers.get(protocol)
            if handler:
                protocol_data = handler(raw_packet)
                normalized.update(protocol_data)
            
            return normalized
        
        except Exception as e:
            logger.error("packet_parsing_failed", error=str(e))
            return None

    def parse_batch(self, packets: List[Dict]) -> List[Dict]:
        """
        Parse multiple packets in batch.
        
        Args:
            packets: List of raw packets
        
        Returns:
            List of normalized packets
        """
        parsed = []
        for packet in packets:
            normalized = self.parse_packet(packet)
            if normalized:
                parsed.append(normalized)
        
        logger.debug("batch_parsed", count=len(parsed))
        return parsed

    def _parse_tcp(self, packet: Dict) -> Dict:
        """Parse TCP-specific fields."""
        return {
            "src_port": packet.get("src_port", 0),
            "dst_port": packet.get("dst_port", 0),
            "flags": packet.get("flags", ""),
            "seq": packet.get("seq", 0),
            "ack": packet.get("ack", 0),
            "window": packet.get("window", 0),
            "is_syn": "S" in packet.get("flags", ""),
            "is_ack": "A" in packet.get("flags", ""),
            "is_fin": "F" in packet.get("flags", ""),
            "is_rst": "R" in packet.get("flags", ""),
        }

    def _parse_udp(self, packet: Dict) -> Dict:
        """Parse UDP-specific fields."""
        return {
            "src_port": packet.get("src_port", 0),
            "dst_port": packet.get("dst_port", 0),
            "length": packet.get("length", 0),
        }

    def _parse_icmp(self, packet: Dict) -> Dict:
        """Parse ICMP-specific fields."""
        icmp_type = packet.get("icmp_type", 0)
        icmp_code = packet.get("icmp_code", 0)
        
        # Classify ICMP type
        icmp_types = {
            0: "echo_reply",
            3: "dest_unreachable",
            5: "redirect",
            8: "echo_request",
            11: "time_exceeded",
        }
        
        return {
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "icmp_type_name": icmp_types.get(icmp_type, "unknown"),
        }

    def _parse_dns(self, packet: Dict) -> Dict:
        """Parse DNS-specific fields."""
        return {
            "dns_id": packet.get("dns_id", 0),
            "dns_query": packet.get("dns_query", ""),
            "is_dns_query": packet.get("dns_qr", 0) == 0,
            "is_dns_response": packet.get("dns_qr", 0) == 1,
        }

    def _parse_http(self, packet: Dict) -> Dict:
        """Parse HTTP-specific fields."""
        return {
            "http_method": packet.get("http_method", ""),
            "http_host": packet.get("http_host", ""),
            "http_path": packet.get("http_path", ""),
        }

    def _parse_arp(self, packet: Dict) -> Dict:
        """Parse ARP-specific fields."""
        arp_op = packet.get("arp_op", 0)
        
        return {
            "arp_operation": "request" if arp_op == 1 else "reply",
            "arp_src_mac": packet.get("arp_hwsrc", ""),
            "arp_src_ip": packet.get("arp_psrc", ""),
            "arp_dst_mac": packet.get("arp_hwdst", ""),
            "arp_dst_ip": packet.get("arp_pdst", ""),
        }

    def extract_connection_tuple(self, packet: Dict) -> Optional[tuple]:
        """
        Extract connection 5-tuple for flow tracking.
        
        Returns:
            (src_ip, dst_ip, src_port, dst_port, protocol)
        """
        try:
            return (
                packet.get("src_ip"),
                packet.get("dst_ip"),
                packet.get("src_port", 0),
                packet.get("dst_port", 0),
                packet.get("protocol"),
            )
        except Exception:
            return None

    def is_suspicious_port(self, port: int) -> bool:
        """Check if port is commonly associated with attacks."""
        suspicious_ports = {
            # Remote access
            22, 23, 3389,
            # Databases
            1433, 3306, 5432, 27017,
            # Admin panels
            8080, 8443, 9090,
            # Backdoors
            4444, 5555, 6666, 31337,
        }
        return port in suspicious_ports

    def classify_traffic_type(self, packet: Dict) -> str:
        """
        Classify traffic type based on ports and protocol.
        
        Returns:
            Traffic classification (e.g., "web", "ssh", "database", "unknown")
        """
        protocol = packet.get("protocol", "")
        dst_port = packet.get("dst_port", 0)
        
        # Port-based classification
        port_types = {
            80: "web",
            443: "web",
            22: "ssh",
            23: "telnet",
            21: "ftp",
            25: "smtp",
            53: "dns",
            3306: "database",
            5432: "database",
            1433: "database",
            27017: "database",
            3389: "rdp",
            445: "smb",
            139: "smb",
        }
        
        return port_types.get(dst_port, "unknown")
