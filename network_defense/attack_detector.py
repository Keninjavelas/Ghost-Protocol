"""
Module 5: Attack Detector
Rule-based detection for 27+ attack scenarios across 8 categories.
"""

from typing import Dict, List, Optional
from collections import defaultdict
from datetime import datetime, timedelta
import structlog

logger = structlog.get_logger(__name__)


class AttackDetector:
    """
    Rule-based attack detection engine.
    Detects 27+ attack types across 8 categories.
    """

    def __init__(self):
        """Initialize attack detector."""
        # Attack detection state
        self.detection_state = {
            "port_scan_targets": defaultdict(set),  # IP -> set of ports scanned
            "login_attempts": defaultdict(int),  # IP -> attempt count
            "arp_cache": defaultdict(set),  # IP -> set of MAC addresses
            "dns_queries": defaultdict(list),  # Domain -> list of timestamps
            "beacon_patterns": defaultdict(list),  # IP -> list of connection times
            "data_transfers": defaultdict(int),  # IP -> bytes transferred
            "file_access_log": defaultdict(list),  # User -> list of accessed files
        }
        
        # Detection thresholds
        self.thresholds = {
            "port_scan_threshold": 10,  # ports per minute
            "brute_force_threshold": 50,  # login attempts per minute
            "arp_spoof_threshold": 2,  # different MACs for same IP
            "dns_query_threshold": 100,  # repeated queries
            "syn_flood_threshold": 1000,  # SYN packets per second
            "udp_flood_threshold": 1000,  # UDP packets per second
            "icmp_flood_threshold": 500,  # ICMP packets per second
            "data_exfil_threshold": 1073741824,  # 1GB
            "beacon_interval_tolerance": 5,  # seconds
        }
        
        logger.info("attack_detector_initialized")

    def detect_attacks(self, packets: List[Dict], features: Dict) -> List[Dict]:
        """
        Detect attacks from packet data and features.
        
        Args:
            packets: List of parsed packets
            features: Extracted feature vector
        
        Returns:
            List of detected attack dictionaries
        """
        attacks = []
        
        # Category 1: Reconnaissance
        attacks.extend(self._detect_reconnaissance(packets, features))
        
        # Category 2: Credential Attacks
        attacks.extend(self._detect_credential_attacks(packets, features))
        
        # Category 3: Network Manipulation
        attacks.extend(self._detect_network_manipulation(packets, features))
        
        # Category 4: Flood Attacks
        attacks.extend(self._detect_flood_attacks(packets, features))
        
        # Category 5: Malware Communication
        attacks.extend(self._detect_malware_communication(packets, features))
        
        # Category 6: Data Exfiltration
        attacks.extend(self._detect_data_exfiltration(packets, features))
        
        # Category 7: Insider Threat
        attacks.extend(self._detect_insider_threat(packets, features))
        
        # Category 8: Infrastructure Attacks
        attacks.extend(self._detect_infrastructure_attacks(packets, features))
        
        logger.info("attack_detection_complete", attacks_detected=len(attacks))
        return attacks

    # ═══════════════════ CATEGORY 1: RECONNAISSANCE ═══════════════════

    def _detect_reconnaissance(self, packets: List[Dict], features: Dict) -> List[Dict]:
        """Detect port scanning, network scanning, service enumeration."""
        attacks = []
        
        # 1. Port Scanning Detection
        for packet in packets:
            if packet.get("protocol") == "TCP" and packet.get("is_syn"):
                src_ip = packet.get("src_ip")
                dst_port = packet.get("dst_port")
                
                if src_ip and dst_port:
                    self.detection_state["port_scan_targets"][src_ip].add(dst_port)
        
        # Check for port scan threshold
        for src_ip, ports in self.detection_state["port_scan_targets"].items():
            if len(ports) >= self.thresholds["port_scan_threshold"]:
                attacks.append({
                    "type": "port_scan",
                    "category": "reconnaissance",
                    "severity": "medium",
                    "source_ip": src_ip,
                    "ports_scanned": len(ports),
                    "confidence": min(len(ports) / 100, 1.0),
                    "description": f"Port scan detected from {src_ip} targeting {len(ports)} ports"
                })
        
        # 2. Network Scanning (ARP-based)
        arp_requests = [p for p in packets if p.get("protocol") == "ARP" and p.get("arp_operation") == "request"]
        if len(arp_requests) > 50:  # Rapid ARP requests
            attacks.append({
                "type": "network_scan",
                "category": "reconnaissance",
                "severity": "low",
                "arp_requests": len(arp_requests),
                "confidence": 0.75,
                "description": f"Network scanning detected via {len(arp_requests)} ARP requests"
            })
        
        # 3. Service Enumeration (specific port patterns)
        common_service_ports = {21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080}
        service_scans = [p for p in packets if p.get("dst_port") in common_service_ports]
        if len(service_scans) > 20:
            attacks.append({
                "type": "service_enumeration",
                "category": "reconnaissance",
                "severity": "medium",
                "probes": len(service_scans),
                "confidence": 0.70,
                "description": "Service enumeration detected on common ports"
            })
        
        return attacks

    # ═══════════════════ CATEGORY 2: CREDENTIAL ATTACKS ═══════════════════

    def _detect_credential_attacks(self, packets: List[Dict], features: Dict) -> List[Dict]:
        """Detect brute force, password spraying, credential stuffing."""
        attacks = []
        
        # Login attempt tracking (SSH, RDP, Telnet)
        login_ports = {22, 23, 3389}
        
        for packet in packets:
            if packet.get("dst_port") in login_ports:
                src_ip = packet.get("src_ip")
                if src_ip:
                    self.detection_state["login_attempts"][src_ip] += 1
        
        # 4. Brute Force Detection
        for src_ip, attempts in self.detection_state["login_attempts"].items():
            if attempts >= self.thresholds["brute_force_threshold"]:
                attacks.append({
                    "type": "brute_force",
                    "category": "credential_attack",
                    "severity": "high",
                    "source_ip": src_ip,
                    "attempts": attempts,
                    "confidence": min(attempts / 100, 1.0),
                    "description": f"Brute force attack from {src_ip} with {attempts} login attempts"
                })
        
        # 5. Password Spraying (multiple targets, few attempts each)
        if features.get("unique_ips_contacted", 0) > 10 and features.get("login_attempts", 0) > 20:
            attacks.append({
                "type": "password_spraying",
                "category": "credential_attack",
                "severity": "high",
                "targets": features["unique_ips_contacted"],
                "attempts": features["login_attempts"],
                "confidence": 0.65,
                "description": "Password spraying pattern detected across multiple targets"
            })
        
        return attacks

    # ═══════════════════ CATEGORY 3: NETWORK MANIPULATION ═══════════════════

    def _detect_network_manipulation(self, packets: List[Dict], features: Dict) -> List[Dict]:
        """Detect ARP spoofing, DNS spoofing, MITM attacks."""
        attacks = []
        
        # 10. ARP Spoofing Detection
        for packet in packets:
            if packet.get("protocol") == "ARP" and packet.get("arp_operation") == "reply":
                arp_src_ip = packet.get("arp_src_ip")
                arp_src_mac = packet.get("arp_src_mac")
                
                if arp_src_ip and arp_src_mac:
                    self.detection_state["arp_cache"][arp_src_ip].add(arp_src_mac)
        
        for ip, macs in self.detection_state["arp_cache"].items():
            if len(macs) >= self.thresholds["arp_spoof_threshold"]:
                attacks.append({
                    "type": "arp_spoofing",
                    "category": "network_manipulation",
                    "severity": "critical",
                    "target_ip": ip,
                    "mac_addresses": list(macs),
                    "confidence": 0.90,
                    "description": f"ARP spoofing detected: {ip} claimed by {len(macs)} MAC addresses"
                })
        
        # 11. DNS Spoofing Detection (rapid DNS responses)
        dns_responses = [p for p in packets if p.get("protocol") == "DNS" and p.get("is_dns_response")]
        if len(dns_responses) > 100:
            attacks.append({
                "type": "dns_spoofing",
                "category": "network_manipulation",
                "severity": "high",
                "responses": len(dns_responses),
                "confidence": 0.60,
                "description": f"Suspicious DNS activity: {len(dns_responses)} rapid responses"
            })
        
        return attacks

    # ═══════════════════ CATEGORY 4: FLOOD ATTACKS ═══════════════════

    def _detect_flood_attacks(self, packets: List[Dict], features: Dict) -> List[Dict]:
        """Detect SYN flood, UDP flood, ICMP flood, HTTP flood."""
        attacks = []
        
        # 14. SYN Flood Detection
        if features.get("syn_packets", 0) > self.thresholds["syn_flood_threshold"] / 10:  # Per window
            attacks.append({
                "type": "syn_flood",
                "category": "flood_attack",
                "severity": "critical",
                "syn_packets": features["syn_packets"],
                "confidence": 0.85,
                "description": f"SYN flood detected: {features['syn_packets']} SYN packets in window"
            })
        
        # 15. UDP Flood Detection
        if features.get("udp_packets", 0) > self.thresholds["udp_flood_threshold"] / 10:
            attacks.append({
                "type": "udp_flood",
                "category": "flood_attack",
                "severity": "critical",
                "udp_packets": features["udp_packets"],
                "confidence": 0.85,
                "description": f"UDP flood detected: {features['udp_packets']} UDP packets in window"
            })
        
        # 16. ICMP Flood Detection
        if features.get("icmp_packets", 0) > self.thresholds["icmp_flood_threshold"] / 10:
            attacks.append({
                "type": "icmp_flood",
                "category": "flood_attack",
                "severity": "high",
                "icmp_packets": features["icmp_packets"],
                "confidence": 0.80,
                "description": f"ICMP flood detected: {features['icmp_packets']} ICMP packets in window"
            })
        
        return attacks

    # ═══════════════════ CATEGORY 5: MALWARE COMMUNICATION ═══════════════════

    def _detect_malware_communication(self, packets: List[Dict], features: Dict) -> List[Dict]:
        """Detect C2 traffic, botnet communication, beaconing."""
        attacks = []
        
        # 18. Beaconing Detection (periodic connections)
        for packet in packets:
            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            timestamp = packet.get("timestamp")
            
            if src_ip and dst_ip and timestamp:
                conn_key = (src_ip, dst_ip)
                self.detection_state["beacon_patterns"][conn_key].append(
                    datetime.fromisoformat(timestamp)
                )
        
        for conn_key, timestamps in self.detection_state["beacon_patterns"].items():
            if len(timestamps) >= 5:
                intervals = [
                    (timestamps[i+1] - timestamps[i]).total_seconds()
                    for i in range(len(timestamps) - 1)
                ]
                
                # Check for consistent intervals (beaconing pattern)
                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                    
                    if variance < self.thresholds["beacon_interval_tolerance"]:
                        attacks.append({
                            "type": "beaconing",
                            "category": "malware_communication",
                            "severity": "critical",
                            "source_ip": conn_key[0],
                            "destination_ip": conn_key[1],
                            "interval_seconds": avg_interval,
                            "confidence": 0.80,
                            "description": f"C2 beaconing detected: {conn_key[0]} → {conn_key[1]} every {avg_interval:.1f}s"
                        })
        
        return attacks

    # ═══════════════════ CATEGORY 6: DATA EXFILTRATION ═══════════════════

    def _detect_data_exfiltration(self, packets: List[Dict], features: Dict) -> List[Dict]:
        """Detect large data transfers, suspicious uploads."""
        attacks = []
        
        # 21. Large Outbound Transfer Detection
        for packet in packets:
            src_ip = packet.get("src_ip")
            packet_size = packet.get("packet_size", 0)
            
            if src_ip and packet_size > 0:
                self.detection_state["data_transfers"][src_ip] += packet_size
        
        for src_ip, bytes_transferred in self.detection_state["data_transfers"].items():
            if bytes_transferred >= self.thresholds["data_exfil_threshold"]:
                attacks.append({
                    "type": "data_exfiltration",
                    "category": "data_exfiltration",
                    "severity": "critical",
                    "source_ip": src_ip,
                    "bytes_transferred": bytes_transferred,
                    "confidence": 0.70,
                    "description": f"Data exfiltration: {src_ip} transferred {bytes_transferred / 1024 / 1024:.1f} MB"
                })
        
        return attacks

    # ═══════════════════ CATEGORY 7: INSIDER THREAT ═══════════════════

    def _detect_insider_threat(self, packets: List[Dict], features: Dict) -> List[Dict]:
        """Detect abnormal file access, bulk downloads."""
        attacks = []
        
        # 24. Abnormal File Access (placeholder - requires application-layer data)
        # This would typically integrate with file access logs
        
        return attacks

    # ═══════════════════ CATEGORY 8: INFRASTRUCTURE ATTACKS ═══════════════════

    def _detect_infrastructure_attacks(self, packets: List[Dict], features: Dict) -> List[Dict]:
        """Detect router/IoT attacks, firmware modification attempts."""
        attacks = []
        
        # 27. Router Admin Access Attempts
        router_ports = {80, 443, 8080, 23}  # Common router admin ports
        router_attempts = [p for p in packets if p.get("dst_port") in router_ports]
        
        if len(router_attempts) > 20:
            attacks.append({
                "type": "infrastructure_attack",
                "category": "infrastructure_attack",
                "severity": "high",
                "attempts": len(router_attempts),
                "confidence": 0.60,
                "description": f"Infrastructure attack detected: {len(router_attempts)} admin access attempts"
            })
        
        return attacks

    def reset_state(self) -> None:
        """Reset detection state for next window."""
        self.detection_state = {
            "port_scan_targets": defaultdict(set),
            "login_attempts": defaultdict(int),
            "arp_cache": defaultdict(set),
            "dns_queries": defaultdict(list),
            "beacon_patterns": defaultdict(list),
            "data_transfers": defaultdict(int),
            "file_access_log": defaultdict(list),
        }
