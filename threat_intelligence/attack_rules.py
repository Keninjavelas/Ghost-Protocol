"""
Advanced threat rule engine with 27+ attack scenarios.
8 attack categories with detection rules.
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum

import structlog

logger = structlog.get_logger(__name__)


class AttackCategory(str, Enum):
    """8 attack categories."""
    RECONNAISSANCE = "RECONNAISSANCE"
    CREDENTIAL = "CREDENTIAL"
    NETWORK_MANIPULATION = "NETWORK_MANIPULATION"
    FLOOD = "FLOOD"
    MALWARE = "MALWARE"
    EXFILTRATION = "EXFILTRATION"
    INSIDER = "INSIDER"
    INFRASTRUCTURE = "INFRASTRUCTURE"


@dataclass
class AttackRule:
    """Single detection rule."""
    name: str
    category: AttackCategory
    description: str
    conditions: Dict
    confidence: float
    mitre_techniques: List[str]


class AttackRuleEngine:
    """
    27+ attack detection rules organized by category.
    """

    def __init__(self):
        """Initialize attack rule engine."""
        self.rules = self._build_rules()
        self.disabled_rules: set[str] = set()
        logger.info("attack_rule_engine_initialized", total_rules=len(self.rules))

    def _build_rules(self) -> List[AttackRule]:
        """Build 27+ attack detection rules."""
        rules = []
        
        # ═══════════════════════════════════════════════════════════
        # 1. RECONNAISSANCE ATTACKS (5 rules)
        # ═══════════════════════════════════════════════════════════
        
        rules.append(AttackRule(
            name="Port Scanning",
            category=AttackCategory.RECONNAISSANCE,
            description="Multiple ports scanned from single source",
            conditions={
                "unique_ports_accessed": (">", 50),
            },
            confidence=0.85,
            mitre_techniques=["T1046"]
        ))
        
        rules.append(AttackRule(
            name="Network Scanning",
            category=AttackCategory.RECONNAISSANCE,
            description="Multiple IPs contacted from single source",
            conditions={
                "unique_ips_contacted": (">", 50),
            },
            confidence=0.78,
            mitre_techniques=["T1046"]
        ))
        
        rules.append(AttackRule(
            name="ARP Scanning",
            category=AttackCategory.RECONNAISSANCE,
            description="High number of ARP requests",
            conditions={
                "arp_requests": (">", 100),
            },
            confidence=0.80,
            mitre_techniques=["T1046"]
        ))
        
        rules.append(AttackRule(
            name="Service Enumeration",
            category=AttackCategory.RECONNAISSANCE,
            description="Systematic probing of network services",
            conditions={
                "unique_ports_accessed": (">", 30),
                "connection_duration": ("<", 5.0),
            },
            confidence=0.76,
            mitre_techniques=["T1046"]
        ))
        
        rules.append(AttackRule(
            name="OS Fingerprinting",
            category=AttackCategory.RECONNAISSANCE,
            description="Varied packet characteristics suggesting OS detection",
            conditions={
                "packet_variance": (">", 150000),
                "connection_count": (">", 20),
            },
            confidence=0.72,
            mitre_techniques=["T1046"]
        ))
        
        # ═══════════════════════════════════════════════════════════
        # 2. CREDENTIAL ATTACKS (4 rules)
        # ═══════════════════════════════════════════════════════════
        
        rules.append(AttackRule(
            name="Brute Force Login",
            category=AttackCategory.CREDENTIAL,
            description="High number of failed SSH login attempts",
            conditions={
                "login_attempts": (">", 50),
                "failed_connections": (">", 40),
            },
            confidence=0.92,
            mitre_techniques=["T1110"]
        ))
        
        rules.append(AttackRule(
            name="Password Spraying",
            category=AttackCategory.CREDENTIAL,
            description="Multiple IPs attempting logins",
            conditions={
                "unique_ips_contacted": (">", 20),
                "login_attempts": (">", 10),
            },
            confidence=0.84,
            mitre_techniques=["T1110.003"]
        ))
        
        rules.append(AttackRule(
            name="Credential Stuffing",
            category=AttackCategory.CREDENTIAL,
            description="Rapid authentication attempts with varying credentials",
            conditions={
                "login_attempts": (">", 100),
                "packet_rate": (">", 50.0),
            },
            confidence=0.79,
            mitre_techniques=["T1110.004"]
        ))
        
        rules.append(AttackRule(
            name="Repeated Login Failures",
            category=AttackCategory.CREDENTIAL,
            description="Multiple failed login attempts from same IP",
            conditions={
                "failed_connections": (">", 30),
            },
            confidence=0.86,
            mitre_techniques=["T1110"]
        ))
        
        # ═══════════════════════════════════════════════════════════
        # 3. NETWORK MANIPULATION (4 rules)
        # ═══════════════════════════════════════════════════════════
        
        rules.append(AttackRule(
            name="ARP Spoofing",
            category=AttackCategory.NETWORK_MANIPULATION,
            description="Abnormal increase in ARP traffic suggesting spoofing",
            conditions={
                "arp_requests": (">", 100),
            },
            confidence=0.88,
            mitre_techniques=["T1557.002"]
        ))
        
        rules.append(AttackRule(
            name="DNS Spoofing",
            category=AttackCategory.NETWORK_MANIPULATION,
            description="Suspicious DNS query patterns",
            conditions={
                "dns_requests": (">", 500),
            },
            confidence=0.81,
            mitre_techniques=["T1557.002"]
        ))
        
        rules.append(AttackRule(
            name="MITM Attack",
            category=AttackCategory.NETWORK_MANIPULATION,
            description="Connection anomalies suggesting interception",
            conditions={
                "failed_connections": (">", 50),
                "packet_variance": (">", 100000),
            },
            confidence=0.75,
            mitre_techniques=["T1557"]
        ))
        
        rules.append(AttackRule(
            name="Rogue DHCP",
            category=AttackCategory.NETWORK_MANIPULATION,
            description="Unusual DHCP traffic patterns",
            conditions={
                "arp_requests": (">", 200),
                "unique_ips_contacted": (">", 100),
            },
            confidence=0.77,
            mitre_techniques=["T1557.003"]
        ))
        
        # ═══════════════════════════════════════════════════════════
        # 4. FLOOD ATTACKS (4 rules)
        # ═══════════════════════════════════════════════════════════
        
        rules.append(AttackRule(
            name="SYN Flood",
            category=AttackCategory.FLOOD,
            description="Massive number of TCP SYN packets",
            conditions={
                "syn_packets": (">", 1000),
            },
            confidence=0.94,
            mitre_techniques=["T1499.004"]
        ))
        
        rules.append(AttackRule(
            name="UDP Flood",
            category=AttackCategory.FLOOD,
            description="Massive number of UDP packets",
            conditions={
                "udp_packets": (">", 1000),
            },
            confidence=0.91,
            mitre_techniques=["T1499.004"]
        ))
        
        rules.append(AttackRule(
            name="ICMP Flood",
            category=AttackCategory.FLOOD,
            description="High number of ICMP echo requests",
            conditions={
                "icmp_packets": (">", 500),
            },
            confidence=0.89,
            mitre_techniques=["T1499.001"]
        ))
        
        rules.append(AttackRule(
            name="HTTP Flood",
            category=AttackCategory.FLOOD,
            description="Flood of HTTP requests",
            conditions={
                "packet_rate": (">", 1000.0),
            },
            confidence=0.83,
            mitre_techniques=["T1499.004"]
        ))
        
        # ═══════════════════════════════════════════════════════════
        # 5. MALWARE COMMUNICATION (3 rules)
        # ═══════════════════════════════════════════════════════════
        
        rules.append(AttackRule(
            name="C2 Beaconing",
            category=AttackCategory.MALWARE,
            description="Regular communication pattern with external IP",
            conditions={
                "connection_count": (">", 100),
                "unique_ips_contacted": (">", 50),
            },
            confidence=0.84,
            mitre_techniques=["T1071"]
        ))
        
        rules.append(AttackRule(
            name="Botnet Communication",
            category=AttackCategory.MALWARE,
            description="Botnet-like traffic pattern",
            conditions={
                "udp_packets": (">", 500),
                "unique_ips_contacted": (">", 30),
            },
            confidence=0.79,
            mitre_techniques=["T1571"]
        ))
        
        rules.append(AttackRule(
            name="Beaconing Pattern",
            category=AttackCategory.MALWARE,
            description="Regular intervals of communication (heartbeat)",
            conditions={
                "connection_count": (">", 50),
                "packet_rate": (">", 10.0),
            },
            confidence=0.81,
            mitre_techniques=["T1071"]
        ))
        
        # ═══════════════════════════════════════════════════════════
        # 6. DATA EXFILTRATION (3 rules)
        # ═══════════════════════════════════════════════════════════
        
        rules.append(AttackRule(
            name="Large Data Transfer",
            category=AttackCategory.EXFILTRATION,
            description="Abnormally large outbound data transfer",
            conditions={
                "bytes_sent": (">", 104857600),  # 100MB
            },
            confidence=0.87,
            mitre_techniques=["T1020"]
        ))
        
        rules.append(AttackRule(
            name="Suspicious Encrypted Upload",
            category=AttackCategory.EXFILTRATION,
            description="Encrypted traffic to suspicious destination",
            conditions={
                "bytes_sent": (">", 52428800),  # 50MB
                "unique_ips_contacted": (">", 1),
            },
            confidence=0.76,
            mitre_techniques=["T1048"]
        ))
        
        rules.append(AttackRule(
            name="Unusual Outbound Traffic",
            category=AttackCategory.EXFILTRATION,
            description="Traffic pattern suggesting data exfiltration",
            conditions={
                "bytes_sent": (">", 10485760),  # 10MB
                "packet_rate": (">", 1000.0),
            },
            confidence=0.72,
            mitre_techniques=["T1048"]
        ))
        
        # ═══════════════════════════════════════════════════════════
        # 7. INSIDER THREATS (3 rules)
        # ═══════════════════════════════════════════════════════════
        
        rules.append(AttackRule(
            name="Abnormal File Access",
            category=AttackCategory.INSIDER,
            description="Unusual file access patterns",
            conditions={
                "unique_ports_accessed": (">", 20),
            },
            confidence=0.74,
            mitre_techniques=["T1005"]
        ))
        
        rules.append(AttackRule(
            name="Bulk Download",
            category=AttackCategory.INSIDER,
            description="Large volume download outside normal patterns",
            conditions={
                "bytes_received": (">", 52428800),  # 50MB
            },
            confidence=0.80,
            mitre_techniques=["T1005"]
        ))
        
        rules.append(AttackRule(
            name="Off-Hours Access",
            category=AttackCategory.INSIDER,
            description="Access outside normal working hours",
            conditions={
                "connection_count": (">", 10),
            },
            confidence=0.65,
            mitre_techniques=["T1078"]
        ))
        
        # ═══════════════════════════════════════════════════════════
        # 8. INFRASTRUCTURE ATTACKS (1 rule)+
        # ═══════════════════════════════════════════════════════════
        
        rules.append(AttackRule(
            name="Router Attack",
            category=AttackCategory.INFRASTRUCTURE,
            description="Attempts to access network infrastructure",
            conditions={
                "failed_connections": (">", 20),
                "login_attempts": (">", 15),
            },
            confidence=0.82,
            mitre_techniques=["T1190"]
        ))
        
        return rules

    def evaluate_rule(self, rule: AttackRule, features) -> bool:
        """
        Evaluate if features match a rule.
        
        Args:
            rule: AttackRule to evaluate
            features: FlowFeatures object
            
        Returns:
            True if rule matches
        """
        try:
            for attr, condition in rule.conditions.items():
                feature_value = getattr(features, attr, 0)
                operator, threshold = condition
                
                if operator == ">" and not (feature_value > threshold):
                    return False
                elif operator == "<" and not (feature_value < threshold):
                    return False
                elif operator == "==" and not (feature_value == threshold):
                    return False
            
            return True
        except Exception as e:
            logger.error("rule_evaluation_failed", error=str(e))
            return False

    def evaluate_all(self, features) -> List[AttackRule]:
        """
        Evaluate all rules against features.
        
        Returns:
            List of matching rules
        """
        matching_rules = []
        for rule in self.rules:
            if rule.name in self.disabled_rules:
                continue
            if self.evaluate_rule(rule, features):
                matching_rules.append(rule)
        
        return matching_rules

    def get_rules_by_category(self, category: AttackCategory) -> List[AttackRule]:
        """Get all rules in a category."""
        return [r for r in self.rules if r.category == category]

    def get_rules(self, category: Optional[str] = None) -> List[AttackRule]:
        """Get rules, optionally filtered by category string."""
        if not category:
            return [r for r in self.rules]

        try:
            category_enum = AttackCategory(category.upper())
        except ValueError:
            return []

        return self.get_rules_by_category(category_enum)

    def disable_rule(self, rule_id: str) -> None:
        """Disable rule by normalized id or by display name."""
        for rule in self.rules:
            normalized = rule.name.lower().replace(" ", "_")
            if rule_id in {normalized, rule.name}:
                self.disabled_rules.add(rule.name)
                return
        raise ValueError(f"rule_not_found: {rule_id}")

    def enable_rule(self, rule_id: str) -> None:
        """Enable rule by normalized id or by display name."""
        for rule in self.rules:
            normalized = rule.name.lower().replace(" ", "_")
            if rule_id in {normalized, rule.name}:
                self.disabled_rules.discard(rule.name)
                return
        raise ValueError(f"rule_not_found: {rule_id}")
