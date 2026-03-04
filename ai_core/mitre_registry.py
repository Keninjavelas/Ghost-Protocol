"""
ai_core/mitre_registry.py
Canonical registry of valid MITRE ATT&CK technique IDs.

Used by MitreMapper to filter out hallucinated technique IDs.
Prevents the LLM from inventing fake MITRE identifiers.

This is a minimal subset of the MITRE ATT&CK Enterprise matrix.
Expand as needed for production deployments.
"""
from __future__ import annotations

# Valid MITRE ATT&CK technique IDs (Enterprise matrix)
VALID_TECHNIQUES = {
    # ── Reconnaissance ──
    "T1595",  # Active Scanning
    "T1590",  # Gather Victim Network Information
    "T1589",  # Gather Victim Identity Information
    "T1591",  # Gather Victim Org Information
    
    # ── Resource Development ──
    "T1583",  # Acquire Infrastructure
    "T1586",  # Compromise Accounts
    "T1588",  # Obtain Capabilities
    "T1587",  # Develop Capabilities
    
    # ── Initial Access ──
    "T1078",  # Valid Accounts
    "T1190",  # Exploit Public-Facing Application
    "T1133",  # External Remote Services
    "T1566",  # Phishing
    
    # ── Execution ──
    "T1059",      # Command and Scripting Interpreter
    "T1059.001",  # PowerShell
    "T1059.003",  # Windows Command Shell
    "T1059.004",  # Unix Shell
    "T1059.006",  # Python
    "T1203",      # Exploitation for Client Execution
    "T1106",      # Native API
    
    # ── Persistence ──
    "T1053",      # Scheduled Task/Job
    "T1136",      # Create Account
    "T1098",      # Account Manipulation
    "T1547",      # Boot or Logon Autostart Execution
    "T1543",      # Create or Modify System Process
    
    # ── Privilege Escalation ──
    "T1068",  # Exploitation for Privilege Escalation
    "T1134",  # Access Token Manipulation
    "T1548",  # Abuse Elevation Control Mechanism
    "T1055",  # Process Injection
    
    # ── Defense Evasion ──
    "T1070",      # Indicator Removal
    "T1070.004",  # File Deletion
    "T1070.006",  # Timestomp
    "T1036",      # Masquerading
    "T1027",      # Obfuscated Files or Information
    "T1140",      # Deobfuscate/Decode Files or Information
    "T1564",      # Hide Artifacts
    "T1562",      # Impair Defenses
    
    # ── Credential Access ──
    "T1003",      # OS Credential Dumping
    "T1003.001",  # LSASS Memory
    "T1003.008",  # /etc/passwd and /etc/shadow
    "T1555",      # Credentials from Password Stores
    "T1552",      # Unsecured Credentials
    "T1110",      # Brute Force
    "T1056",      # Input Capture
    
    # ── Discovery ──
    "T1082",  # System Information Discovery
    "T1083",  # File and Directory Discovery
    "T1087",  # Account Discovery
    "T1069",  # Permission Groups Discovery
    "T1046",  # Network Service Discovery
    "T1057",  # Process Discovery
    "T1018",  # Remote System Discovery
    "T1049",  # System Network Connections Discovery
    "T1033",  # System Owner/User Discovery
    
    # ── Lateral Movement ──
    "T1021",      # Remote Services
    "T1021.001",  # Remote Desktop Protocol
    "T1021.002",  # SMB/Windows Admin Shares
    "T1021.004",  # SSH
    "T1563",      # Remote Service Session Hijacking
    "T1210",      # Exploitation of Remote Services
    
    # ── Collection ──
    "T1560",  # Archive Collected Data
    "T1005",  # Data from Local System
    "T1039",  # Data from Network Shared Drive
    "T1025",  # Data from Removable Media
    "T1074",  # Data Staged
    "T1113",  # Screen Capture
    
    # ── Command and Control ──
    "T1071",      # Application Layer Protocol
    "T1071.001",  # Web Protocols
    "T1105",      # Ingress Tool Transfer
    "T1572",      # Protocol Tunneling
    "T1090",      # Proxy
    "T1219",      # Remote Access Software
    
    # ── Exfiltration ──
    "T1041",  # Exfiltration Over C2 Channel
    "T1048",  # Exfiltration Over Alternative Protocol
    "T1567",  # Exfiltration Over Web Service
    "T1029",  # Scheduled Transfer
    
    # ── Impact ──
    "T1486",  # Data Encrypted for Impact
    "T1490",  # Inhibit System Recovery
    "T1485",  # Data Destruction
    "T1489",  # Service Stop
    "T1491",  # Defacement
}


def is_valid_technique(technique_id: str) -> bool:
    """
    Check if a technique ID is in the canonical registry.
    Returns True if valid, False if hallucinated/invalid.
    """
    return technique_id in VALID_TECHNIQUES


def filter_techniques(techniques: list[dict]) -> list[dict]:
    """
    Filter a list of technique dicts (from LLM) to only include valid IDs.
    
    Args:
        techniques: List of dicts with 'id' field (MITRE technique ID)
        
    Returns:
        Filtered list containing only valid MITRE techniques
    """
    return [t for t in techniques if is_valid_technique(t.get("id", ""))]
