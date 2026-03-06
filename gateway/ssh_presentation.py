"""
gateway/ssh_presentation.py
SSH presentation layer for realistic Ubuntu 22.04 experience.

Handles:
  - Hostname generation from IP address
  - Realistic Ubuntu banner with system information
  - Last login tracking
  - Built-in command responses (whoami, hostname, pwd, uname -a)
  - Prompt formatting with working directory
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

import structlog

log = structlog.get_logger(__name__)


# ── Hostname Generation ────────────────────────────────────────────────────────

def generate_hostname_from_ip(peer_ip: str) -> str:
    """
    Generate a realistic AWS-style hostname from attacker's IP.
    
    Example: 192.168.1.25 → ip-192-168-1-25
    Or for internal: 10.0.4.12 → ip-10-0-4-12
    """
    # Sanitize IP to remove leading zeros and convert dots to dashes
    octets = peer_ip.split(".")
    if len(octets) != 4:
        # Fallback for invalid IPs
        return "ip-ghost-protocol"
    
    # Remove leading zeros from each octet
    cleaned = [str(int(octet)) for octet in octets]
    hostname = "ip-" + "-".join(cleaned)
    return hostname


# ── Banner Generation ──────────────────────────────────────────────────────────

def generate_ubuntu_banner(hostname: str) -> str:
    """
    Generate a realistic Ubuntu 22.04 LTS login banner.
    
    Includes:
      - Welcome message
      - Documentation/support links
      - System information (load, disk, memory, IP)
      - Timestamp
    """
    import socket
    
    try:
        server_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        server_ip = "10.0.0.100"  # Fallback
    
    ts = datetime.now(timezone.utc)
    ts_str = ts.strftime("%a %b %d %H:%M:%S %Z %Y")
    
    # Realistic system metrics
    # System load (3-value average)
    load_avg = "0.08"
    processes = "112"
    
    # Disk usage
    disk_usage = "41.2"
    disk_total = "40GB"
    
    # Memory usage
    mem_usage = "32"
    
    # Users logged in
    users_logged = "1"
    
    # Swap usage
    swap_usage = "0"
    
    banner = (
        f"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
        f"  * Documentation:  https://help.ubuntu.com\r\n"
        f"  * Management:     https://landscape.canonical.com\r\n"
        f"  * Support:        https://ubuntu.com/advantage\r\n\r\n"
        f"System information as of {ts_str}\r\n\r\n"
        f"System load:  {load_avg:<14} Processes:             {processes}\r\n"
        f"Usage of /:   {disk_usage}% of {disk_total:<6} Users logged in:       {users_logged}\r\n"
        f"Memory usage: {mem_usage}%{'':<14} IPv4 address for eth0: {server_ip}\r\n"
        f"Swap usage:   {swap_usage}%\r\n\r\n"
    )
    
    return banner


# ── Last Login Message ─────────────────────────────────────────────────────────

def format_last_login(source_ip: str, relative_time_seconds: int = 0) -> str:
    """
    Format a realistic 'Last login' message.
    
    Example:
        Last login: Mon Jun 10 14:21:17 2024 from 192.168.1.25
    """
    # Use current time, optionally offset by seconds
    ts = datetime.now(timezone.utc)
    ts_str = ts.strftime("%a %b %d %H:%M:%S %Z %Y")
    
    return f"Last login: {ts_str} from {source_ip}"


# ── Built-in Command Responses ─────────────────────────────────────────────────

def handle_builtin_command(
    command: str,
    hostname: str,
    working_directory: str,
) -> Optional[str]:
    """
    Handle built-in shell commands that should NOT go to the AI pipeline.
    
    Returns:
        Response string if this is a built-in command.
        None if the command should be routed to the AI pipeline.
    
    Supported commands:
      - whoami, hostname, pwd, id
      - uname (all variants)
      - ip a / ifconfig
      - echo, date, uptime
      - ls, dir (basic listing)
    """
    cmd = command.strip().lower()
    
    # whoami
    if cmd == "whoami":
        return "root"
    
    # hostname
    if cmd == "hostname":
        return hostname
    
    # pwd (print working directory)
    if cmd == "pwd":
        return working_directory
    
    # id - user identity (root)
    if cmd == "id":
        return "uid=0(root) gid=0(root) groups=0(root)"
    
    # uname - system information (Ubuntu kernel)
    if cmd.startswith("uname"):
        if cmd == "uname" or cmd == "uname -s":
            return "Linux"
        elif cmd == "uname -r":
            return "5.15.0-91-generic"
        elif cmd == "uname -n":
            return hostname
        elif cmd == "uname -m":
            return "x86_64"
        elif cmd == "uname -o":
            return "GNU/Linux"
        else:
            # uname -a (all info)
            return f"Linux {hostname} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
    
    # ip a / ip addr - network interface info
    if cmd in ["ip a", "ip addr", "ip address", "ip address show", "ip a show"]:
        return """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 10.0.4.12/24 brd 10.0.4.255 scope global dynamic eth0
       valid_lft 3467sec preferred_lft 3467sec
    inet6 fe80::42:acff:fe11:2/64 scope link 
       valid_lft forever preferred_lft forever"""
    
    # ifconfig - network interface info (legacy)
    if cmd == "ifconfig":
        return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.0.4.12  netmask 255.255.255.0  broadcast 10.0.4.255
        inet6 fe80::42:acff:fe11:2  prefixlen 64  scopeid 0x20<link>
        ether 02:42:ac:11:00:02  txqueuelen 1000  (Ethernet)
        RX packets 1245  bytes 156324 (156.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 987  bytes 98765 (98.7 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0"""
    
    # echo - print arguments
    if cmd.startswith("echo"):
        text = command[5:].strip() if len(command) > 5 else ""
        if text.startswith('"') and text.endswith('"'):
            text = text[1:-1]
        elif text.startswith("'") and text.endswith("'"):
            text = text[1:-1]
        return text
    
    # date - current date/time
    if cmd == "date":
        return "Thu Mar  6 14:23:15 UTC 2026"
    
    # uptime - system uptime
    if cmd == "uptime":
        return " 14:23:15 up 7 days, 3:42,  1 user,  load average: 0.08, 0.12, 0.09"
    
    # Not a built-in command - let response generator handle ls, dir, cat, etc.
    return None


# ── Prompt Rendering ──────────────────────────────────────────────────────────

def render_prompt(hostname: str, working_directory: str) -> str:
    """
    Render a realistic bash prompt.
    
    Format: root@hostname:directory#
    
    Example:
        root@ip-10-0-4-12:~#
        root@ip-10-0-4-12:/home/admin#
    
    Uses ANSI color codes for realism:
        \033[01;32m = Bold Green (username@hostname)
        \033[01;34m = Bold Blue (directory)
        \033[00m = Reset
    """
    # Normalize working directory for display
    if working_directory == "/root":
        display_dir = "~"
    else:
        display_dir = working_directory
    
    # Colored prompt
    prompt = (
        f"\033[01;32mroot@{hostname}\033[00m:"
        f"\033[01;34m{display_dir}\033[00m# "
    )
    
    return prompt


# ── Session Banner Formatter ───────────────────────────────────────────────────

def format_session_welcome(
    peer_ip: str,
    previous_login_timestamp: Optional[datetime] = None,
) -> tuple[str, str]:
    """
    Generate the complete welcome sequence for a new SSH session.
    
    Returns:
        (banner, last_login_message)
    
    The banner contains the Ubuntu welcome and system info.
    The last_login_message shows previous connection info (or initial login).
    """
    hostname = generate_hostname_from_ip(peer_ip)
    banner = generate_ubuntu_banner(hostname)
    
    if previous_login_timestamp:
        # Realistic last login from a previous session
        last_login = f"Last login: {previous_login_timestamp.strftime('%a %b %d %H:%M:%S %Z %Y')} from {peer_ip}"
    else:
        # First login (or simulated first connection)
        current_time = datetime.now(timezone.utc)
        last_login = f"Last login: {current_time.strftime('%a %b %d %H:%M:%S %Z %Y')} from {peer_ip}"
    
    return banner, hostname, last_login
