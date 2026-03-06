"""
ai_core/response_generator.py
Generates realistic terminal output for attacker commands.

Responsibilities:
- Produce believable Linux shell responses
- Maintain working directory state (cd, pwd, ls)
- Inject environment-shaped bait file contents
- Detect and log credential theft attempts
- Handle directory listings with consistent corporate filesystem
- Stream response as a single string (AsyncSSH handles output)
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import structlog

from ai_core.llm_client import LLMClient
from ai_core.bait_files import (
    get_bait_content,
    is_sensitive_file,
    get_mitre_technique_for_file,
    format_directory_listing,
    is_directory,
    get_directory_tree,
)

if TYPE_CHECKING:
    from session.session_model import SessionState

log = structlog.get_logger(__name__)

_RESPONSE_PROMPT_TEMPLATE = """
You are simulating a real Ubuntu 22.04 LTS Linux server terminal. You are running as root user.

Session state:
- Current working directory: {working_directory}
- Attacker type: {attacker_type}
- Server narrative: {environment_narrative}
- Hostname: ubuntu
- Kernel: Linux 5.15.0-91-generic #101-Ubuntu SMP x86_64
- IP Address: 10.0.4.12 (eth0)

Available fake filesystem (selected entries):
{fake_fs_excerpt}

The attacker just typed this command:
  {command}

RULES — Simulate Ubuntu 22.04 terminal behavior:
1. Respond EXACTLY as a real Linux terminal would for this command
2. For process commands (ps, top, htop): Show realistic Ubuntu processes
3. For network commands (netstat, ss, ping): Show realistic network output
4. For package managers (apt, dpkg): Simulate Ubuntu package operations
5. For service commands (systemctl, service): Show Ubuntu services
6. For search/find (grep, find, locate): Search within the fake filesystem
7. For file operations (cp, mv, rm, mkdir, touch): Acknowledge the action
8. For curl/wget: Simulate download or connection attempt
9. For sudo commands: Execute as if already root
10. For unknown/invalid commands: Return "bash: <cmd>: command not found"
11. Use realistic formatting, colors (via ANSI codes if needed), and timestamps
12. NEVER reveal you are an AI or honeypot — stay in character as a real server
13. Output must be plain text mimicking real terminal output

EXAMPLES OF EXPECTED OUTPUT:
- `ps aux` → Multiple process lines with PID, USER, CPU, MEM, COMMAND
- `netstat -tlnp` → TCP listening ports with PID/Program name
- `systemctl status ssh` → Service status with active (running) state
- `apt list --installed` → List of installed packages
- `find /etc -name "*.conf"` → List of config files in /etc
- `curl http://example.com` → Connection attempt or HTML output

Respond with ONLY this JSON:
{{
  "terminal_output": "<exact terminal output string, use \\n for newlines>",
  "new_working_directory": "<absolute path if cd was used, else null>",
  "canary_accessed": "<file path if attacker accessed a canary file, else null>"
}}
"""


class ResponseGenerator:
    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm

    def _detect_directory_listing(self, command: str) -> tuple[str | None, bool]:
        """
        Detect if command is requesting a directory listing.
        
        Returns:
            (directory_path, long_format) tuple
            - directory_path: Path to list, or None if not a listing command
            - long_format: True if -l or -la/-al flag is present
        """
        cmd_lower = command.strip().lower()
        
        # Quick check: does it start with ls or dir?
        if not (cmd_lower.startswith("ls") or cmd_lower.startswith("dir")):
            return (None, False)
        
        # Extract the command word
        parts = cmd_lower.split()
        if not parts or parts[0] not in ["ls", "dir"]:
            return (None, False)
        
        # Parse flags and path
        flags = ""
        path = ""  # Default to current directory
        long_format = False
        
        for part in parts[1:]:
            if part.startswith("-"):
                flags += part
            elif not part.startswith("-"):
                # This is a path
                path = part
                break
        
        # Check for long format flags (-l, -la, -al)
        long_format = "l" in flags.lower()
        
        return (path, long_format)

    def _detect_file_access(self, command: str) -> str | None:
        """
        Detect if command is attempting to read a file.
        Returns the file path if detected, None otherwise.
        
        Patterns: cat, less, more, head, tail, view, strings, grep, etc.
        """
        cmd_lower = command.strip().lower()
        
        # Extract command and arguments
        parts = cmd_lower.split(None, 1)  # Split into command and rest
        if not parts:
            return None
        
        cmd_word = parts[0]
        args = parts[1] if len(parts) > 1 else ""
        
        # Commands that read files
        if cmd_word not in ["cat", "less", "more", "head", "tail", "view", "strings", "grep", "grep"]:
            return None
        
        if not args:
            return None
        
        # For grep: grep "pattern" file
        if cmd_word == "grep":
            # Extract the last word as the filename (simplified)
            arg_parts = args.split()
            if len(arg_parts) >= 2:
                # Assume last part is the file
                file_path = arg_parts[-1].strip("'\"")
                return file_path if file_path and not file_path.startswith("-") else None
        
        # For head/tail: head -n 10 file or head file
        if cmd_word in ["head", "tail"]:
            arg_parts = args.split()
            # Find the filename (not a flag)
            for arg in arg_parts:
                if not arg.startswith("-") and not arg.isdigit():
                    return arg.strip("'\"")
            return None
        
        # For cat, less, more, view, strings: just take first argument
        arg_parts = args.split(None, 1)  # Split first arg from rest
        if arg_parts:
            file_path = arg_parts[0].strip("'\"")
            return file_path if file_path and not file_path.startswith("-") else None
        
        return None

    def _normalize_command(self, command: str) -> tuple[str, list[str], list[str]]:
        """
        Normalize and parse command into components.
        
        Returns:
            (command_word, flags, arguments) tuple
        
        Example:
            "ls -la /etc" → ("ls", ["-l", "-a"], ["/etc"])
        """
        parts = command.strip().split()
        if not parts:
            return ("", [], [])
        
        cmd_word = parts[0].lower()
        flags = []
        arguments = []
        
        for part in parts[1:]:
            if part.startswith("-"):
                # Split combined flags: -la → -l, -a
                if part.startswith("--"):
                    flags.append(part)  # Long flag like --help
                else:
                    for char in part[1:]:
                        flags.append(f"-{char}")
            else:
                arguments.append(part)
        
        return (cmd_word, flags, arguments)

    def _handle_builtin_commands(self, command: str, session_state: "SessionState") -> str | None:
        """
        Handle common Linux builtin commands with deterministic outputs.
        Returns None if not a builtin command, allowing fallback to other handlers.
        
        Commands handled:
        - pwd: Print working directory
        - whoami: Current user (always root in honeypot)
        - uname: System information (Ubuntu 22.04 LTS identity)
        - hostname: Server hostname
        - id: User identity
        - cd: Change directory
        - ip a / ifconfig: Network interface info
        - echo: Print arguments
        - date: Current date/time
        - uptime: System uptime
        """
        cmd = command.strip().lower()
        
        # pwd - print working directory
        if cmd == "pwd":
            return session_state.working_directory
        
        # whoami - current user
        if cmd == "whoami":
            return "root"
        
        # hostname - server hostname
        if cmd == "hostname":
            return "ubuntu"
        
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
                return "ubuntu"
            elif cmd == "uname -m":
                return "x86_64"
            elif cmd == "uname -o":
                return "GNU/Linux"
            else:
                # uname -a (all info)
                return "Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
        
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
            # Extract the text after "echo "
            text = command[5:].strip() if len(command) > 5 else ""
            # Remove quotes if present
            if text.startswith('"') and text.endswith('"'):
                text = text[1:-1]
            elif text.startswith("'") and text.endswith("'"):
                text = text[1:-1]
            return text
        
        # date - current date/time (static for consistency)
        if cmd == "date":
            return "Thu Mar  6 14:23:15 UTC 2026"
        
        # uptime - system uptime
        if cmd == "uptime":
            return " 14:23:15 up 7 days, 3:42,  1 user,  load average: 0.08, 0.12, 0.09"
        
        # cd - change directory (original working directory update logic)
        if cmd.startswith("cd"):
            # Use original command for path extraction (preserve case)
            if command.strip() == "cd" or command.strip() == "cd ~":
                session_state.working_directory = "/root"
                return ""
            
            # Extract target directory
            target = command[2:].strip()
            if not target or target == "~":
                session_state.working_directory = "/root"
                return ""
            
            # Absolute path
            if target.startswith("/"):
                # Check if directory exists in fake_fs
                if is_directory(target):
                    session_state.working_directory = target
                    return ""
                else:
                    return f"bash: cd: {target}: No such file or directory"
            
            # Relative path
            if target == "..":
                # Go up one directory
                if session_state.working_directory == "/":
                    return ""
                parent = "/".join(session_state.working_directory.rstrip("/").split("/")[:-1])
                session_state.working_directory = parent if parent else "/"
                return ""
            
            # Relative subdirectory
            base = session_state.working_directory.rstrip("/")
            new_path = f"{base}/{target}"
            if is_directory(new_path):
                session_state.working_directory = new_path
                return ""
            else:
                return f"bash: cd: {target}: No such file or directory"
        
        # Not a builtin command
        return None

    def _generate_directory_listing(
        self,
        target_dir: str,
        long_format: bool,
        session_state: "SessionState",
    ) -> str:
        """
        Generate a directory listing for ls command.
        Uses bait_files module for consistent corporate filesystem.
        """
        # Normalize directory path
        if target_dir == "~":
            target_dir = "/root"
        elif not target_dir.startswith("/"):
            # Relative path - resolve from working directory
            base = session_state.working_directory.rstrip("/")
            target_dir = f"{base}/{target_dir}".replace("//", "/")
        
        try:
            # Use bait_files function for consistent output
            listing = format_directory_listing(target_dir, long_format)
            if listing:
                return listing
            
            # Empty directory or doesn't exist
            if is_directory(target_dir):
                return ""  # Empty directory
            else:
                return f"ls: cannot access '{target_dir}': No such file or directory"
        
        except Exception as exc:
            log.warning(
                "directory_listing_error",
                session_id=str(session_state.session_id),
                directory=target_dir,
                error=str(exc),
            )
            return f"ls: cannot access '{target_dir}': No such file or directory"

    def _read_file_content(self, file_path: str, session_state: "SessionState") -> str | None:
        """
        Read file content from bait_files.
        Returns None if file not found.
        """
        # Normalize path
        if file_path == "~":
            file_path = "/root"
        elif not file_path.startswith("/"):
            # Relative path - resolve from working directory
            base = session_state.working_directory.rstrip("/")
            file_path = f"{base}/{file_path}".replace("//", "/")
        
        # Try bait_files function
        try:
            content = get_bait_content(file_path)
            if content:
                return content
        except Exception as exc:
            log.debug(f"get_bait_content failed for {file_path}: {exc}")
        
        # File not found
        return None

    async def generate(
        self,
        session_state: "SessionState",
        command: str,
        env_context: dict[str, Any],
    ) -> str:
        """
        Generate a terminal response string for the given command.
        
        Hybrid Command Handling Model:
        
        Priority order (deterministic before LLM):
        1. Built-in commands (pwd, whoami, cd, hostname, uname, id, ip, ifconfig, echo, date, uptime)
        2. Directory listing (ls, dir with flags)
        3. File access (cat, less, more, head, tail, view, strings, grep)
        4. AI pipeline for advanced commands (ps, netstat, systemctl, apt, find, curl, etc.)
        
        Safety: All commands are simulated. Nothing executes on host system.
        Integration: Does not interfere with intent inference, MITRE mapping, threat scoring, or telemetry.
        """
        
        # Normalize command for better parsing
        command = command.strip()
        if not command:
            return ""

        # ── 1. BUILTIN COMMAND HANDLER ─────────────────────────────────────────
        # Handle common Linux commands deterministically
        builtin_output = self._handle_builtin_commands(command, session_state)
        if builtin_output is not None:
            log.info(
                "builtin_command_executed",
                session_id=str(session_state.session_id),
                command=command.split()[0],
            )
            return builtin_output

        # ── 2. DIRECTORY LISTING (ls/dir) ──────────────────────────────────────
        list_path, long_format = self._detect_directory_listing(command)
        if list_path is not None:
            # Use current directory if no path specified
            target_dir = list_path if list_path else session_state.working_directory
            
            try:
                # Generate directory listing
                listing = self._generate_directory_listing(target_dir, long_format, session_state)
                log.info(
                    "directory_listed",
                    session_id=str(session_state.session_id),
                    directory=target_dir,
                    long_format=long_format,
                )
                return listing
            except Exception as exc:
                log.warning(
                    "directory_listing_error",
                    session_id=str(session_state.session_id),
                    directory=target_dir,
                    error=str(exc),
                )
                return f"ls: cannot access '{target_dir}': No such file or directory"

        # ── 3. FILE ACCESS HANDLER (cat, less, more, head, tail, view, strings) ──
        accessed_file = self._detect_file_access(command)
        if accessed_file:
            # Normalize path (handle relative paths)
            if not accessed_file.startswith("/"):
                file_path = f"{session_state.working_directory}/{accessed_file}"
            else:
                file_path = accessed_file
            
            # Clean up path (remove double slashes)
            file_path = file_path.replace("//", "/")
            
            try:
                # Try to read the file
                content = self._read_file_content(file_path, session_state)
                
                if content is not None:
                    # File found and readable
                    log.info(
                        "file_accessed",
                        session_id=str(session_state.session_id),
                        file=file_path,
                        command=command.split()[0],
                    )
                    
                    # Check if this is a sensitive bait file
                    if is_sensitive_file(file_path):
                        mitre_technique = get_mitre_technique_for_file(file_path)
                        log.warning(
                            "credential_file_accessed",
                            session_id=str(session_state.session_id),
                            file=file_path,
                            command=command,
                            mitre_technique=mitre_technique,
                        )
                        
                        # Track canary access
                        if file_path not in session_state.deployed_canaries:
                            session_state.deployed_canaries.append(file_path)
                        
                        # Track credential access event
                        if not hasattr(session_state, 'credential_accesses'):
                            session_state.credential_accesses = []  # type: ignore[attr-defined]
                        
                        session_state.credential_accesses.append({  # type: ignore[attr-defined]
                            "file": file_path,
                            "command": command,
                            "mitre_technique": mitre_technique,
                        })
                    
                    return content
                else:
                    # File not found
                    return f"cat: {file_path}: No such file or directory"
            
            except Exception as exc:
                log.warning(
                    "file_access_error",
                    session_id=str(session_state.session_id),
                    file=file_path,
                    error=str(exc),
                )
                return f"cat: {file_path}: No such file or directory"

        # ── 4. AI PIPELINE FOR UNKNOWN COMMANDS ────────────────────────────────
        # Only route to LLM if the command is not a recognized deterministic type
        
        # Build a short excerpt of fake_fs for the LLM prompt
        fs_items = list(session_state.fake_fs.items())[:10]
        fake_fs_text = "\n".join(
            f"  {path}: {meta.get('content_hint', '')}"
            for path, meta in fs_items
        ) or "  (empty filesystem)"

        prompt = _RESPONSE_PROMPT_TEMPLATE.format(
            working_directory=session_state.working_directory,
            attacker_type=session_state.attacker_type or "unknown",
            environment_narrative=env_context.get(
                "environment_narrative", "Generic Linux server"
            ),
            fake_fs_excerpt=fake_fs_text,
            command=command,
        )

        messages = self._llm.build_messages(session_state.ai_memory, prompt)

        try:
            result = await self._llm.chat(messages, json_mode=True)

            terminal_output: str = result.get("terminal_output", "")
            new_wd: str | None = result.get("new_working_directory")
            canary_accessed: str | None = result.get("canary_accessed")

            # Update working directory if `cd` succeeded
            if new_wd:
                session_state.working_directory = new_wd

            # Flag canary access
            if canary_accessed:
                session_state.deployed_canaries.append(canary_accessed)
                log.warning(
                    "canary_file_accessed",
                    session_id=str(session_state.session_id),
                    file=canary_accessed,
                )

            # Update AI memory with this exchange
            self._llm.append_to_memory(
                session_state.ai_memory, prompt, result.get("terminal_output", "")
            )

            return terminal_output

        except Exception as exc:
            log.warning("response_generation_error", error=str(exc), command=command)
            cmd_name = command.split()[0] if command.split() else command
            return f"bash: {cmd_name}: command not found"
