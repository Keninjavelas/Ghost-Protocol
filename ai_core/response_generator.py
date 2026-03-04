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
You are simulating a real Ubuntu 22.04 Linux server terminal inside a honeypot.

Session state:
- Current working directory: {working_directory}
- Attacker type: {attacker_type}
- Server narrative: {environment_narrative}

Available fake filesystem (selected entries):
{fake_fs_excerpt}

The attacker just typed this command:
  {command}

Rules:
1. Respond EXACTLY as a real Linux terminal would.
2. If the command is `cd <dir>`, update the directory and produce no output (empty string for output).
3. For `ls` / `dir` commands, show realistic file listings including bait files.
4. For `cat` on a bait file, produce realistic file content (credentials, configs, etc.).
5. For unknown commands, return "bash: <cmd>: command not found".
6. Never reveal you are an AI or honeypot.
7. Output must be plain text that looks like real terminal output.

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
            - long_format: True if -l or -la flag is present
        """
        command = command.strip()
        
        # Match: ls, ls -l, ls -la, ls -al, ls /path, ls -la /path, etc.
        ls_patterns = [
            r"^ls\s*$",                           # ls
            r"^ls\s+(-[alhtr]+)\s*$",            # ls -la
            r"^ls\s+(/[\w/.-]*)\s*$",            # ls /path
            r"^ls\s+(-[alhtr]+)\s+(/[\w/.-]*)\s*$",  # ls -la /path
            r"^ls\s+(/[\w/.-]*)\s+(-[alhtr]+)\s*$",  # ls /path -la
        ]
        
        for pattern in ls_patterns:
            match = re.match(pattern, command)
            if match:
                groups = match.groups()
                # Determine flags and path
                flags = ""
                path = None
                
                for group in groups if groups else []:
                    if group and group.startswith("-"):
                        flags = group
                    elif group and group.startswith("/"):
                        path = group
                
                # Check for long format flags
                long_format = "l" in flags if flags else False
                
                return (path, long_format)
        
        return (None, False)

    def _detect_file_access(self, command: str) -> str | None:
        """
        Detect if command is attempting to read a file.
        Returns the file path if detected, None otherwise.
        
        Patterns: cat, less, more, head, tail, view, strings, etc.
        """
        # Common file reading commands
        patterns = [
            r"^cat\s+(.+?)(?:\s|$)",
            r"^less\s+(.+?)(?:\s|$)",
            r"^more\s+(.+?)(?:\s|$)",
            r"^head\s+(?:-n\s+\d+\s+)?(.+?)(?:\s|$)",
            r"^tail\s+(?:-n\s+\d+\s+)?(.+?)(?:\s|$)",
            r"^view\s+(.+?)(?:\s|$)",
            r"^strings\s+(.+?)(?:\s|$)",
            r"^grep\s+.*\s+(.+?)(?:\s|$)",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, command.strip())
            if match:
                file_path = match.group(1).strip()
                # Remove quotes if present
                file_path = file_path.strip('"').strip("'")
                return file_path
        
        return None

    def _handle_builtin_commands(self, command: str, session_state: "SessionState") -> str | None:
        """
        Handle common Linux builtin commands with deterministic outputs.
        Returns None if not a builtin command, allowing fallback to LLM.
        
        Commands handled:
        - pwd: Print working directory
        - whoami: Current user (always root in honeypot)
        - uname -a: System information (Ubuntu 22.04 LTS identity)
        - cd: Change directory (updates session state, returns empty string)
        """
        cmd = command.strip()
        
        # pwd - print working directory
        if cmd == "pwd":
            return session_state.working_directory
        
        # whoami - current user
        if cmd == "whoami":
            return "root"
        
        # uname -a - system information
        if cmd in ["uname -a", "uname"]:
            # Consistent Ubuntu 22.04 LTS server identity
            return "Linux ip-10-0-4-12 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
        
        # cd - change directory
        if cmd.startswith("cd "):
            target = cmd[3:].strip()
            
            # Handle special cases
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
                    return ""  # Already at root
                parent = "/".join(session_state.working_directory.rstrip("/").split("/")[:-1])
                session_state.working_directory = parent if parent else "/"
                return ""
            
            # Relative subdirectory
            new_path = f"{session_state.working_directory.rstrip('/')}/{target}"
            if is_directory(new_path):
                session_state.working_directory = new_path
                return ""
            else:
                return f"bash: cd: {target}: No such file or directory"
        
        # hostname - server hostname
        if cmd == "hostname":
            return "ip-10-0-4-12"
        
        # id - user identity
        if cmd == "id":
            return "uid=0(root) gid=0(root) groups=0(root)"
        
        # Not a builtin command
        return None

    async def generate(
        self,
        session_state: "SessionState",
        command: str,
        env_context: dict[str, Any],
    ) -> str:
        """Generate a terminal response string for the given command."""

        # ── Builtin Command Handler ───────────────────────────────────────────
        # Handle common Linux commands deterministically for demo reliability
        builtin_output = self._handle_builtin_commands(command, session_state)
        if builtin_output is not None:
            log.debug(
                "builtin_command_handled",
                session_id=str(session_state.session_id),
                command=command,
            )
            return builtin_output

        # ── Directory Listing Detection ────────────────────────────────────────
        # Handle ls commands with consistent filesystem display for demo reliability
        list_path, long_format = self._detect_directory_listing(command)
        if list_path is not None:
            # Use current directory if no path specified
            target_dir = list_path if list_path else session_state.working_directory
            
            # Generate directory listing
            listing = format_directory_listing(target_dir, long_format)
            
            if listing:
                log.info(
                    "directory_listed",
                    session_id=str(session_state.session_id),
                    directory=target_dir,
                    long_format=long_format,
                )
                return listing
            else:
                # Empty directory or doesn't exist
                if is_directory(target_dir):
                    return ""  # Empty directory
                else:
                    return f"ls: cannot access '{target_dir}': No such file or directory"

        # ── Credential Theft Trap Detection ────────────────────────────────────
        # Detect if attacker is trying to read a sensitive file
        accessed_file = self._detect_file_access(command)
        credential_access_detected = False
        mitre_technique = None
        
        if accessed_file:
            # Normalize path (handle relative paths in simple way)
            if not accessed_file.startswith("/"):
                accessed_file = f"{session_state.working_directory}/{accessed_file}"
            
            # Check if this is a sensitive bait file
            if is_sensitive_file(accessed_file):
                credential_access_detected = True
                mitre_technique = get_mitre_technique_for_file(accessed_file)
                
                log.warning(
                    "credential_file_accessed",
                    session_id=str(session_state.session_id),
                    file=accessed_file,
                    command=command,
                    mitre_technique=mitre_technique,
                )
                
                # Return realistic bait content directly (bypass LLM for consistency)
                bait_content = get_bait_content(accessed_file)
                if bait_content:
                    # Mark canary as accessed for tracking
                    if accessed_file not in session_state.deployed_canaries:
                        session_state.deployed_canaries.append(accessed_file)
                    
                    # Store credential access event in session state for telemetry
                    if not hasattr(session_state, 'credential_accesses'):
                        session_state.credential_accesses = []  # type: ignore[attr-defined]
                    
                    session_state.credential_accesses.append({  # type: ignore[attr-defined]
                        "file": accessed_file,
                        "command": command,
                        "mitre_technique": mitre_technique,
                    })
                    
                    return bait_content

        # ── Standard LLM Response Generation ───────────────────────────────────

        # Build a short excerpt of fake_fs for the prompt
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
