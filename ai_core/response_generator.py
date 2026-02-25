"""
ai_core/response_generator.py
Generates realistic terminal output for attacker commands.

Responsibilities:
- Produce believable Linux shell responses
- Maintain working directory state (cd, pwd, ls)
- Inject environment-shaped bait file contents
- Stream response as a single string (AsyncSSH handles output)
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

from ai_core.llm_client import LLMClient

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

    async def generate(
        self,
        session_state: "SessionState",
        command: str,
        env_context: dict[str, Any],
    ) -> str:
        """Generate a terminal response string for the given command."""

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
