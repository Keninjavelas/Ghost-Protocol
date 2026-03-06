"""
gateway/ssh_server.py
Async SSH honeypot server built with AsyncSSH.

Flow:
  Attacker connects → GhostSSHServer handles auth (always succeeds)
  → GhostSSHSession receives commands
  → Routes to CommandInterceptor → AI Core → returns response
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional

import asyncssh
import structlog

from config.settings import settings
from database.db import close_db, init_db
from gateway.ssh_presentation import (
    generate_hostname_from_ip,
    generate_ubuntu_banner,
    format_last_login,
    handle_builtin_command,
    render_prompt,
)
from interception.command_interceptor import CommandInterceptor
from sandbox.docker_manager import DockerManager
from session.session_manager import SessionManager
from telemetry.logger import TelemetryLogger

log = structlog.get_logger(__name__)


# ── Per-connection SSH session ─────────────────────────────────────────────────

class GhostSSHSession(asyncssh.SSHServerSession):   # type: ignore[misc]
    """
    Handles one attacker connection.
    Each command typed by the attacker is intercepted and routed to the AI.
    
    Presents a realistic Ubuntu 22.04 SSH experience with:
      - Authentic login banner with system information
      - Realistic hostname (e.g., ip-10-0-4-12)
      - Last login tracking
      - Accurate prompt rendering (root@hostname:path#)
      - Built-in command support (whoami, hostname, pwd, uname -a)
    """

    def __init__(
        self,
        session_manager: SessionManager,
        interceptor: CommandInterceptor,
        telemetry: TelemetryLogger,
        peer_ip: str,
        username: str,
    ) -> None:
        self._session_manager = session_manager
        self._interceptor = interceptor
        self._telemetry = telemetry
        self._peer_ip = peer_ip
        self._username = username

        self._session_state = None
        self._chan: Optional[asyncssh.SSHServerChannel] = None
        self._buf: str = ""
        self._loop = asyncio.get_event_loop()
        
        # SSH presentation state
        self._hostname = generate_hostname_from_ip(peer_ip)
        self._login_time = datetime.now(timezone.utc)

    def shell_requested(self) -> bool:
        """Accept the attacker's shell request."""
        return True

    def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:
        self._chan = chan
        self._loop.create_task(self._start_session())

    async def _start_session(self) -> None:
        self._session_state = await self._session_manager.create_session(
            source_ip=self._peer_ip,
            username=self._username,
        )
        log.info(
            "ssh_session_started",
            session_id=str(self._session_state.session_id),
            peer_ip=self._peer_ip,
            hostname=self._hostname,
        )
        
        # Display Ubuntu login banner
        banner = generate_ubuntu_banner(self._hostname)
        self._send(banner)
        
        # Display last login message
        last_login = format_last_login(self._peer_ip)
        self._send(last_login + "\r\n\r\n")
        
        # Show initial prompt
        self._prompt()

    def _send(self, data: str) -> None:
        if self._chan:
            self._chan.write(data)

    def _prompt(self) -> None:
        """Render and display the shell prompt with hostname and working directory."""
        wd = "~" if self._session_state is None else self._session_state.working_directory
        prompt = render_prompt(self._hostname, wd)
        self._send(prompt)

    def data_received(self, data: str, datatype: object) -> None:
        """Called for every keystroke/paste from the attacker."""
        for char in data:
            if char in ("\r", "\n"):
                self._send("\r\n")
                command = self._buf.strip()
                self._buf = ""
                if command:
                    self._loop.create_task(self._handle_command(command))
                else:
                    self._prompt()
            elif char == "\x7f":  # Backspace
                if self._buf:
                    self._buf = self._buf[:-1]
                    self._send("\b \b")
            elif char == "\x04":  # Ctrl-D (EOF)
                if not self._buf:
                    self._send("logout\r\n")
                    self._loop.create_task(self._close_and_exit())
                    return
            elif char == "\x03":  # Ctrl-C
                self._buf = ""
                self._send("^C\r\n")
                self._prompt()
            else:
                self._buf += char
                self._send(char)  # Echo

    _EXIT_COMMANDS = {"exit", "quit", "logout", "bye", "disconnect"}

    async def _handle_command(self, command: str) -> None:
        if self._session_state is None:
            self._prompt()
            return

        sid = self._session_state.session_id

        # ── Handle exit / quit / logout ────────────────────────────────────────
        if command.strip().lower() in self._EXIT_COMMANDS:
            log.info("attacker_exit_requested", session_id=str(sid), command=command)
            try:
                await self._session_manager.append_command(sid, command)
            except Exception:
                pass
            self._send("logout\r\n")
            await self._end_session()
            if self._chan:
                self._chan.close()
            return

        try:
            await self._session_manager.append_command(sid, command)
        except Exception as exc:
            log.warning("command_append_failed", error=str(exc), session_id=str(sid))

        # Check for built-in commands (whoami, hostname, pwd, uname -a)
        builtin_response = handle_builtin_command(
            command,
            self._hostname,
            self._session_state.working_directory,
        )
        
        if builtin_response is not None:
            # Built-in command: return immediately without AI processing
            log.info(
                "builtin_command_executed",
                session_id=str(sid),
                command=command,
                hostname=self._hostname,
            )
            self._send(builtin_response.rstrip("\n") + "\r\n")
            self._prompt()
            return

        # Route to AI pipeline for intelligent response
        try:
            response = await self._interceptor.process(
                session_state=self._session_state,
                command=command,
            )
        except Exception as exc:
            log.error(
                "command_processing_error",
                error=str(exc),
                error_type=type(exc).__name__,
                command=command,
                session_id=str(sid),
            )
            # Provide graceful fallback
            cmd_name = command.split()[0] if command.split() else "command"
            response = f"bash: {cmd_name}: command not found"

        self._send(response.rstrip("\n") + "\r\n")
        self._prompt()

    async def _close_and_exit(self) -> None:
        """Handle Ctrl-D: end session and close channel."""
        await self._end_session()
        if self._chan:
            self._chan.close()

    def eof_received(self) -> None:
        self._loop.create_task(self._end_session())

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self._loop.create_task(self._end_session())

    async def _end_session(self) -> None:
        if self._session_state is None:
            return
        sid = self._session_state.session_id
        log.info("ssh_session_ending", session_id=str(sid))
        await self._session_manager.close_session(sid)
        self._session_state = None


# ── AsyncSSH server factory ────────────────────────────────────────────────────

class GhostSSHServer(asyncssh.SSHServer):   # type: ignore[misc]
    """One instance per incoming connection."""

    def __init__(
        self,
        session_manager: SessionManager,
        interceptor: CommandInterceptor,
        telemetry: TelemetryLogger,
    ) -> None:
        self._session_manager = session_manager
        self._interceptor = interceptor
        self._telemetry = telemetry
        self._peer_ip: str = "0.0.0.0"
        self._username: str = "root"

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername")
        self._peer_ip = peer[0] if peer else "0.0.0.0"
        log.info("ssh_connection_accepted", peer_ip=self._peer_ip)

    def begin_auth(self, username: str) -> bool:
        self._username = username
        return True  # Require auth step so we can capture credentials

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        log.info(
            "auth_password",
            username=username,
            pw_len=len(password),
            ip=self._peer_ip,
        )
        return True  # Always accept

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:  # type: ignore[override]
        log.info("auth_pubkey", username=username, ip=self._peer_ip)
        return True

    def session_requested(self) -> GhostSSHSession:
        return GhostSSHSession(
            session_manager=self._session_manager,
            interceptor=self._interceptor,
            telemetry=self._telemetry,
            peer_ip=self._peer_ip,
            username=self._username,
        )


# ── Entrypoint ─────────────────────────────────────────────────────────────────

async def main() -> None:
    from telemetry.logger import configure_logging
    configure_logging()

    await init_db()

    docker_mgr = DockerManager()
    telemetry = TelemetryLogger()

    from ai_core.llm_client import LLMClient
    from ai_core.intent_inference import IntentInferenceEngine
    from ai_core.environment_shaper import EnvironmentShaper
    from ai_core.mitre_mapper import MitreMapper
    from ai_core.threat_scorer import ThreatScorer
    from ai_core.response_generator import ResponseGenerator
    from ai_core.report_generator import ReportGenerator

    llm = LLMClient()
    report_gen = ReportGenerator(llm)
    
    # SSH server runs standalone without WebSocket
    session_mgr = SessionManager(
        docker_manager=docker_mgr,
        report_generator=report_gen,
        ws_manager=None,
    )
    
    interceptor = CommandInterceptor(
        session_manager=session_mgr,
        llm_client=llm,
        intent_engine=IntentInferenceEngine(llm),
        env_shaper=EnvironmentShaper(llm),
        mitre_mapper=MitreMapper(llm),
        threat_scorer=ThreatScorer(),
        response_generator=ResponseGenerator(llm),
        report_generator=report_gen,
        telemetry=telemetry,
        ws_manager=None,  # SSH server runs standalone without WebSocket
    )

    def server_factory() -> GhostSSHServer:
        return GhostSSHServer(
            session_manager=session_mgr,
            interceptor=interceptor,
            telemetry=telemetry,
        )

    log.info(
        "ssh_server_starting",
        host=settings.SSH_HOST,
        port=settings.SSH_PORT,
    )

    await asyncssh.create_server(
        server_factory,
        host=settings.SSH_HOST,
        port=settings.SSH_PORT,
        server_host_keys=[settings.SSH_HOST_KEY_PATH],
        encoding="utf-8",
    )

    log.info("ssh_server_ready", port=settings.SSH_PORT)

    try:
        await asyncio.Future()  # Run forever
    except (KeyboardInterrupt, asyncio.CancelledError):
        log.info("shutting_down")
    finally:
        await close_db()
        docker_mgr.close()


if __name__ == "__main__":
    asyncio.run(main())
