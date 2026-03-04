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
        )
        # Show a realistic banner
        self._send(
            f"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
            f" * Documentation:  https://help.ubuntu.com\r\n\r\n"
            f"Last login: {datetime.now(timezone.utc).strftime('%a %b %d %H:%M:%S %Z %Y')}\r\n\r\n"
        )
        self._prompt()

    def _send(self, data: str) -> None:
        if self._chan:
            self._chan.write(data)

    def _prompt(self) -> None:
        wd = "~" if self._session_state is None else self._session_state.working_directory
        prompt = f"\033[01;32mroot@ubuntu\033[00m:\033[01;34m{wd}\033[00m# "
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
            elif char == "\x03":  # Ctrl-C
                self._buf = ""
                self._send("^C\r\n")
                self._prompt()
            else:
                self._buf += char
                self._send(char)  # Echo

    async def _handle_command(self, command: str) -> None:
        if self._session_state is None:
            self._prompt()
            return

        sid = self._session_state.session_id
        await self._session_manager.append_command(sid, command)

        try:
            response = await self._interceptor.process(
                session_state=self._session_state,
                command=command,
            )
        except Exception as exc:
            log.warning("command_processing_error", error=str(exc), command=command)
            response = f"bash: {command.split()[0]}: command not found"

        self._send(response.rstrip("\n") + "\r\n")
        self._prompt()

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
