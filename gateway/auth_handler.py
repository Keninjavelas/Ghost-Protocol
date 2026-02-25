"""
gateway/auth_handler.py
Handles SSH authentication for the honeypot.
Always grants access (fake authentication) to engage attackers.
Captures username and password for intelligence logging.
"""
from __future__ import annotations

import structlog

log = structlog.get_logger(__name__)


class GhostAuthHandler:
    """
    AsyncSSH server auth interface.
    All authentication attempts succeed – this is intentional deception.
    Credentials are logged for attribution purposes.
    """

    def __init__(self) -> None:
        self._attempts: list[dict[str, str]] = []

    def validate_password(
        self,
        username: str,
        password: str,
        source_ip: str = "",
    ) -> bool:
        """Accept any username/password pair and log the attempt."""
        log.info(
            "auth_attempt",
            username=username,
            password_length=len(password),
            source_ip=source_ip,
        )
        self._attempts.append(
            {"username": username, "password": password, "source_ip": source_ip}
        )
        # Always return True – fake authentication success
        return True

    def validate_public_key(
        self,
        username: str,
        key_type: str,
        source_ip: str = "",
    ) -> bool:
        """Accept any public key."""
        log.info(
            "auth_pubkey_attempt",
            username=username,
            key_type=key_type,
            source_ip=source_ip,
        )
        return True
