"""
tracking/canary_manager.py
Creates and manages canary tokens embedded in honeypot bait files.

Each canary token is a unique URL-based identifier.
When an attacker retrieves/accesses a bait file containing the token,
the beacon_listener endpoint receives a callback and logs the event.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional

import structlog

from config.settings import settings

log = structlog.get_logger(__name__)


class CanaryManager:
    """Manages canary tokens: generates, embeds, tracks per session."""

    def __init__(self) -> None:
        # token_id → session_id + metadata
        self._tokens: dict[str, dict] = {}

    def generate_token(self, session_id: uuid.UUID, file_path: str) -> str:
        """
        Create a unique canary token and return the tracking URL.
        The URL is embedded into the bait file content by the ResponseGenerator.
        """
        token_id = secrets.token_urlsafe(16)
        track_url = f"{settings.BEACON_BASE_URL}/{token_id}"

        self._tokens[token_id] = {
            "session_id": str(session_id),
            "file_path": file_path,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "triggered": False,
        }

        log.info(
            "canary_created",
            token_id=token_id,
            session_id=str(session_id),
            file_path=file_path,
            track_url=track_url,
        )
        return track_url

    def get_token_meta(self, token_id: str) -> Optional[dict]:
        return self._tokens.get(token_id)

    def mark_triggered(self, token_id: str, triggered_ip: str) -> Optional[str]:
        """
        Mark a token as triggered.
        Returns the associated session_id or None if token unknown.
        """
        meta = self._tokens.get(token_id)
        if not meta:
            log.warning("canary_unknown_token", token_id=token_id)
            return None

        meta["triggered"] = True
        meta["triggered_ip"] = triggered_ip
        meta["triggered_at"] = datetime.now(timezone.utc).isoformat()

        log.warning(
            "canary_triggered",
            token_id=token_id,
            session_id=meta["session_id"],
            triggered_ip=triggered_ip,
        )
        return meta["session_id"]

    def list_tokens(self, session_id: Optional[uuid.UUID] = None) -> list[dict]:
        """Return all tokens, optionally filtered by session_id."""
        tokens = list(self._tokens.items())
        if session_id:
            sid_str = str(session_id)
            tokens = [(k, v) for k, v in tokens if v["session_id"] == sid_str]
        return [{"token_id": k, **v} for k, v in tokens]
