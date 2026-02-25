"""
session/session_model.py
In-memory Session dataclass (runtime state).
The database Session ORM model is in database/models.py.
This class holds transient runtime state not persisted to DB.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class SessionState:
    """Runtime state for an active attacker session."""

    session_id: uuid.UUID
    source_ip: str
    username: str
    start_time: datetime

    # Docker
    container_id: Optional[str] = None

    # Simulated filesystem state
    working_directory: str = "/root"
    fake_fs: dict[str, Any] = field(default_factory=dict)

    # Command history (last N commands sent to AI)
    command_history: list[dict[str, Any]] = field(default_factory=list)

    # AI memory context (list of messages for LLM)
    ai_memory: list[dict[str, str]] = field(default_factory=list)

    # AI-derived profile (updated per command)
    attacker_type: Optional[str] = None
    primary_objective: Optional[str] = None
    sophistication_level: Optional[str] = None
    intent_confidence: float = 0.0

    # Threat scoring
    risk_score: float = 0.0
    threat_level: str = "UNKNOWN"
    likelihood_apt: float = 0.0

    # Canary tracking
    deployed_canaries: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": str(self.session_id),
            "source_ip": self.source_ip,
            "username": self.username,
            "start_time": self.start_time.isoformat(),
            "container_id": self.container_id,
            "working_directory": self.working_directory,
            "attacker_type": self.attacker_type,
            "primary_objective": self.primary_objective,
            "sophistication_level": self.sophistication_level,
            "intent_confidence": self.intent_confidence,
            "risk_score": self.risk_score,
            "threat_level": self.threat_level,
            "likelihood_apt": self.likelihood_apt,
            "command_count": len(self.command_history),
        }
