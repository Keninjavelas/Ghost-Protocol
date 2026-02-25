"""
database/models.py
SQLAlchemy ORM models for all Ghost Protocol tables.
Tables: sessions, commands, mitre_mappings, beacon_events, reports
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    username: Mapped[str] = mapped_column(String(128), nullable=False, default="root")
    start_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    end_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    threat_level: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    attacker_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    primary_objective: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    sophistication_level: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | closed

    commands: Mapped[list["Command"]] = relationship(
        "Command", back_populates="session", cascade="all, delete-orphan"
    )
    mitre_mappings: Mapped[list["MitreMapping"]] = relationship(
        "MitreMapping", back_populates="session", cascade="all, delete-orphan"
    )
    beacon_events: Mapped[list["BeaconEvent"]] = relationship(
        "BeaconEvent", back_populates="session", cascade="all, delete-orphan"
    )
    report: Mapped[Optional["Report"]] = relationship(
        "Report", back_populates="session", uselist=False, cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Session id={self.id} ip={self.source_ip} status={self.status}>"


class Command(Base):
    __tablename__ = "commands"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False
    )
    command: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    ai_classification: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    session: Mapped["Session"] = relationship("Session", back_populates="commands")

    def __repr__(self) -> str:
        return f"<Command id={self.id} cmd={self.command[:40]!r}>"


class MitreMapping(Base):
    __tablename__ = "mitre_mappings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False
    )
    technique_id: Mapped[str] = mapped_column(String(32), nullable=False)
    technique_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    tactic: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    session: Mapped["Session"] = relationship("Session", back_populates="mitre_mappings")

    def __repr__(self) -> str:
        return f"<MitreMapping {self.technique_id} tactic={self.tactic}>"


class BeaconEvent(Base):
    __tablename__ = "beacon_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False
    )
    token_id: Mapped[str] = mapped_column(String(64), nullable=False)
    triggered_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    triggered_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    session: Mapped["Session"] = relationship("Session", back_populates="beacon_events")

    def __repr__(self) -> str:
        return f"<BeaconEvent token={self.token_id} ip={self.triggered_ip}>"


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    report_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    session: Mapped["Session"] = relationship("Session", back_populates="report")

    def __repr__(self) -> str:
        return f"<Report session={self.session_id}>"
