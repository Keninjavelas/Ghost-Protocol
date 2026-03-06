"""
config/settings.py
Central configuration loaded from environment variables.
No hardcoded secrets – all sensitive values come from .env or environment.
"""
from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── SSH Gateway ──────────────────────────────────────────────────────────
    SSH_HOST: str = Field(default="0.0.0.0", description="SSH bind address")
    SSH_PORT: int = Field(default=2222, description="SSH listen port")
    SSH_HOST_KEY_PATH: str = Field(
        default="./config/ssh_host_rsa_key",
        description="Path to RSA host key file",
    )

    # ── PostgreSQL ───────────────────────────────────────────────────────────
    POSTGRES_USER: str = Field(default="ghost")
    POSTGRES_PASSWORD: str = Field(default="ghostpass")
    POSTGRES_DB: str = Field(default="ghost_db")
    POSTGRES_HOST: str = Field(default="localhost")
    POSTGRES_PORT: int = Field(default=5433, description="PostgreSQL port (5433 for Docker, 5432 for local)")

    @property
    def DATABASE_URL(self) -> str:  # noqa: N802
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def DATABASE_URL_SYNC(self) -> str:  # noqa: N802
        return (
            f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # ── Redis ────────────────────────────────────────────────────────────────
    REDIS_HOST: str = Field(default="localhost")
    REDIS_PORT: int = Field(default=6379)
    REDIS_DB: int = Field(default=0)

    @property
    def REDIS_URL(self) -> str:  # noqa: N802
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    # ── Local LLM (Ollama) ────────────────────────────────────────────────────
    OLLAMA_BASE_URL: str = Field(
        default="http://localhost:11434/v1",
        description="Ollama OpenAI-compatible endpoint",
    )
    OLLAMA_MODEL: str = Field(
        default="llama3",
        description="Local Ollama model name (e.g. llama3, llama3.1, mistral)",
    )
    LLM_MAX_TOKENS: int = Field(default=1024)
    LLM_TEMPERATURE: float = Field(default=0.2)
    LLM_CONTEXT_WINDOW: int = Field(default=20, description="Commands kept in memory")

    # ── Docker Sandbox ────────────────────────────────────────────────────────
    SANDBOX_IMAGE: str = Field(
        default="ubuntu:22.04", description="Base Docker image for sandbox"
    )
    SANDBOX_CPU_QUOTA: int = Field(default=50000, description="CPU quota (microseconds)")
    SANDBOX_MEM_LIMIT: str = Field(default="256m", description="Memory limit per container")
    SANDBOX_NETWORK: str = Field(default="none", description="Docker network mode")
    SANDBOX_AUTO_REMOVE: bool = Field(default=True)

    # ── Dashboard ─────────────────────────────────────────────────────────────
    DASHBOARD_HOST: str = Field(default="0.0.0.0")
    DASHBOARD_PORT: int = Field(default=8000)
    DASHBOARD_RELOAD: bool = Field(default=False)

    # ── Beacon / Canary ───────────────────────────────────────────────────────
    BEACON_BASE_URL: str = Field(
        default="http://localhost:8000/beacon",
        description="HTTP base URL injected into canary tokens",
    )

    # ── Logging ───────────────────────────────────────────────────────────────
    LOG_LEVEL: str = Field(default="INFO")
    LOG_JSON: bool = Field(default=True, description="Emit structured JSON logs")

    # ── Resilience (Network Seizure Defense) ──────────────────────────────────
    CACHE_DIR: str = Field(
        default="/var/ghost_protocol/cache",
        description="Directory for encrypted offline cache"
    )
    HEARTBEAT_INTERVAL_SECONDS: float = Field(
        default=30.0,
        description="Expected time between heartbeats"
    )
    HEARTBEAT_FAILURE_THRESHOLD: int = Field(
        default=4,
        description="Consecutive failures before network seizure detection"
    )
    NETWORK_BASELINE_WINDOW_SECONDS: int = Field(
        default=300,
        description="Time window for network baseline calculation"
    )
    NETWORK_ANOMALY_THRESHOLD: float = Field(
        default=2.5,
        description="Multiplier for anomaly detection (e.g., 2.5x baseline)"
    )
    SYSLOG_ALERTS_ENABLED: bool = Field(
        default=True,
        description="Enable syslog alerting"
    )
    EXTERNAL_MONITOR_URL: Optional[str] = Field(
        default=None,
        description="External monitoring service URL for out-of-band alerts"
    )


# Singleton – import this everywhere
settings = Settings()
