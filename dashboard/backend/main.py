"""
dashboard/backend/main.py
FastAPI application entrypoint for the Ghost Protocol dashboard.

Wires together:
  - Lifespan: DB init, service instantiation
  - Beacon router (/beacon/*)
  - Dashboard router (/sessions, /session/{id}, /mitre/{id}, /threat/{id}, /beacons, /report/{id})
  - WebSocket hub (/ws) for real-time event streaming
  - StaticFiles serving the frontend SPA at /static
  - CORS middleware for frontend
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from pathlib import Path

import structlog
import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from config.settings import settings
from database.db import close_db, init_db
from sandbox.docker_manager import DockerManager
from session.session_manager import SessionManager
from telemetry.logger import TelemetryLogger, configure_logging
from tracking.canary_manager import CanaryManager
from tracking.beacon_listener import create_beacon_router
from dashboard.backend.routes import create_dashboard_router
from dashboard.backend.websocket import ConnectionManager, create_ws_router

from ai_core.llm_client import LLMClient
from ai_core.intent_inference import IntentInferenceEngine
from ai_core.environment_shaper import EnvironmentShaper
from ai_core.mitre_mapper import MitreMapper
from ai_core.threat_scorer import ThreatScorer
from ai_core.response_generator import ResponseGenerator
from ai_core.report_generator import ReportGenerator
from interception.command_interceptor import CommandInterceptor

log = structlog.get_logger(__name__)

# ── Shared services (module-level for lifespan access) ─────────────────────────
_docker_mgr: DockerManager | None = None
_session_mgr: SessionManager | None = None
_telemetry: TelemetryLogger | None = None
_canary_mgr: CanaryManager | None = None
_ws_manager: ConnectionManager | None = None

_FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup / shutdown lifecycle."""
    global _docker_mgr, _session_mgr, _telemetry, _canary_mgr, _ws_manager

    configure_logging()
    log.info("ghost_dashboard_starting")

    await init_db()

    _docker_mgr = DockerManager()
    _telemetry = TelemetryLogger()
    _canary_mgr = CanaryManager()
    _session_mgr = SessionManager(docker_manager=_docker_mgr)
    _ws_manager = ConnectionManager()

    # Wire up AI core
    llm = LLMClient()
    interceptor = CommandInterceptor(
        session_manager=_session_mgr,
        llm_client=llm,
        intent_engine=IntentInferenceEngine(llm),
        env_shaper=EnvironmentShaper(llm),
        mitre_mapper=MitreMapper(llm),
        threat_scorer=ThreatScorer(),
        response_generator=ResponseGenerator(llm),
        report_generator=ReportGenerator(llm),
        telemetry=_telemetry,
    )

    # Attach services to app state
    app.state.session_manager = _session_mgr
    app.state.interceptor = interceptor
    app.state.telemetry = _telemetry
    app.state.canary_manager = _canary_mgr
    app.state.ws_manager = _ws_manager

    log.info("ghost_dashboard_ready", port=settings.DASHBOARD_PORT)
    yield

    # ── Shutdown ───────────────────────────────────────────────────────────────
    log.info("ghost_dashboard_shutting_down")
    await close_db()
    if _docker_mgr:
        _docker_mgr.close()


# ── Application ────────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="Ghost Protocol – AI Deception & Attribution Engine",
        description="Live SOC dashboard — built by Team A.S.E.A.",
        version="1.0.0",
        lifespan=lifespan,
    )

    # CORS – allow frontend (adjust origins in production)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Deferred router registration (services available after lifespan starts)
    @app.on_event("startup")
    async def register_routes() -> None:
        assert _session_mgr is not None
        assert _telemetry is not None
        assert _canary_mgr is not None
        assert _ws_manager is not None

        app.include_router(create_beacon_router(_canary_mgr, _telemetry))
        app.include_router(create_dashboard_router(_session_mgr, _ws_manager))
        app.include_router(create_ws_router(_ws_manager))

    @app.get("/health", tags=["meta"])
    async def health() -> dict:
        return {"status": "ok", "service": "ghost-protocol-dashboard"}

    @app.get("/", include_in_schema=False)
    async def serve_dashboard() -> FileResponse:
        """Serve the frontend SPA."""
        return FileResponse(str(_FRONTEND_DIR / "index.html"))

    # Mount static assets AFTER all API routes so they don't shadow them
    if _FRONTEND_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_FRONTEND_DIR)), name="static")

    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "dashboard.backend.main:app",
        host=settings.DASHBOARD_HOST,
        port=settings.DASHBOARD_PORT,
        reload=settings.DASHBOARD_RELOAD,
        log_config=None,  # structlog handles logging
    )
