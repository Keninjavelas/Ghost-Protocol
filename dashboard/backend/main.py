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

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator

from pathlib import Path

import asyncssh
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
from gateway.ssh_server import GhostSSHServer

log = structlog.get_logger(__name__)

# ── Shared services (module-level for lifespan access) ─────────────────────────
_docker_mgr: DockerManager | None = None
_session_mgr: SessionManager | None = None
_telemetry: TelemetryLogger | None = None
_canary_mgr: CanaryManager | None = None
_ws_manager: ConnectionManager | None = None
_ssh_server_handle: asyncio.Task | None = None

_FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup / shutdown lifecycle."""
    global _docker_mgr, _session_mgr, _telemetry, _canary_mgr, _ws_manager, _ssh_server_handle

    configure_logging()
    log.info("ghost_dashboard_starting")

    await init_db()

    _docker_mgr = DockerManager()
    _telemetry = TelemetryLogger()
    _canary_mgr = CanaryManager()
    _ws_manager = ConnectionManager()

    # Wire up AI core
    llm = LLMClient()
    report_gen = ReportGenerator(llm)
    
    _session_mgr = SessionManager(
        docker_manager=_docker_mgr,
        report_generator=report_gen,
        ws_manager=_ws_manager,
    )
    
    interceptor = CommandInterceptor(
        session_manager=_session_mgr,
        llm_client=llm,
        intent_engine=IntentInferenceEngine(llm),
        env_shaper=EnvironmentShaper(llm),
        mitre_mapper=MitreMapper(llm),
        threat_scorer=ThreatScorer(),
        response_generator=ResponseGenerator(llm),
        report_generator=report_gen,
        telemetry=_telemetry,
        ws_manager=_ws_manager,
    )

    # Attach services to app state
    app.state.session_manager = _session_mgr
    app.state.interceptor = interceptor
    app.state.telemetry = _telemetry
    app.state.canary_manager = _canary_mgr
    app.state.ws_manager = _ws_manager

    # ── Validate Service Health ───────────────────────────────────────────
    # Database health check
    try:
        from sqlalchemy import text
        from database.db import get_session
        async with get_session() as db:
            await db.execute(text("SELECT 1"))
        log.info("database_health_check_passed")
    except Exception as e:
        log.critical("database_health_check_failed", error=str(e))
        raise RuntimeError(f"Database connection failed: {e}")
    
    # LLM health check
    try:
        test_messages = [{"role": "system", "content": "Test"}, {"role": "user", "content": "Respond with OK"}]
        await llm.chat(test_messages, json_mode=False, max_tokens=10)
        log.info("llm_health_check_passed", model=settings.OLLAMA_MODEL)
    except Exception as e:
        log.critical("llm_health_check_failed", error=str(e), model=settings.OLLAMA_MODEL)
        log.warning("continuing_without_llm_validation", warning="Ollama might not be running")
    
    # Start SSH server in background
    def ssh_server_factory() -> GhostSSHServer:
        return GhostSSHServer(
            session_manager=_session_mgr,
            interceptor=interceptor,
            telemetry=_telemetry,
        )

    try:
        await asyncssh.create_server(
            ssh_server_factory,
            host=settings.SSH_HOST,
            port=settings.SSH_PORT,
            server_host_keys=[settings.SSH_HOST_KEY_PATH],
            encoding="utf-8",
        )
        log.info("ssh_honeypot_ready", host=settings.SSH_HOST, port=settings.SSH_PORT)
    except Exception as e:
        log.critical("ssh_server_startup_failed", error=str(e))
        raise RuntimeError(f"SSH server failed to start: {e}")

    # Start resilience monitoring
    try:
        await _session_mgr.start_resilience()
        log.info("resilience_monitoring_activated")
    except Exception as e:
        log.warning("resilience_startup_failed", error=str(e))

    log.info("ghost_dashboard_ready", port=settings.DASHBOARD_PORT)
    yield

    # ── Shutdown ───────────────────────────────────────────────────────────────
    log.info("ghost_dashboard_shutting_down")
    
    # Stop resilience monitoring
    try:
        await _session_mgr.stop_resilience()
        log.info("resilience_monitoring_stopped")
    except Exception as e:
        log.warning("resilience_shutdown_failed", error=str(e))
    
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

    # ── Resilience API Endpoints ───────────────────────────────────────────────

    @app.post("/heartbeat", tags=["resilience"])
    async def heartbeat() -> dict:
        """Record heartbeat from dashboard frontend."""
        if _session_mgr:
            _session_mgr.record_heartbeat()
        return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

    @app.get("/network-status", tags=["resilience"])
    async def network_status() -> dict:
        """Check network seizure detection status and anomalies."""
        if not _session_mgr:
            return {"error": "session_manager_not_initialized"}
        
        anomalies = _session_mgr.detect_network_anomalies()
        return {
            "network_seized": _session_mgr.is_network_seized,
            "anomalies": anomalies,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    @app.get("/cached-reports", tags=["resilience"])
    async def list_cached_reports() -> dict:
        """List all offline-cached session reports."""
        if not _session_mgr:
            return {"error": "session_manager_not_initialized"}
        
        cached_ids = _session_mgr.list_cached_reports()
        return {
            "cached_reports": cached_ids,
            "count": len(cached_ids)
        }

    @app.get("/cached-report/{session_id}", tags=["resilience"])
    async def get_cached_report(session_id: str) -> dict:
        """Retrieve a specific offline-cached report."""
        if not _session_mgr:
            return {"error": "session_manager_not_initialized"}
        
        report = _session_mgr.get_cached_report(session_id)
        if report is None:
            return {"error": "report_not_found", "session_id": session_id}
        
        return report

    @app.get("/health", tags=["meta"])
    async def health() -> dict:
        """Comprehensive health check endpoint for monitoring and startup validation."""
        health_status = {
            "status": "healthy",
            "service": "ghost-protocol-dashboard",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "services": {}
        }
        
        # Check database
        try:
            from sqlalchemy import text
            from database.db import get_session
            async with get_session() as db:
                await db.execute(text("SELECT 1"))
            health_status["services"]["database"] = "ok"
        except Exception as e:
            health_status["services"]["database"] = f"error: {str(e)[:100]}"
            health_status["status"] = "degraded"
        
        # Check SSH server
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((settings.SSH_HOST or "localhost", settings.SSH_PORT))
            sock.close()
            health_status["services"]["ssh_honeypot"] = "listening" if result == 0 else "not_listening"
            if result != 0:
                health_status["status"] = "degraded"
        except Exception as e:
            health_status["services"]["ssh_honeypot"] = f"error: {str(e)[:100]}"
            health_status["status"] = "degraded"
        
        # Check WebSocket manager
        health_status["services"]["websocket"] = "ok" if _ws_manager else "not_initialized"
        if not _ws_manager:
            health_status["status"] = "degraded"
        
        # Check session manager
        health_status["services"]["session_manager"] = "ok" if _session_mgr else "not_initialized"
        if not _session_mgr:
            health_status["status"] = "degraded"
        
        return health_status

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> dict:
        """Suppress favicon 404 errors."""
        return {}

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
