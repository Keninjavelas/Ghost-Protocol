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
from typing import Any, AsyncGenerator

from pathlib import Path

import asyncssh
import structlog
import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import Response

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

# ── Detection System ─────────────────────────────────────────────────────────
from detection_orchestrator import DetectionOrchestrator
import detection_api
from threat_websocket import websocket_handler

# ── Optional Security Systems ────────────────────────────────────────────────
# Imported lazily at runtime so core dashboard can start without optional deps.

log = structlog.get_logger(__name__)

# ── Shared services (module-level for lifespan access) ─────────────────────────
_docker_mgr: DockerManager | None = None
_session_mgr: SessionManager | None = None
_telemetry: TelemetryLogger | None = None
_canary_mgr: CanaryManager | None = None
_ws_manager: ConnectionManager | None = None
_detection_orchestrator: DetectionOrchestrator | None = None
_network_defense: Any | None = None
_vpn_security: Any | None = None
_ssh_server_handle: asyncio.Task | None = None

_FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


# ── Custom StaticFiles with Cache-Busting Headers ──────────────────────────────
class NoCacheStaticFiles(StaticFiles):
    """StaticFiles subclass that adds cache-busting headers to all responses."""
    
    async def get_response(self, path: str, scope) -> Response:
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response


# ── Network Defense Callbacks ──────────────────────────────────────────────────
async def _network_defense_alert_callback(alert_data: dict) -> None:
    """Callback for network defense alerts to broadcast to dashboard."""
    if _ws_manager:
        await _ws_manager.broadcast(alert_data)


def _create_network_defense_system() -> Any:
    """Create network defense instance with lazy import of optional deps."""
    from network_defense import NetworkDefenseSystem

    return NetworkDefenseSystem(
        interface=settings.NETWORK_INTERFACE,
        enable_ml=settings.NETWORK_DEFENSE_ML_ENABLED,
        ml_model_path=settings.NETWORK_DEFENSE_ML_MODEL_PATH,
        enable_automated_response=settings.NETWORK_DEFENSE_AUTOMATED_RESPONSE,
        response_dry_run=settings.NETWORK_DEFENSE_RESPONSE_DRY_RUN,
        dashboard_callback=_network_defense_alert_callback,
        alert_webhook_url=settings.NETWORK_DEFENSE_ALERT_WEBHOOK,
        log_dir=settings.NETWORK_DEFENSE_LOG_DIR,
    )


def _create_vpn_security_coordinator() -> Any:
    """Create VPN security coordinator with lazy import of optional deps."""
    from vpn_security import VPNSecurityCoordinator

    return VPNSecurityCoordinator(
        interface=settings.VPN_SECURITY_INTERFACE,
        poll_interval_seconds=settings.VPN_SECURITY_POLL_INTERVAL_SECONDS,
        dashboard_callback=_network_defense_alert_callback,
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup / shutdown lifecycle."""
    global _docker_mgr, _session_mgr, _telemetry, _canary_mgr, _ws_manager, _detection_orchestrator, _network_defense, _vpn_security, _ssh_server_handle

    configure_logging()
    log.info("ghost_dashboard_starting")

    try:
        await init_db()
        log.info("database_initialized")
    except Exception as e:
        log.warning("database_init_failed", error=str(e))
        log.warning("continuing_without_database", note="Dashboard will operate with limited functionality")

    _docker_mgr = DockerManager()
    _telemetry = TelemetryLogger()
    _canary_mgr = CanaryManager()
    _ws_manager = ConnectionManager()
    _detection_orchestrator = DetectionOrchestrator()

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
    app.state.detection_orchestrator = _detection_orchestrator

    # Register routers after service initialization.
    if not getattr(app.state, "routes_registered", False):
        app.include_router(create_beacon_router(_canary_mgr, _telemetry))
        app.include_router(create_dashboard_router(_session_mgr, _ws_manager))
        app.include_router(create_ws_router(_ws_manager))
        app.include_router(detection_api.router)
        app.state.routes_registered = True

    # ── Validate Service Health ───────────────────────────────────────────
    # Database health check
    try:
        from sqlalchemy import text
        from database.db import get_session
        async with get_session() as db:
            await db.execute(text("SELECT 1"))
        log.info("database_health_check_passed")
    except Exception as e:
        log.warning("database_health_check_failed", error=str(e))
        log.warning("continuing_without_database", note="Some features may be limited")
    
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
    except OSError as e:
        log.warning("ssh_server_startup_failed", port=settings.SSH_PORT, error=str(e))
        log.warning("continuing_without_ssh_honeypot", note="Backend will operate without SSH honeypot")
    except Exception as e:
        log.warning("ssh_server_startup_failed", error=str(e))
        log.warning("continuing_without_ssh_honeypot", note="Backend will operate without SSH honeypot")

    # Start resilience monitoring
    try:
        await _session_mgr.start_resilience()
        log.info("resilience_monitoring_activated")
    except Exception as e:
        log.warning("resilience_startup_failed", error=str(e))

    # Start threat detection system
    try:
        await _detection_orchestrator.start()
        log.info("threat_detection_system_started")
    except Exception as e:
        log.warning("threat_detection_startup_failed", error=str(e))

    # Start network defense system (if enabled)
    if settings.NETWORK_DEFENSE_ENABLED:
        try:
            _network_defense = _create_network_defense_system()
            await _network_defense.start()
            log.info(
                "network_defense_system_started",
                interface=settings.NETWORK_INTERFACE,
                ml_enabled=settings.NETWORK_DEFENSE_ML_ENABLED,
                automated_response=settings.NETWORK_DEFENSE_AUTOMATED_RESPONSE
            )
        except Exception as e:
            log.error("network_defense_startup_failed", error=str(e))
            _network_defense = None
    else:
        log.info("network_defense_disabled")

    # Start VPN security platform (if enabled)
    if settings.VPN_SECURITY_ENABLED:
        try:
            _vpn_security = _create_vpn_security_coordinator()
            await _vpn_security.start()
            app.state.vpn_security = _vpn_security
            log.info(
                "vpn_security_platform_started",
                interface=settings.VPN_SECURITY_INTERFACE,
                poll_interval_seconds=settings.VPN_SECURITY_POLL_INTERVAL_SECONDS,
            )
        except Exception as e:
            log.error("vpn_security_startup_failed", error=str(e))
            _vpn_security = None
    else:
        log.info("vpn_security_platform_disabled")

    log.info("ghost_dashboard_ready", port=settings.DASHBOARD_PORT)
    yield

    # ── Shutdown ───────────────────────────────────────────────────────────────
    log.info("ghost_dashboard_shutting_down")
    
    # Stop network defense system
    if _network_defense:
        try:
            await _network_defense.stop()
            log.info("network_defense_system_stopped")
        except Exception as e:
            log.warning("network_defense_shutdown_failed", error=str(e))

    # Stop VPN security platform
    if _vpn_security:
        try:
            await _vpn_security.stop()
            log.info("vpn_security_platform_stopped")
        except Exception as e:
            log.warning("vpn_security_shutdown_failed", error=str(e))
    
    # Stop threat detection system
    try:
        if _detection_orchestrator:
            await _detection_orchestrator.stop()
            log.info("threat_detection_system_stopped")
    except Exception as e:
        log.warning("threat_detection_shutdown_failed", error=str(e))
    
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

    # Detection WebSocket endpoint
    @app.websocket("/ws/threats")
    async def websocket_threats(websocket):
        await websocket_handler(websocket)

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

    # ── Network Defense API Endpoints ──────────────────────────────────────────

    @app.post("/network-defense/start", tags=["network_defense"])
    async def start_network_defense() -> dict:
        """Manually start network defense system."""
        global _network_defense
        
        if _network_defense and _network_defense.running:
            return {"error": "network_defense_already_running"}
        
        if not settings.NETWORK_DEFENSE_ENABLED:
            return {"error": "network_defense_disabled_in_config"}
        
        try:
            _network_defense = _create_network_defense_system()
            await _network_defense.start()
            log.info("network_defense_started_manually")
            return {"status": "started", "timestamp": datetime.now(timezone.utc).isoformat()}
        except Exception as e:
            log.error("network_defense_start_failed", error=str(e))
            return {"error": str(e)}

    @app.post("/network-defense/stop", tags=["network_defense"])
    async def stop_network_defense() -> dict:
        """Manually stop network defense system."""
        if not _network_defense:
            return {"error": "network_defense_not_running"}
        
        try:
            await _network_defense.stop()
            log.info("network_defense_stopped_manually")
            return {"status": "stopped", "timestamp": datetime.now(timezone.utc).isoformat()}
        except Exception as e:
            log.error("network_defense_stop_failed", error=str(e))
            return {"error": str(e)}

    @app.get("/network-defense/status", tags=["network_defense"])
    async def network_defense_status() -> dict:
        """Get network defense system status."""
        if not _network_defense:
            return {
                "running": False,
                "enabled": settings.NETWORK_DEFENSE_ENABLED,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        try:
            status = _network_defense.get_status()
            return status
        except Exception as e:
            log.error("network_defense_status_failed", error=str(e))
            return {"error": str(e)}

    @app.get("/network-defense/threats", tags=["network_defense"])
    async def network_defense_threats(
        threat_level: str | None = None,
        min_score: float | None = None,
        limit: int = 50
    ) -> dict:
        """Query detected network threats."""
        if not _network_defense:
            return {"error": "network_defense_not_running", "threats": []}
        
        try:
            threats = _network_defense.query_threats(
                threat_level=threat_level,
                min_score=min_score,
                limit=limit
            )
            return {
                "threats": threats,
                "count": len(threats),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            log.error("network_defense_threats_query_failed", error=str(e))
            return {"error": str(e), "threats": []}

    @app.get("/network-defense/recent", tags=["network_defense"])
    async def recent_network_threats(limit: int = 20) -> dict:
        """Get recent network threats."""
        if not _network_defense:
            return {"error": "network_defense_not_running", "threats": []}
        
        try:
            threats = _network_defense.get_recent_threats(limit=limit)
            return {
                "threats": threats,
                "count": len(threats),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            log.error("recent_threats_query_failed", error=str(e))
            return {"error": str(e), "threats": []}

    # ── VPN Security API Endpoints ───────────────────────────────────────────

    @app.post("/vpn-security/start", tags=["vpn_security"])
    async def start_vpn_security() -> dict:
        """Start VPN security platform."""
        global _vpn_security

        if _vpn_security and _vpn_security.running:
            return {"error": "vpn_security_already_running"}

        if not settings.VPN_SECURITY_ENABLED:
            return {"error": "vpn_security_disabled_in_config"}

        try:
            _vpn_security = _create_vpn_security_coordinator()
            await _vpn_security.start()
            app.state.vpn_security = _vpn_security
            return {"status": "started", "timestamp": datetime.now(timezone.utc).isoformat()}
        except Exception as e:
            log.error("vpn_security_start_failed", error=str(e))
            return {"error": str(e)}

    @app.post("/vpn-security/stop", tags=["vpn_security"])
    async def stop_vpn_security() -> dict:
        """Stop VPN security platform."""
        if not _vpn_security:
            return {"error": "vpn_security_not_running"}

        try:
            await _vpn_security.stop()
            app.state.vpn_security = None
            return {"status": "stopped", "timestamp": datetime.now(timezone.utc).isoformat()}
        except Exception as e:
            log.error("vpn_security_stop_failed", error=str(e))
            return {"error": str(e)}

    @app.get("/vpn-security/status", tags=["vpn_security"])
    async def vpn_security_status() -> dict:
        """Get VPN security platform status."""
        if not _vpn_security:
            return {
                "running": False,
                "enabled": settings.VPN_SECURITY_ENABLED,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        try:
            return _vpn_security.get_status()
        except Exception as e:
            log.error("vpn_security_status_failed", error=str(e))
            return {"error": str(e)}

    @app.get("/vpn-security/findings", tags=["vpn_security"])
    async def vpn_security_findings(
        vpn_only: bool = False,
        compromised_only: bool = False,
        leak_only: bool = False,
        min_anomaly_score: float | None = None,
        limit: int = 100,
    ) -> dict:
        """Query VPN security findings."""
        if not _vpn_security:
            return {"error": "vpn_security_not_running", "findings": []}

        try:
            findings = _vpn_security.query_findings(
                vpn_only=vpn_only,
                compromised_only=compromised_only,
                leak_only=leak_only,
                min_anomaly_score=min_anomaly_score,
                limit=limit,
            )
            return {
                "findings": findings,
                "count": len(findings),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            log.error("vpn_security_findings_failed", error=str(e))
            return {"error": str(e), "findings": []}

    @app.get("/vpn-security/recent", tags=["vpn_security"])
    async def vpn_security_recent(limit: int = 20) -> dict:
        """Get recent VPN security findings."""
        if not _vpn_security:
            return {"error": "vpn_security_not_running", "findings": []}

        try:
            findings = _vpn_security.get_recent_findings(limit=limit)
            return {
                "findings": findings,
                "count": len(findings),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            log.error("vpn_security_recent_failed", error=str(e))
            return {"error": str(e), "findings": []}

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
            probe_host = settings.SSH_HOST
            if probe_host in {"0.0.0.0", "::", ""}:
                probe_host = "127.0.0.1"
            result = sock.connect_ex((probe_host, settings.SSH_PORT))
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
        
        # Check detection system
        health_status["services"]["threat_detection"] = "ok" if _detection_orchestrator else "not_initialized"
        if not _detection_orchestrator:
            health_status["status"] = "degraded"

        # Check VPN security platform
        if settings.VPN_SECURITY_ENABLED:
            health_status["services"]["vpn_security"] = "running" if (_vpn_security and _vpn_security.running) else "not_running"
            if not (_vpn_security and _vpn_security.running):
                health_status["status"] = "degraded"
        else:
            health_status["services"]["vpn_security"] = "disabled"
        
        return health_status

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> dict:
        """Suppress favicon 404 errors."""
        return {}

    @app.get("/test", include_in_schema=False)
    async def test_page() -> dict:
        """Simple test endpoint to verify connectivity."""
        return {
            "status": "success",
            "message": "Ghost Protocol backend is working!",
            "static_files_available": True,
            "frontend_dir": str(_FRONTEND_DIR),
            "files": ["index.html", "app.js", "style.css"]
        }

    @app.get("/", include_in_schema=False)
    async def serve_dashboard() -> FileResponse:
        """Serve the frontend SPA."""
        response = FileResponse(str(_FRONTEND_DIR / "index.html"))
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    # Mount static assets AFTER all API routes so they don't shadow them
    if _FRONTEND_DIR.exists():
        app.mount("/static", NoCacheStaticFiles(directory=str(_FRONTEND_DIR)), name="static")

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
