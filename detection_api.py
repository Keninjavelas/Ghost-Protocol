"""
Detection API routes - expose detection capabilities via REST API.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query
import structlog

from detection_orchestrator import DetectionOrchestrator

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/detection", tags=["detection"])

# Global orchestrator instance
_orchestrator: Optional[DetectionOrchestrator] = None


def get_orchestrator() -> DetectionOrchestrator:
    """Get detection orchestrator instance."""
    global _orchestrator
    if not _orchestrator:
        _orchestrator = DetectionOrchestrator()
    return _orchestrator


@router.post("/start")
async def start_detection():
    """Start threat detection."""
    try:
        orchestrator = get_orchestrator()
        await orchestrator.start()
        return {"status": "running", "message": "Detection started"}
    except Exception as e:
        logger.error("detection_start_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop")
async def stop_detection():
    """Stop threat detection."""
    try:
        orchestrator = get_orchestrator()
        await orchestrator.stop()
        return {"status": "stopped", "message": "Detection stopped"}
    except Exception as e:
        logger.error("detection_stop_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/threats")
async def get_threats(
    source_ip: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000)
):
    """Get detected threats."""
    try:
        orchestrator = get_orchestrator()
        threats = orchestrator.get_threats(source_ip, limit)
        return {
            "threats": threats,
            "count": sum(len(t) for t in threats.values())
        }
    except Exception as e:
        logger.error("get_threats_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_network_status():
    """Get network security status."""
    try:
        orchestrator = get_orchestrator()
        return orchestrator.get_network_status()
    except Exception as e:
        logger.error("get_status_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard")
async def get_dashboard_data():
    """Get dashboard data."""
    try:
        orchestrator = get_orchestrator()
        return orchestrator.get_dashboard_data()
    except Exception as e:
        logger.error("get_dashboard_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts")
async def get_alerts(
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None)
):
    """Get recent alerts."""
    try:
        orchestrator = get_orchestrator()
        alerts = orchestrator.alert_engine.get_recent_alerts(
            count=limit,
            severity_filter=severity
        )
        return {"alerts": alerts, "count": len(alerts)}
    except Exception as e:
        logger.error("get_alerts_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/blocked-ips")
async def get_blocked_ips():
    """Get list of blocked IP addresses."""
    try:
        orchestrator = get_orchestrator()
        blocked = orchestrator.response_orchestrator.get_blocked_ips()
        return {"blocked_ips": blocked, "count": len(blocked)}
    except Exception as e:
        logger.error("get_blocked_ips_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/unblock/{ip_address}")
async def unblock_ip(ip_address: str):
    """Unblock an IP address."""
    try:
        orchestrator = get_orchestrator()
        orchestrator.response_orchestrator.unblock_ip(ip_address)
        return {
            "status": "unblocked",
            "ip": ip_address
        }
    except Exception as e:
        logger.error("unblock_ip_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rules")
async def get_rules(
    category: Optional[str] = Query(None)
):
    """Get attack detection rules."""
    try:
        orchestrator = get_orchestrator()
        rules = orchestrator.attack_rules.get_rules(category)
        return {
            "rules": [
                {
                    "id": r.id,
                    "name": r.name,
                    "category": r.category.value,
                    "severity": r.severity.value,
                    "description": r.description,
                }
                for r in rules
            ],
            "count": len(rules)
        }
    except Exception as e:
        logger.error("get_rules_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rules/disable/{rule_id}")
async def disable_rule(rule_id: str):
    """Disable a detection rule."""
    try:
        orchestrator = get_orchestrator()
        orchestrator.attack_rules.disable_rule(rule_id)
        return {
            "status": "disabled",
            "rule_id": rule_id
        }
    except Exception as e:
        logger.error("disable_rule_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rules/enable/{rule_id}")
async def enable_rule(rule_id: str):
    """Enable a detection rule."""
    try:
        orchestrator = get_orchestrator()
        orchestrator.attack_rules.enable_rule(rule_id)
        return {
            "status": "enabled",
            "rule_id": rule_id
        }
    except Exception as e:
        logger.error("enable_rule_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_detection_stats():
    """Get detection statistics."""
    try:
        orchestrator = get_orchestrator()
        return {
            "threat_detection": orchestrator.threat_detector.stats,
            "alerts": orchestrator.alert_engine.stats,
            "responses": orchestrator.response_orchestrator.stats,
        }
    except Exception as e:
        logger.error("get_stats_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
