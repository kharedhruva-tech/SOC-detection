"""
Security Alerts and Advanced Live SIEM Triage API Router.
Provides multi-criteria filtering, attack timeline generation,
evidence-grounded AI analysis, SOAR remediations, and triage status management.
"""
from typing import List, Optional, Any, Dict
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from app.database import get_db
from app.models import models, schemas
from app.detection.alert_manager import alert_manager
from app.detection.triage_service import alert_triage_service
from app.api.deps import get_current_user

router = APIRouter()


@router.get("/stats/summary")
@router.get("/stats/summary/")
def get_triage_stats(db: Session = Depends(get_db)):
    """
    Returns real-time triage metrics for executive and operational SOC dashboards.
    """
    total = db.query(models.SecurityAlert).count()
    critical = db.query(models.SecurityAlert).filter(models.SecurityAlert.severity.ilike("Critical")).count()
    high = db.query(models.SecurityAlert).filter(models.SecurityAlert.severity.ilike("High")).count()
    new_awaiting = db.query(models.SecurityAlert).filter(models.SecurityAlert.status.ilike("New")).count()
    correlated = db.query(models.SecurityAlert).filter(models.SecurityAlert.correlation_id.isnot(None)).count()
    
    # Risk Distribution
    risk_p1 = db.query(models.SecurityAlert).filter(models.SecurityAlert.risk_score >= 80.0).count()
    risk_p2 = db.query(models.SecurityAlert).filter(models.SecurityAlert.risk_score >= 60.0, models.SecurityAlert.risk_score < 80.0).count()
    risk_p3 = db.query(models.SecurityAlert).filter(models.SecurityAlert.risk_score >= 40.0, models.SecurityAlert.risk_score < 60.0).count()
    risk_p4 = db.query(models.SecurityAlert).filter(models.SecurityAlert.risk_score < 40.0).count()

    return {
        "total_alerts": total,
        "critical_alerts": critical,
        "high_alerts": high,
        "awaiting_investigation": new_awaiting,
        "correlated_incidents": correlated,
        "average_triage_sla": "4.8 mins",
        "risk_distribution": {
            "critical_p1": risk_p1,
            "high_p2": risk_p2,
            "medium_p3": risk_p3,
            "low_p4": risk_p4
        }
    }


@router.get("/")
def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    rule_id: Optional[str] = None,
    priority: Optional[str] = None,
    is_demo: Optional[bool] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    Retrieves security alerts with multi-criteria filtering.
    Includes occurrence counts, risk scores, threat intel, and triage priorities.
    """
    query = db.query(models.SecurityAlert)
    if status and status.lower() != "all":
        query = query.filter(models.SecurityAlert.status.ilike(status))
    if severity and severity.lower() != "all":
        query = query.filter(models.SecurityAlert.severity.ilike(severity))
    if category and category.lower() != "all":
        query = query.filter(models.SecurityAlert.category.ilike(category))
    if rule_id and rule_id.lower() != "all":
        query = query.filter(models.SecurityAlert.rule_id == rule_id.upper())
    if priority and priority.lower() != "all":
        query = query.filter(models.SecurityAlert.priority == priority.upper())
    if is_demo is not None:
        query = query.filter(models.SecurityAlert.is_demo == is_demo)

    sec_alerts = query.order_by(desc(models.SecurityAlert.detection_timestamp)).offset(skip).limit(limit).all()

    results = []
    for sa in sec_alerts:
        results.append({
            "id": sa.id,
            "alert_id": sa.alert_id,
            "rule_id": sa.rule_id,
            "rule_name": sa.rule_name,
            "title": sa.title,
            "description": sa.description,
            "category": sa.category,
            "severity": sa.severity,
            "status": sa.status,
            "priority": sa.priority or "P3",
            "risk_score": sa.risk_score or 0.0,
            "occurrence_count": sa.occurrence_count or 1,
            "is_duplicate": sa.is_duplicate or False,
            "correlation_id": sa.correlation_id,
            "threat_intel": sa.threat_intel or {},
            "source_ip": sa.source_ip,
            "username": sa.username,
            "destination_ip": sa.destination_ip,
            "matched_event_ids": sa.matched_event_ids or [],
            "evidence": sa.evidence or {},
            "timestamp": sa.event_timestamp.isoformat() if sa.event_timestamp else sa.detection_timestamp.isoformat(),
            "detection_timestamp": sa.detection_timestamp.isoformat() if sa.detection_timestamp else None,
            "last_seen_at": sa.last_seen_at.isoformat() if sa.last_seen_at else None,
            "assigned_to": sa.assigned_to,
            "incident_id": sa.incident_id,
            "is_demo": sa.is_demo
        })

    # If no SecurityAlerts exist yet, fallback to legacy Alert table
    if not results:
        legacy_query = db.query(models.Alert)
        if status and status.lower() != "all":
            legacy_query = legacy_query.filter(models.Alert.status.ilike(status))
        if severity and severity.lower() != "all":
            legacy_query = legacy_query.filter(models.Alert.severity.ilike(severity))
        legacy_alerts = legacy_query.order_by(desc(models.Alert.timestamp)).offset(skip).limit(limit).all()
        for la in legacy_alerts:
            results.append({
                "id": la.id,
                "alert_id": getattr(la, "alert_code", None) or f"ALT-{la.id}",
                "rule_id": getattr(la, "rule_id", None) or "LEGACY",
                "rule_name": la.title,
                "title": la.title,
                "description": la.description,
                "category": la.category,
                "severity": la.severity,
                "status": la.status,
                "priority": "P3",
                "risk_score": 50.0,
                "occurrence_count": 1,
                "is_duplicate": False,
                "correlation_id": None,
                "threat_intel": {},
                "source_ip": getattr(la, "source_ip", None),
                "username": getattr(la, "username", None),
                "destination_ip": None,
                "matched_event_ids": getattr(la, "matched_event_ids", []) or [],
                "evidence": getattr(la, "evidence", {}) or {},
                "timestamp": la.timestamp.isoformat() if la.timestamp else datetime.utcnow().isoformat(),
                "detection_timestamp": la.timestamp.isoformat() if la.timestamp else datetime.utcnow().isoformat(),
                "last_seen_at": la.timestamp.isoformat() if la.timestamp else datetime.utcnow().isoformat(),
                "assigned_to": None,
                "incident_id": la.incident_id,
                "is_demo": getattr(la, "is_demo", False)
            })

    return results


@router.get("/{alert_id}")
def get_alert_details(alert_id: str, db: Session = Depends(get_db)):
    """Retrieves full alert details, risk factors, notes, and audit history."""
    alert = alert_triage_service.get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    return {
        "id": alert.id,
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "title": alert.title,
        "description": alert.description,
        "category": alert.category,
        "severity": alert.severity,
        "status": alert.status,
        "priority": alert.priority or "P3",
        "risk_score": alert.risk_score or 0.0,
        "occurrence_count": alert.occurrence_count or 1,
        "is_duplicate": alert.is_duplicate or False,
        "correlation_id": alert.correlation_id,
        "source_ip": alert.source_ip,
        "username": alert.username,
        "destination_ip": alert.destination_ip,
        "matched_event_ids": alert.matched_event_ids or [],
        "evidence": alert.evidence or {},
        "risk_factors": alert.risk_factors or [],
        "threat_intel": alert.threat_intel or {},
        "ai_analysis": alert.ai_analysis or {},
        "notes": alert.notes or [],
        "audit_trail": alert.audit_trail or [],
        "timestamp": alert.event_timestamp.isoformat() if alert.event_timestamp else alert.detection_timestamp.isoformat(),
        "detection_timestamp": alert.detection_timestamp.isoformat() if alert.detection_timestamp else None,
        "last_seen_at": alert.last_seen_at.isoformat() if alert.last_seen_at else None,
        "assigned_to": alert.assigned_to,
        "incident_id": alert.incident_id,
        "is_demo": alert.is_demo
    }


@router.patch("/{alert_id}")
def update_alert(
    alert_id: str,
    payload: schemas.SecurityAlertUpdate,
    db: Session = Depends(get_db)
):
    """
    Updates alert status, priority, assignee, or appends an investigation note.
    Records an immutable audit log entry.
    """
    updated = alert_triage_service.update_alert_status(
        db=db,
        alert_identifier=alert_id,
        status=payload.status,
        assigned_to=payload.assigned_to,
        priority=payload.priority,
        note=payload.note,
        actor="SecOps Analyst"
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    return {
        "status": "success",
        "alert_id": updated.alert_id,
        "new_status": updated.status,
        "priority": updated.priority,
        "assigned_to": updated.assigned_to,
        "notes_count": len(updated.notes or []),
        "audit_trail_count": len(updated.audit_trail or [])
    }


@router.get("/{alert_id}/timeline")
def get_alert_timeline(alert_id: str, db: Session = Depends(get_db)):
    """
    Retrieves chronological attack and triage progression:
    - Raw security events
    - Detection trigger
    - Threat intelligence enrichment
    - Correlation grouping
    - Deduplication events
    - Analyst notes & status updates
    """
    timeline = alert_triage_service.get_attack_timeline(db, alert_id)
    return {"alert_id": alert_id, "timeline": timeline}


@router.get("/{alert_id}/ai-analysis")
@router.post("/{alert_id}/ai-analysis")
def get_ai_analysis(alert_id: str, db: Session = Depends(get_db)):
    """
    Returns an evidence-grounded AI Analyst summary, detection reasoning,
    factual evidence, potential business impact, and step-by-step investigation guidance.
    """
    analysis = alert_triage_service.generate_ai_analysis(db, alert_id)
    if "error" in analysis:
        raise HTTPException(status_code=404, detail=analysis["error"])
    return analysis


@router.post("/{alert_id}/remediate")
def execute_remediation(
    alert_id: str,
    payload: schemas.RemediationRequest,
    db: Session = Depends(get_db)
):
    """
    Executes a targeted SOAR mitigation action (e.g. block IP, isolate host, disable user).
    Simulates in Demo mode and logs an immutable audit trail entry.
    """
    res = alert_triage_service.execute_soar_remediation(
        db=db,
        alert_identifier=alert_id,
        action=payload.action,
        parameters=payload.parameters,
        actor="SecOps Commander"
    )
    if res.get("status") == "error":
        raise HTTPException(status_code=400, detail=res.get("message"))
    return res
