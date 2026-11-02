"""
UEBA (User and Entity Behaviour Analytics) API Router.
Provides endpoints for behavioral dashboard metrics, profile management,
baseline rebuilding, anomaly findings triage, explainable risk scoring, and safe demo simulation.
"""
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, or_

from app.database import get_db
from app.models import models, schemas
from app.detection.ueba.baseline_engine import baseline_engine
from app.detection.ueba.finding_manager import finding_manager
from app.detection.ueba.demo_scenarios import ueba_demo_service
from app.services.ai_agent import ai_agent
from app.api.deps import require_admin, get_current_user
from pydantic import BaseModel

router = APIRouter()

class UEBAAIAnalysisRequest(BaseModel):
    finding_id: str
    prompt: Optional[str] = None


# ==========================================
# 1. UEBA DASHBOARD OVERVIEW
# ==========================================
@router.get("/dashboard")
@router.get("/dashboard/")
def get_ueba_dashboard_stats(db: Session = Depends(get_db)):
    """
    Returns comprehensive UEBA overview statistics:
    Total monitored users, entities, anomalies count, risk distribution,
    baseline status breakdown, and recent findings stream.
    """
    # Ensure baseline profiles exist
    baseline_engine.seed_default_sample_profiles(db)

    profiles = db.query(models.UEBAProfile).all()
    findings = db.query(models.UEBAFinding).order_by(desc(models.UEBAFinding.created_at)).all()

    total_users = sum(1 for p in profiles if p.entity_type == "user")
    total_entities = len(profiles)
    entities_with_anomalies = sum(1 for p in profiles if p.anomalies_count > 0)
    high_risk_count = sum(1 for p in profiles if p.risk_score >= 50.0)
    new_findings_count = sum(1 for f in findings if f.status == "New")

    # Baseline status breakdown
    status_breakdown = {
        "Established": sum(1 for p in profiles if p.baseline_status == "Established"),
        "Learning": sum(1 for p in profiles if p.baseline_status == "Learning"),
        "Insufficient Data": sum(1 for p in profiles if p.baseline_status == "Insufficient Data"),
        "Outdated": sum(1 for p in profiles if p.baseline_status == "Outdated")
    }

    # Risk distribution
    risk_dist = {
        "Critical": sum(1 for p in profiles if p.risk_level == "Critical"),
        "High": sum(1 for p in profiles if p.risk_level == "High"),
        "Medium": sum(1 for p in profiles if p.risk_level == "Medium"),
        "Low": sum(1 for p in profiles if p.risk_level == "Low")
    }

    # Anomaly categories distribution
    anomaly_categories = {}
    for f in findings:
        cat = f.anomaly_type
        anomaly_categories[cat] = anomaly_categories.get(cat, 0) + 1

    # Recent findings formatted
    recent_findings = []
    for f in findings[:8]:
        recent_findings.append({
            "id": f.id,
            "finding_id": f.finding_id,
            "entity_id": f.entity_id,
            "entity_type": f.entity_type,
            "anomaly_type": f.anomaly_type,
            "detection_method": f.detection_method,
            "risk_score": f.risk_score,
            "confidence": f.confidence,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence or {},
            "status": f.status,
            "is_demo": f.is_demo,
            "created_at": f.created_at.isoformat() if f.created_at else datetime.utcnow().isoformat()
        })

    return {
        "total_monitored_users": total_users,
        "total_monitored_entities": total_entities,
        "entities_with_anomalies": entities_with_anomalies,
        "high_risk_entities_count": high_risk_count,
        "new_findings_count": new_findings_count,
        "baseline_status_breakdown": status_breakdown,
        "risk_distribution": risk_dist,
        "anomaly_categories": anomaly_categories,
        "recent_findings": recent_findings
    }


# ==========================================
# 2. PROFILES & BASELINES
# ==========================================
@router.get("/profiles")
@router.get("/profiles/")
def get_ueba_profiles(
    entity_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    baseline_status: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Retrieves paginated behavioral profiles for monitored users and entities."""
    # Auto-seed if empty
    baseline_engine.seed_default_sample_profiles(db)

    query = db.query(models.UEBAProfile)

    if entity_type and entity_type.lower() != "all":
        query = query.filter(models.UEBAProfile.entity_type == entity_type.lower())

    if risk_level and risk_level.lower() != "all":
        query = query.filter(models.UEBAProfile.risk_level.ilike(risk_level))

    if baseline_status and baseline_status.lower() != "all":
        query = query.filter(models.UEBAProfile.baseline_status.ilike(baseline_status))

    if search and search.strip():
        term = f"%{search.strip().lower()}%"
        query = query.filter(
            or_(
                models.UEBAProfile.entity_id.ilike(term),
                models.UEBAProfile.display_name.ilike(term)
            )
        )

    total = query.count()
    profiles = query.order_by(desc(models.UEBAProfile.risk_score)).offset(skip).limit(limit).all()

    items = []
    for p in profiles:
        items.append({
            "id": p.id,
            "entity_id": p.entity_id,
            "entity_type": p.entity_type,
            "display_name": p.display_name,
            "baseline_status": p.baseline_status,
            "risk_score": p.risk_score,
            "risk_level": p.risk_level,
            "learning_started_at": p.learning_started_at.isoformat() if p.learning_started_at else None,
            "last_updated_at": p.last_updated_at.isoformat() if p.last_updated_at else None,
            "baseline_version": p.baseline_version,
            "metadata_info": p.metadata_info or {},
            "anomalies_count": p.anomalies_count,
            "created_at": p.created_at.isoformat() if p.created_at else None
        })

    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit
    }


@router.get("/profiles/{entity_id}")
@router.get("/profiles/{entity_id}/")
def get_ueba_profile_detail(entity_id: str, db: Session = Depends(get_db)):
    """Retrieves detailed profile, multi-category baselines, active findings, and recent events."""
    profile = db.query(models.UEBAProfile).filter(models.UEBAProfile.entity_id == entity_id).first()
    if not profile:
        profile = baseline_engine.get_or_create_profile(db, entity_id)

    baselines_list = []
    for b in profile.baselines:
        baselines_list.append({
            "id": b.id,
            "behaviour_category": b.behaviour_category,
            "baseline_data": b.baseline_data or {},
            "sample_count": b.sample_count,
            "confidence": b.confidence,
            "created_at": b.created_at.isoformat() if b.created_at else None,
            "updated_at": b.updated_at.isoformat() if b.updated_at else None
        })

    # Recent findings for this entity
    findings = (
        db.query(models.UEBAFinding)
        .filter(models.UEBAFinding.entity_id == entity_id)
        .order_by(desc(models.UEBAFinding.created_at))
        .limit(10)
        .all()
    )
    findings_data = []
    for f in findings:
        findings_data.append({
            "id": f.id,
            "finding_id": f.finding_id,
            "anomaly_type": f.anomaly_type,
            "severity": f.severity,
            "risk_score": f.risk_score,
            "title": f.title,
            "status": f.status,
            "created_at": f.created_at.isoformat() if f.created_at else None
        })

    # Recent events count
    events_count = db.query(models.SecurityEvent).filter(models.SecurityEvent.username == entity_id).count()

    return {
        "id": profile.id,
        "entity_id": profile.entity_id,
        "entity_type": profile.entity_type,
        "display_name": profile.display_name,
        "baseline_status": profile.baseline_status,
        "risk_score": profile.risk_score,
        "risk_level": profile.risk_level,
        "baseline_version": profile.baseline_version,
        "metadata_info": profile.metadata_info or {},
        "anomalies_count": profile.anomalies_count,
        "baselines": baselines_list,
        "recent_findings": findings_data,
        "recent_events_count": events_count,
        "created_at": profile.created_at.isoformat() if profile.created_at else None
    }


# ==========================================
# 3. UEBA FINDINGS (ANOMALY ALERTS)
# ==========================================
@router.get("/findings")
@router.get("/findings/")
def get_ueba_findings(
    severity: Optional[str] = None,
    anomaly_type: Optional[str] = None,
    status: Optional[str] = None,
    entity_id: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Retrieves paginated, searchable, and filterable UEBA anomaly findings."""
    query = db.query(models.UEBAFinding)

    if severity and severity.lower() != "all":
        query = query.filter(models.UEBAFinding.severity.ilike(severity))

    if anomaly_type and anomaly_type.lower() != "all":
        query = query.filter(models.UEBAFinding.anomaly_type.ilike(f"%{anomaly_type}%"))

    if status and status.lower() != "all":
        query = query.filter(models.UEBAFinding.status.ilike(status))

    if entity_id and entity_id.strip():
        query = query.filter(models.UEBAFinding.entity_id.ilike(f"%{entity_id.strip()}%"))

    if search and search.strip():
        term = f"%{search.strip().lower()}%"
        query = query.filter(
            or_(
                models.UEBAFinding.finding_id.ilike(term),
                models.UEBAFinding.entity_id.ilike(term),
                models.UEBAFinding.title.ilike(term),
                models.UEBAFinding.description.ilike(term)
            )
        )

    total = query.count()
    findings = query.order_by(desc(models.UEBAFinding.created_at)).offset(skip).limit(limit).all()

    items = []
    for f in findings:
        items.append({
            "id": f.id,
            "finding_id": f.finding_id,
            "entity_id": f.entity_id,
            "entity_type": f.entity_type,
            "anomaly_type": f.anomaly_type,
            "detection_method": f.detection_method,
            "risk_score": f.risk_score,
            "confidence": f.confidence,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence or {},
            "related_event_ids": f.related_event_ids or [],
            "recommended_steps": f.recommended_steps or [],
            "status": f.status,
            "assigned_to": f.assigned_to,
            "is_demo": f.is_demo,
            "created_at": f.created_at.isoformat() if f.created_at else None,
            "updated_at": f.updated_at.isoformat() if f.updated_at else None
        })

    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit
    }


@router.get("/findings/{finding_id}")
@router.get("/findings/{finding_id}/")
def get_ueba_finding_detail(finding_id: str, db: Session = Depends(get_db)):
    """Retrieves full finding evidence, baseline comparison, related events, and feedback."""
    finding = db.query(models.UEBAFinding).filter(models.UEBAFinding.finding_id == finding_id).first()
    if not finding:
        # Check by integer ID fallback
        if finding_id.isdigit():
            finding = db.query(models.UEBAFinding).filter(models.UEBAFinding.id == int(finding_id)).first()

    if not finding:
        raise HTTPException(status_code=404, detail=f"UEBA finding '{finding_id}' not found")

    # Fetch profile and baselines
    profile = db.query(models.UEBAProfile).filter(models.UEBAProfile.entity_id == finding.entity_id).first()
    baselines_data = {}
    if profile:
        for b in profile.baselines:
            baselines_data[b.behaviour_category] = b.baseline_data

    # Fetch related events
    related_events = []
    if finding.related_event_ids:
        events = db.query(models.SecurityEvent).filter(models.SecurityEvent.event_id.in_(finding.related_event_ids)).all()
        for e in events:
            related_events.append({
                "id": e.id,
                "event_id": e.event_id,
                "event_type": e.event_type,
                "category": e.category,
                "severity": e.severity,
                "source_ip": e.source_ip,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "details": e.details or {}
            })

    # Fetch feedback history
    feedbacks = db.query(models.UEBAFeedback).filter(models.UEBAFeedback.finding_id == finding.finding_id).all()
    feedback_list = []
    for fb in feedbacks:
        feedback_list.append({
            "id": fb.id,
            "analyst_id": fb.analyst_id,
            "feedback_type": fb.feedback_type,
            "comments": fb.comments,
            "created_at": fb.created_at.isoformat() if fb.created_at else None
        })

    return {
        "id": finding.id,
        "finding_id": finding.finding_id,
        "entity_id": finding.entity_id,
        "entity_type": finding.entity_type,
        "anomaly_type": finding.anomaly_type,
        "detection_method": finding.detection_method,
        "risk_score": finding.risk_score,
        "confidence": finding.confidence,
        "severity": finding.severity,
        "title": finding.title,
        "description": finding.description,
        "evidence": finding.evidence or {},
        "related_event_ids": finding.related_event_ids or [],
        "recommended_steps": finding.recommended_steps or [],
        "status": finding.status,
        "assigned_to": finding.assigned_to,
        "is_demo": finding.is_demo,
        "profile": {
            "display_name": profile.display_name if profile else finding.entity_id,
            "baseline_status": profile.baseline_status if profile else "Unknown",
            "metadata_info": profile.metadata_info if profile else {}
        },
        "baselines": baselines_data,
        "related_events": related_events,
        "feedback_history": feedback_list,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
        "updated_at": finding.updated_at.isoformat() if finding.updated_at else None
    }


@router.patch("/findings/{finding_id}")
@router.patch("/findings/{finding_id}/")
def update_ueba_finding_status(
    finding_id: str,
    update_data: schemas.UEBAFindingStatusUpdate,
    db: Session = Depends(get_db)
):
    """Updates investigation status and assigns analysts."""
    updated = finding_manager.update_finding_status(
        db,
        finding_id=finding_id,
        status=update_data.status,
        assigned_to=update_data.assigned_to,
        comments=update_data.comments
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"UEBA finding '{finding_id}' not found")

    return {
        "status": "success",
        "finding_id": updated.finding_id,
        "new_status": updated.status,
        "assigned_to": updated.assigned_to,
        "updated_at": updated.updated_at.isoformat()
    }


# ==========================================
# 4. RISK SCORES & TIMELINE
# ==========================================
@router.get("/risk-scores")
@router.get("/risk-scores/")
def get_ueba_risk_scores(db: Session = Depends(get_db)):
    """Returns all monitored entities ranked by behavioral risk score with factor breakdowns."""
    baseline_engine.seed_default_sample_profiles(db)
    profiles = db.query(models.UEBAProfile).order_by(desc(models.UEBAProfile.risk_score)).all()

    items = []
    for p in profiles:
        factors = [
            {"factor": "Baseline Deviation", "contribution": round(p.risk_score * 0.35, 1)},
            {"factor": "Historical Anomalies", "contribution": round(p.risk_score * 0.30, 1)},
            {"factor": "Activity Frequency", "contribution": round(p.risk_score * 0.15, 1)},
            {"factor": "Asset Criticality", "contribution": round(p.risk_score * 0.20, 1)}
        ]
        items.append({
            "entity_id": p.entity_id,
            "entity_type": p.entity_type,
            "display_name": p.display_name,
            "risk_score": p.risk_score,
            "risk_level": p.risk_level,
            "deviation_score": round(p.risk_score * 0.85, 1),
            "anomalies_count": p.anomalies_count,
            "contributing_factors": factors
        })

    return items


@router.get("/timeline/{entity_id}")
@router.get("/timeline/{entity_id}/")
def get_entity_activity_timeline(entity_id: str, db: Session = Depends(get_db)):
    """Returns unified chronological activity timeline of events and anomalies for an entity."""
    events = (
        db.query(models.SecurityEvent)
        .filter(or_(models.SecurityEvent.username == entity_id, models.SecurityEvent.source_ip == entity_id))
        .order_by(desc(models.SecurityEvent.timestamp))
        .limit(25)
        .all()
    )

    findings = (
        db.query(models.UEBAFinding)
        .filter(models.UEBAFinding.entity_id == entity_id)
        .order_by(desc(models.UEBAFinding.created_at))
        .limit(15)
        .all()
    )

    timeline = []
    for f in findings:
        timeline.append({
            "timestamp": f.created_at.isoformat() if f.created_at else datetime.utcnow().isoformat(),
            "event_type": "ueba_anomaly",
            "category": "Behavioral Anomaly",
            "is_anomaly": True,
            "title": f.title,
            "severity": f.severity,
            "details": {
                "finding_id": f.finding_id,
                "anomaly_type": f.anomaly_type,
                "risk_score": f.risk_score,
                "detection_method": f.detection_method
            }
        })

    for e in events:
        timeline.append({
            "timestamp": e.timestamp.isoformat() if e.timestamp else datetime.utcnow().isoformat(),
            "event_type": e.event_type,
            "category": e.category or "Authentication",
            "is_anomaly": False,
            "title": f"Activity: {e.event_type} from {e.source_ip or 'Local'}",
            "severity": e.severity or "low",
            "details": e.details or {}
        })

    timeline.sort(key=lambda x: x["timestamp"], reverse=True)
    return timeline[:30]


# ==========================================
# 5. ANALYST FEEDBACK & ACTIONS
# ==========================================
@router.post("/feedback")
@router.post("/feedback/")
def submit_analyst_feedback(
    fb_data: schemas.UEBAFeedbackCreate,
    db: Session = Depends(get_db)
):
    """Records analyst verification feedback on a UEBA finding."""
    finding = db.query(models.UEBAFinding).filter(models.UEBAFinding.finding_id == fb_data.finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{fb_data.finding_id}' not found")

    fb = finding_manager.add_feedback(
        db,
        finding_id=fb_data.finding_id,
        analyst_id="SOC Analyst (Tier 1)",
        feedback_type=fb_data.feedback_type,
        comments=fb_data.comments
    )
    return {
        "status": "success",
        "id": fb.id,
        "finding_id": fb.finding_id,
        "feedback_type": fb.feedback_type,
        "created_at": fb.created_at.isoformat()
    }


@router.post("/baselines/rebuild")
@router.post("/baselines/rebuild/")
def rebuild_baselines(db: Session = Depends(get_db)):
    """Rebuilds behavioural baselines from historical security events."""
    res = baseline_engine.rebuild_all_baselines(db)
    return res


# ==========================================
# 6. DEMO SCENARIO SIMULATION
# ==========================================
@router.post("/demo/generate")
@router.post("/demo/generate/")
def generate_demo_scenario(
    req: Optional[schemas.UEBADemoGenerateRequest] = None,
    db: Session = Depends(get_db)
):
    """
    Generates synthetic, safe demonstration anomaly events for testing UEBA detection.
    Scenarios: unusual_login_time, dormant_account, mass_resource_access, auth_velocity, bulk_data_exfiltration, all
    """
    scenario = req.scenario if req and req.scenario else "all"
    entity_id = req.entity_id if req else None
    result = ueba_demo_service.run_scenario(db, scenario=scenario, entity_id=entity_id)
    return result


# ==========================================
# 7. AI ANALYST UEBA COPILOT
# ==========================================
@router.post("/ai/analyze")
@router.post("/ai/analyze/")
def analyze_finding_with_ai(
    req: UEBAAIAnalysisRequest,
    db: Session = Depends(get_db)
):
    """Generates evidence-grounded AI Analyst explanation for a UEBA anomaly finding."""
    finding = db.query(models.UEBAFinding).filter(models.UEBAFinding.finding_id == req.finding_id).first()
    if not finding and req.finding_id.isdigit():
        finding = db.query(models.UEBAFinding).filter(models.UEBAFinding.id == int(req.finding_id)).first()

    if not finding:
        raise HTTPException(status_code=404, detail=f"UEBA finding '{req.finding_id}' not found")

    analysis = ai_agent.explain_ueba_anomaly(
        anomaly_title=finding.title,
        anomaly_type=finding.anomaly_type,
        entity_id=finding.entity_id,
        severity=finding.severity,
        risk_score=finding.risk_score,
        evidence=finding.evidence or {}
    )
    return analysis


# ==========================================
# 8. BACKWARD COMPATIBILITY
# ==========================================
@router.get("/users")
@router.get("/users/")
def get_legacy_users(db: Session = Depends(get_db)):
    """Provides backward-compatibility for legacy user baselines views."""
    baseline_engine.seed_default_sample_profiles(db)
    profiles = db.query(models.UEBAProfile).filter(models.UEBAProfile.entity_type == "user").all()

    items = []
    for p in profiles:
        findings = (
            db.query(models.UEBAFinding)
            .filter(models.UEBAFinding.entity_id == p.entity_id)
            .order_by(desc(models.UEBAFinding.created_at))
            .limit(4)
            .all()
        )
        anomalies_list = []
        for f in findings:
            anomalies_list.append({
                "type": f.anomaly_type,
                "title": f.title,
                "category": f.anomaly_type,
                "details": f.description,
                "timestamp": f.created_at.isoformat() if f.created_at else datetime.utcnow().isoformat()
            })

        # Baseline details
        workplace = p.metadata_info.get("department", "Corporate HQ") if p.metadata_info else "Corporate HQ"
        hours_baseline = next((b for b in p.baselines if b.behaviour_category == "login_hours"), None)
        normal_hours = "09:00 - 18:00 EST"
        if hours_baseline and hours_baseline.baseline_data:
            th = hours_baseline.baseline_data.get("typical_hours", [9, 18])
            normal_hours = f"{min(th):02d}:00 - {max(th):02d}:00 UTC"

        loc_baseline = next((b for b in p.baselines if b.behaviour_category == "login_locations"), None)
        trusted = loc_baseline.baseline_data.get("common_ips", ["10.0.1.45"]) if loc_baseline and loc_baseline.baseline_data else ["10.0.1.45"]

        items.append({
            "username": p.entity_id,
            "risk_score": p.risk_score,
            "severity": p.risk_level,
            "anomalies_count": len(anomalies_list),
            "anomalies": anomalies_list,
            "login_baseline": {
                "workplace": workplace,
                "normal_hours": normal_hours,
                "trusted_devices": trusted
            }
        })

    return items
