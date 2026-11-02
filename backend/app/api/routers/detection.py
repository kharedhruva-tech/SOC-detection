"""
Detection Engine and Rules API Router.
Provides endpoints for event ingestion, recent security activity queries,
detection rule management, and safe demo simulation.
"""
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

from app.database import get_db
from app.models import schemas, models
from app.detection.engine import detection_engine
from app.detection.rule_registry import rule_registry
from app.detection.demo_generator import DemoEventGenerator
from app.detection.event_normalizer import EventValidationError
from app.api.deps import require_admin, get_current_user

router = APIRouter()


# ==========================================
# 1. SECURITY EVENT INGESTION & QUERIES
# ==========================================
@router.post("/events", status_code=status.HTTP_201_CREATED)
@router.post("/events/", status_code=status.HTTP_201_CREATED)
def ingest_event(payload: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Ingests and validates incoming security events.
    Normalizes the payload, stores the event, and evaluates against enabled detection rules.
    Broadcasts NEW_EVENT to live WebSocket streams.
    """
    try:
        result = detection_engine.process_event(db, payload)
        return result
    except EventValidationError as e:
        raise HTTPException(status_code=400, detail=f"Event validation error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process event: {str(e)}")


@router.get("/events")
@router.get("/events/")
def get_security_events(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    detection_status: Optional[str] = None,
    time_range: Optional[str] = None,
    is_demo: Optional[bool] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """
    Retrieves a paginated stream of security events for the Live Recent Activity Feed.
    Supports filtering by severity, category, detection status, time range, source IP, and search keyword.
    """
    query = db.query(models.SecurityEvent)

    # 1. Severity filter
    if severity and severity.lower() != "all":
        query = query.filter(models.SecurityEvent.severity.ilike(severity))

    # 2. Category filter
    if category and category.lower() != "all":
        query = query.filter(models.SecurityEvent.category.ilike(category))

    # 3. Detection status filter
    if detection_status and detection_status.lower() != "all":
        query = query.filter(models.SecurityEvent.detection_status.ilike(detection_status))

    # 4. Event type filter
    if event_type and event_type.lower() != "all":
        query = query.filter(models.SecurityEvent.event_type.ilike(f"%{event_type}%"))

    # 5. Source IP filter
    if source_ip and source_ip.strip():
        query = query.filter(models.SecurityEvent.source_ip.ilike(f"%{source_ip.strip()}%"))

    # 6. Time Range filter
    now = datetime.utcnow()
    if time_range == "15m":
        query = query.filter(models.SecurityEvent.timestamp >= now - timedelta(minutes=15))
    elif time_range == "1h":
        query = query.filter(models.SecurityEvent.timestamp >= now - timedelta(hours=1))
    elif time_range == "24h":
        query = query.filter(models.SecurityEvent.timestamp >= now - timedelta(hours=24))

    # 7. Demo flag filter
    if is_demo is not None:
        query = query.filter(models.SecurityEvent.is_demo == is_demo)

    # 8. Keyword search across event_id, event_type, source_ip, username
    if search and search.strip():
        term = f"%{search.strip().lower()}%"
        query = query.filter(
            or_(
                models.SecurityEvent.event_id.ilike(term),
                models.SecurityEvent.event_type.ilike(term),
                models.SecurityEvent.source_ip.ilike(term),
                models.SecurityEvent.username.ilike(term)
            )
        )

    total_count = query.count()
    events = query.order_by(desc(models.SecurityEvent.timestamp)).offset(skip).limit(limit).all()

    items = []
    for evt in events:
        items.append({
            "id": evt.id,
            "event_id": evt.event_id,
            "event_type": evt.event_type,
            "category": evt.category or "Authentication",
            "severity": evt.severity or "low",
            "detection_status": evt.detection_status or "Normal",
            "matched_rule_id": evt.matched_rule_id,
            "risk_score": evt.risk_score or 0.0,
            "source_ip": evt.source_ip,
            "username": evt.username,
            "dest_ip": evt.dest_ip,
            "source": evt.source or "generic",
            "details": evt.details or {},
            "timestamp": evt.timestamp.isoformat() if evt.timestamp else now.isoformat(),
            "is_demo": evt.is_demo
        })

    return {
        "items": items,
        "total": total_count,
        "skip": skip,
        "limit": limit
    }


@router.get("/events/{event_id}")
@router.get("/events/{event_id}/")
def get_security_event_detail(event_id: str, db: Session = Depends(get_db)):
    """
    Returns full event detail, raw evidence payload, matched detection rule explanation,
    and related events sharing the same source IP or username.
    """
    if str(event_id).isdigit():
        evt = db.query(models.SecurityEvent).filter(models.SecurityEvent.id == int(event_id)).first()
    else:
        evt = db.query(models.SecurityEvent).filter(models.SecurityEvent.event_id == event_id).first()

    if not evt:
        raise HTTPException(status_code=404, detail=f"Security event '{event_id}' not found")

    # Fetch matched rule info if rule ID present
    matched_rule_info = None
    detection_explanation = "Evaluated by SIEM detection pipeline: Normal activity profile."
    if evt.matched_rule_id:
        rule = db.query(models.DetectionRule).filter(models.DetectionRule.rule_id == evt.matched_rule_id).first()
        if rule:
            matched_rule_info = {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "description": rule.description,
                "severity": rule.severity,
                "category": rule.category,
                "mitre_tactics": rule.mitre_tactics or [],
                "mitre_techniques": rule.mitre_techniques or []
            }
            detection_explanation = (
                f"Triggered detection rule {rule.rule_id} ({rule.name}). "
                f"Activity matched threshold patterns in the active sliding correlation window."
            )

    # Fetch related events (same source_ip or username within 30 minutes)
    related_events = []
    if evt.source_ip or evt.username:
        time_lower = (evt.timestamp or datetime.utcnow()) - timedelta(minutes=30)
        time_upper = (evt.timestamp or datetime.utcnow()) + timedelta(minutes=30)
        conds = []
        if evt.source_ip:
            conds.append(models.SecurityEvent.source_ip == evt.source_ip)
        if evt.username:
            conds.append(models.SecurityEvent.username == evt.username)

        rel = (
            db.query(models.SecurityEvent)
            .filter(
                models.SecurityEvent.event_id != evt.event_id,
                models.SecurityEvent.timestamp >= time_lower,
                models.SecurityEvent.timestamp <= time_upper,
                or_(*conds)
            )
            .order_by(desc(models.SecurityEvent.timestamp))
            .limit(10)
            .all()
        )
        for r in rel:
            related_events.append({
                "id": r.id,
                "event_id": r.event_id,
                "event_type": r.event_type,
                "category": r.category or "Authentication",
                "severity": r.severity or "low",
                "source_ip": r.source_ip,
                "username": r.username,
                "timestamp": r.timestamp.isoformat() if r.timestamp else datetime.utcnow().isoformat()
            })

    return {
        "id": evt.id,
        "event_id": evt.event_id,
        "event_type": evt.event_type,
        "category": evt.category or "Authentication",
        "severity": evt.severity or "low",
        "detection_status": evt.detection_status or "Normal",
        "matched_rule_id": evt.matched_rule_id,
        "risk_score": evt.risk_score or 0.0,
        "source_ip": evt.source_ip,
        "username": evt.username,
        "dest_ip": evt.dest_ip,
        "source": evt.source or "generic",
        "details": evt.details or {},
        "raw_event": evt.raw_event or "{}",
        "timestamp": evt.timestamp.isoformat() if evt.timestamp else datetime.utcnow().isoformat(),
        "is_demo": evt.is_demo,
        "matched_rule": matched_rule_info,
        "detection_explanation": detection_explanation,
        "related_events": related_events
    }


# ==========================================
# 2. DETECTION RULES MANAGEMENT
# ==========================================
@router.get("/detection-rules", response_model=List[schemas.DetectionRuleResponse])
@router.get("/detection-rules/", response_model=List[schemas.DetectionRuleResponse])
def get_detection_rules(db: Session = Depends(get_db)):
    """
    Retrieves all 10 SIEM detection rules including active configuration,
    enabled status, and detection statistics.
    """
    rule_registry.seed_database(db)
    rules = db.query(models.DetectionRule).order_by(models.DetectionRule.rule_id).all()
    return rules


@router.get("/detection-rules/{rule_id}", response_model=schemas.DetectionRuleResponse)
@router.get("/detection-rules/{rule_id}/", response_model=schemas.DetectionRuleResponse)
def get_detection_rule(rule_id: str, db: Session = Depends(get_db)):
    """Retrieves full details and configuration of a specific detection rule by ID."""
    rule_registry.seed_database(db)
    clean_id = rule_id.upper()
    rule = db.query(models.DetectionRule).filter(models.DetectionRule.rule_id == clean_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Detection rule '{rule_id}' not found")
    return rule


@router.patch("/detection-rules/{rule_id}", response_model=schemas.DetectionRuleResponse)
@router.patch("/detection-rules/{rule_id}/", response_model=schemas.DetectionRuleResponse)
def update_detection_rule(
    rule_id: str,
    update_data: schemas.DetectionRuleUpdate,
    db: Session = Depends(get_db),
    admin_user: dict = Depends(require_admin)
):
    """
    Enables/disables a detection rule or updates its permitted configuration thresholds.
    Requires administrative permissions.
    """
    rule_registry.seed_database(db)
    clean_id = rule_id.upper()
    updated = rule_registry.update_rule(
        db=db,
        rule_id=clean_id,
        enabled=update_data.enabled,
        configuration=update_data.configuration,
        severity=update_data.severity
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Detection rule '{rule_id}' not found")
    return updated


# ==========================================
# 3. SAFE DEMO AND ACTIVITY SIMULATION
# ==========================================
@router.post("/demo/generate-activity")
@router.post("/demo/generate-activity/")
def generate_demo_activity(db: Session = Depends(get_db)):
    """
    Generates a realistic batch of synthetic security events covering the 7 SIEM categories:
    - Authentication
    - Network Security
    - Endpoint Security
    - File Activity
    - Account Management
    - Web Application Security
    - Malware Indicators
    All events are labeled with is_demo=True and broadcast in real-time via WebSocket.
    """
    synthetic_batch = [
        # 1. Authentication
        {
            "event_type": "login_success",
            "username": "jsmith",
            "source_ip": "10.0.1.45",
            "dest_ip": "10.0.1.10",
            "source": "ActiveDirectory",
            "severity": "low",
            "details": {"event_id": 4624, "auth_package": "Kerberos", "workstation": "WKSTN-FIN-02"},
            "is_demo": True
        },
        {
            "event_type": "login_failed",
            "username": "administrator",
            "source_ip": "185.220.101.4",
            "dest_ip": "10.0.1.10",
            "source": "ActiveDirectory",
            "severity": "high",
            "details": {"event_id": 4625, "reason": "bad_password", "workstation": "EXTERNAL-TOR"},
            "is_demo": True
        },
        # 2. Network Security
        {
            "event_type": "port_scan",
            "username": None,
            "source_ip": "45.142.122.9",
            "dest_ip": "10.0.1.15",
            "source": "Snort-NIDS",
            "severity": "high",
            "details": {"dest_port": 22, "protocol": "TCP", "flag": "SYN", "scan_speed": "rapid"},
            "is_demo": True
        },
        {
            "event_type": "firewall_drop",
            "username": None,
            "source_ip": "103.44.55.66",
            "dest_ip": "10.0.1.10",
            "source": "PaloAlto-Edge",
            "severity": "medium",
            "details": {"dest_port": 445, "action": "deny", "rule_matched": "Block-SMB-Inbound"},
            "is_demo": True
        },
        # 3. Endpoint Security
        {
            "event_type": "process_creation",
            "username": "admin",
            "source_ip": "10.0.2.20",
            "dest_ip": "Local",
            "source": "Sysmon",
            "severity": "medium",
            "details": {"process_name": "powershell.exe", "command_line": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass", "parent": "cmd.exe"},
            "is_demo": True
        },
        {
            "event_type": "registry_value_set",
            "username": "System",
            "source_ip": "10.0.2.50",
            "dest_ip": "Local",
            "source": "Sysmon",
            "severity": "medium",
            "details": {"target_object": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "details": "C:\\ProgramData\\svc.exe"},
            "is_demo": True
        },
        # 4. File Activity
        {
            "event_type": "file_modify",
            "username": "finance_user",
            "source_ip": "10.0.1.80",
            "dest_ip": "Local",
            "source": "Sysmon",
            "severity": "high",
            "details": {"file_path": "C:\\Finance\\Q4_Payroll.xlsx.locked", "action": "file_write", "extension": ".locked"},
            "is_demo": True
        },
        # 5. Account Management
        {
            "event_type": "role_assigned",
            "username": "backup_svc",
            "source_ip": "10.0.1.10",
            "dest_ip": "10.0.1.10",
            "source": "ActiveDirectory",
            "severity": "critical",
            "details": {"event_id": 4728, "assigned_role": "Domain Admins", "assigned_by": "admin"},
            "is_demo": True
        },
        # 6. Web Application Security
        {
            "event_type": "sql_injection_attempt",
            "username": "anonymous",
            "source_ip": "198.51.100.22",
            "dest_ip": "10.0.1.5",
            "source": "Cloudflare-WAF",
            "severity": "high",
            "details": {"url": "/api/v1/users?id=1' OR '1'='1", "method": "GET", "waf_rule": "942100-SQLi"},
            "is_demo": True
        },
        # 7. Malware Indicators
        {
            "event_type": "malware_detected",
            "username": "victim_pc",
            "source_ip": "10.0.2.14",
            "dest_ip": "Local",
            "source": "CrowdStrike-Falcon",
            "severity": "critical",
            "details": {"file_name": "invoice_macro.docm.exe", "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "threat_name": "WannaCry.Ransomware"},
            "is_demo": True
        }
    ]

    processed_events = []
    for raw in synthetic_batch:
        res = detection_engine.process_event(db, raw)
        processed_events.append(res)

    return {
        "status": "success",
        "message": f"Generated and broadcast {len(processed_events)} synthetic security events across 7 categories.",
        "events_count": len(processed_events),
        "results": processed_events
    }


@router.post("/demo/generate-events")
@router.post("/demo/generate-events/")
def generate_demo_events(req: Optional[schemas.DemoGenerateRequest] = None, db: Session = Depends(get_db)):
    """
    Generates synthetic security events for a specific rule (e.g. 'BR-001') or 'all'.
    All generated events are safe, non-destructive, and strictly labeled with is_demo=True.
    """
    scenario = "all"
    if req and req.rule_id:
        scenario = req.rule_id

    result = DemoEventGenerator.run_scenario(db, scenario)
    return result


@router.post("/demo/reset", response_model=schemas.DemoResetResponse)
@router.post("/demo/reset/", response_model=schemas.DemoResetResponse)
def reset_demo_data(db: Session = Depends(get_db), admin_user: dict = Depends(require_admin)):
    """
    Safely purges demonstration events and alerts from the database.
    Requires administrative permissions.
    """
    res = DemoEventGenerator.reset_demo_data(db)
    return res


# ==========================================
# 4. AI ANALYST COPILOT ENDPOINT
# ==========================================
from pydantic import BaseModel
from app.services.ai_agent import AIAgentService
from app.detection.alert_manager import alert_manager
import json

ai_agent = AIAgentService()

class AIAnalysisRequest(BaseModel):
    query: str
    alert_id: Optional[str] = None
    incident_id: Optional[int] = None

@router.post("/ai/analyze")
@router.post("/ai/analyze/")
def analyze_with_ai(req: AIAnalysisRequest, db: Session = Depends(get_db)):
    """
    Provides evidence-based AI Analyst investigation.
    Distinguishes verified system facts from AI hypotheses and recommended remediations.
    """
    verified_evidence = {}
    alert_obj = None

    if req.alert_id:
        alert_obj = alert_manager.get_alert_by_id(db, req.alert_id)
        if alert_obj:
            verified_evidence = {
                "alert_id": alert_obj.alert_id,
                "rule_id": alert_obj.rule_id,
                "title": alert_obj.title,
                "severity": alert_obj.severity,
                "source_ip": alert_obj.source_ip,
                "username": alert_obj.username,
                "matched_event_ids": alert_obj.matched_event_ids,
                "evidence_payload": alert_obj.evidence
            }

    if not verified_evidence:
        latest = db.query(models.SecurityAlert).order_by(models.SecurityAlert.detection_timestamp.desc()).first()
        if latest:
            alert_obj = latest
            verified_evidence = {
                "alert_id": latest.alert_id,
                "rule_id": latest.rule_id,
                "title": latest.title,
                "severity": latest.severity,
                "source_ip": latest.source_ip,
                "username": latest.username,
                "matched_event_ids": latest.matched_event_ids,
                "evidence_payload": latest.evidence
            }

    title = alert_obj.title if alert_obj else "System Threat Telemetry"
    category = alert_obj.category if alert_obj else "General"
    severity = alert_obj.severity if alert_obj else "High"
    raw_log = json.dumps(verified_evidence) if verified_evidence else "{}"

    ai_exp = ai_agent.explain_alert(
        alert_title=title,
        category=category,
        severity=severity,
        log_payload=raw_log
    )

    return {
        "verified_evidence": verified_evidence,
        "ai_explanation": ai_exp,
        "model": "Aegis-CyberAnalyst-v2.4",
        "timestamp": datetime.utcnow().isoformat()
    }
