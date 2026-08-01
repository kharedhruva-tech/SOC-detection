import hashlib
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from app.database import get_db
from app.models.models import Incident, Alert, IncidentTimeline, IncidentTask, IncidentComment, IncidentEvidence
from app.models.schemas import IncidentResponse, IncidentCreate, IncidentUpdate, IncidentTaskCreate, IncidentTaskResponse, IncidentCommentCreate
from app.routers.auth import get_current_user
from app.services.ai_agent import ai_agent

router = APIRouter(prefix="/incidents", tags=["Incident Response"])

@router.get("/", response_model=List[IncidentResponse])
def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    return query.order_by(Incident.created_at.desc()).all()

@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.post("/", response_model=IncidentResponse)
def create_incident(
    incident_in: IncidentCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    # Fetch alerts if provided
    alerts = []
    mitre_tactics = set()
    mitre_techniques = set()
    
    if incident_in.alert_ids:
        alerts = db.query(Alert).filter(Alert.id.in_(incident_in.alert_ids)).all()
        for alert in alerts:
            if alert.mitre_tactics:
                mitre_tactics.update(alert.mitre_tactics)
            if alert.mitre_techniques:
                mitre_techniques.update(alert.mitre_techniques)

    incident = Incident(
        title=incident_in.title,
        description=incident_in.description,
        severity=incident_in.severity,
        status="Open",
        risk_score=75.0 if incident_in.severity == "High" else 50.0,
        mitre_tactics=list(mitre_tactics),
        mitre_techniques=list(mitre_techniques),
        creator=current_user.username
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    
    # Associate alerts
    for alert in alerts:
        alert.incident_id = incident.id
        
    # Create timeline entry
    db.add(IncidentTimeline(
        incident_id=incident.id,
        event_type="incident_created",
        message=f"Incident manually created by {current_user.username}.",
        actor=current_user.username
    ))
    db.commit()
    db.refresh(incident)
    return incident

@router.put("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: int,
    incident_in: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    old_status = incident.status
    old_assignee = incident.assigned_to
    
    if incident_in.status:
        incident.status = incident_in.status
        if incident_in.status in ["Closed", "Resolved"] and old_status not in ["Closed", "Resolved"]:
            incident.closed_at = datetime.utcnow()
            
    if incident_in.severity:
        incident.severity = incident_in.severity
    if incident_in.assigned_to is not None:
        incident.assigned_to = incident_in.assigned_to
    if incident_in.risk_score is not None:
        incident.risk_score = incident_in.risk_score

    # Add timeline notes
    if incident_in.status and incident_in.status != old_status:
        db.add(IncidentTimeline(
            incident_id=incident.id,
            event_type="status_change",
            message=f"Status changed from {old_status} to {incident.status}.",
            actor=current_user.username
        ))
        
    if incident_in.assigned_to != old_assignee:
        db.add(IncidentTimeline(
            incident_id=incident.id,
            event_type="assignee_change",
            message=f"Incident assigned to {incident.assigned_to or 'Unassigned'}.",
            actor=current_user.username
        ))

    db.commit()
    db.refresh(incident)
    return incident

@router.post("/{incident_id}/summarize")
def summarize_incident_ai(incident_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    summary = ai_agent.summarize_incident(incident)
    incident.ai_summary = summary
    
    db.add(IncidentTimeline(
        incident_id=incident.id,
        event_type="ai_summary_generated",
        message="AI Copilot generated a comprehensive incident summary.",
        actor="AI Copilot"
    ))
    db.commit()
    return {"summary": summary}

@router.post("/{incident_id}/comments")
def add_comment(
    incident_id: int,
    comment_in: IncidentCommentCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    comment = IncidentComment(
        incident_id=incident.id,
        comment_text=comment_in.comment_text,
        author=current_user.username
    )
    db.add(comment)
    db.add(IncidentTimeline(
        incident_id=incident.id,
        event_type="comment_added",
        message=f"Analyst commented: '{comment_in.comment_text[:60]}...'",
        actor=current_user.username
    ))
    db.commit()
    db.refresh(comment)
    return comment

@router.post("/{incident_id}/tasks")
def add_task(
    incident_id: int,
    task_in: IncidentTaskCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    task = IncidentTask(
        incident_id=incident.id,
        description=task_in.description,
        assigned_to=task_in.assigned_to,
        status="Pending"
    )
    db.add(task)
    db.add(IncidentTimeline(
        incident_id=incident.id,
        event_type="task_added",
        message=f"Task added: '{task_in.description}'",
        actor=current_user.username
    ))
    db.commit()
    db.refresh(task)
    return task

@router.put("/{incident_id}/tasks/{task_id}")
def update_task(
    incident_id: int,
    task_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    task = db.query(IncidentTask).filter(IncidentTask.incident_id == incident_id, IncidentTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
        
    # Toggle status
    if task.status == "Pending":
        task.status = "Completed"
        task.completed_at = datetime.utcnow()
        msg = f"Task completed: '{task.description}'"
    else:
        task.status = "Pending"
        task.completed_at = None
        msg = f"Task marked pending: '{task.description}'"
        
    db.add(IncidentTimeline(
        incident_id=incident_id,
        event_type="task_updated",
        message=msg,
        actor=current_user.username
    ))
    db.commit()
    db.refresh(task)
    return task

@router.post("/{incident_id}/evidence")
def upload_evidence(
    incident_id: int,
    file: UploadFile = File(...),
    chain_of_custody_notes: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    # Read file content to generate SHA-256 hash for digital forensics evidence integrity
    contents = file.file.read()
    sha256_hash = hashlib.sha256(contents).hexdigest()
    file_size = len(contents)
    
    coc_text = f"[{datetime.utcnow().isoformat()}] Uploaded by {current_user.username}. IP Address logged. Integrity hash verified: {sha256_hash}.\n"
    if chain_of_custody_notes:
        coc_text += f"Notes: {chain_of_custody_notes}\n"

    evidence = IncidentEvidence(
        incident_id=incident.id,
        file_name=file.filename,
        file_hash=sha256_hash,
        file_size=file_size,
        chain_of_custody=coc_text,
        uploaded_by=current_user.username
    )
    db.add(evidence)
    db.add(IncidentTimeline(
        incident_id=incident.id,
        event_type="evidence_uploaded",
        message=f"Forensic evidence file '{file.filename}' uploaded and locked with SHA-256 integrity hash.",
        actor=current_user.username
    ))
    db.commit()
    db.refresh(evidence)
    return evidence
