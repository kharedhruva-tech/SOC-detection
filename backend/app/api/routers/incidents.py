from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models import models, schemas
from app.services.ai_analyst import ai_analyst

router = APIRouter()

@router.get("/", response_model=List[schemas.IncidentResponse])
def get_incidents(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    incidents = db.query(models.Incident).order_by(models.Incident.created_at.desc()).offset(skip).limit(limit).all()
    return incidents

@router.get("/{incident_id}", response_model=schemas.IncidentResponse)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.patch("/{incident_id}/status", response_model=schemas.IncidentResponse)
def update_incident_status(incident_id: int, status_update: schemas.IncidentStatusUpdate, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = status_update.status
    db.commit()
    db.refresh(incident)

    # Add timeline entry — use actual model field names: event_type, message, actor
    timeline_entry = models.IncidentTimeline(
        incident_id=incident.id,
        event_type="status_update",
        message=f"Status changed to '{status_update.status}'",
        actor="API User"
    )
    db.add(timeline_entry)
    db.commit()

    return incident

@router.get("/{incident_id}/timeline", response_model=List[schemas.TimelineResponse])
def get_incident_timeline(incident_id: int, db: Session = Depends(get_db)):
    timeline = (
        db.query(models.IncidentTimeline)
        .filter(models.IncidentTimeline.incident_id == incident_id)
        .order_by(models.IncidentTimeline.timestamp.desc())
        .all()
    )
    return timeline

@router.get("/{incident_id}/comments", response_model=List[schemas.CommentResponse])
def get_incident_comments(incident_id: int, db: Session = Depends(get_db)):
    comments = (
        db.query(models.IncidentComment)
        .filter(models.IncidentComment.incident_id == incident_id)
        .order_by(models.IncidentComment.timestamp.desc())
        .all()
    )
    return comments

@router.post("/{incident_id}/comments", response_model=schemas.CommentResponse)
def add_incident_comment(incident_id: int, comment: schemas.CommentCreate, db: Session = Depends(get_db)):
    # Use actual model field name: comment_text (not content)
    new_comment = models.IncidentComment(
        incident_id=incident_id,
        author="API User",
        comment_text=comment.comment_text,
    )
    db.add(new_comment)
    db.commit()
    db.refresh(new_comment)
    return new_comment

@router.put("/{incident_id}", response_model=schemas.IncidentResponse)
def update_incident(incident_id: int, update_data: schemas.IncidentUpdate, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    for key, val in update_data.model_dump(exclude_unset=True).items():
        setattr(incident, key, val)

    db.commit()
    db.refresh(incident)

    timeline_entry = models.IncidentTimeline(
        incident_id=incident.id,
        event_type="update",
        message="Incident details updated.",
        actor="API User"
    )
    db.add(timeline_entry)
    db.commit()

    return incident

@router.post("/{incident_id}/ai-summary")
@router.post("/{incident_id}/summarize")
def generate_ai_summary(incident_id: int, db: Session = Depends(get_db)):
    summary = ai_analyst.summarize_incident(db, incident_id)
    return {"summary": summary}

@router.post("/{incident_id}/tasks", response_model=schemas.IncidentTaskResponse)
def add_incident_task(incident_id: int, task_data: schemas.IncidentTaskCreate, db: Session = Depends(get_db)):
    task = models.IncidentTask(
        incident_id=incident_id,
        description=task_data.description,
        assigned_to=task_data.assigned_to or "SecOps Analyst",
        status="Pending"
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task

@router.put("/{incident_id}/tasks/{task_id}", response_model=schemas.IncidentTaskResponse)
def update_incident_task(incident_id: int, task_id: int, db: Session = Depends(get_db)):
    task = db.query(models.IncidentTask).filter(models.IncidentTask.id == task_id, models.IncidentTask.incident_id == incident_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task.status == "Completed":
        task.status = "Pending"
        task.completed_at = None
    else:
        task.status = "Completed"
        task.completed_at = models.datetime.utcnow()

    db.commit()
    db.refresh(task)
    return task

@router.post("/{incident_id}/evidence", response_model=schemas.IncidentEvidenceResponse)
def upload_incident_evidence(incident_id: int, db: Session = Depends(get_db)):
    evidence = models.IncidentEvidence(
        incident_id=incident_id,
        file_name="EVIDENCE_LOG_EXPORT.LOG",
        file_hash="8f4e3c2b1a0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f",
        file_size=204800,
        chain_of_custody="Uploaded via SOC Dashboard. Sealed in custody vault.",
        uploaded_by="API User"
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence

