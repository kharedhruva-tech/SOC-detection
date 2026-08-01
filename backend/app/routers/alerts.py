from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models.models import Alert
from app.models.schemas import AlertResponse, AlertUpdate
from app.routers.auth import get_current_user
from app.services.ai_agent import ai_agent

router = APIRouter(prefix="/alerts", tags=["SIEM Alerts"])

@router.get("/", response_model=List[AlertResponse])
def get_alerts(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if category:
        query = query.filter(Alert.category == category)
    if status:
        query = query.filter(Alert.status == status)
    return query.order_by(Alert.timestamp.desc()).all()

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.put("/{alert_id}", response_model=AlertResponse)
def update_alert(
    alert_id: int,
    alert_in: AlertUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    if alert_in.status:
        alert.status = alert_in.status
    if alert_in.incident_id:
        alert.incident_id = alert_in.incident_id
        
    db.commit()
    db.refresh(alert)
    return alert

@router.post("/{alert_id}/explain")
def explain_alert_ai(alert_id: int, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    explanation = ai_agent.explain_alert(
        alert_title=alert.title,
        category=alert.category,
        severity=alert.severity,
        log_payload=alert.source_log or ""
    )
    return explanation
