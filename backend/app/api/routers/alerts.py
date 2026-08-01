from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models import models, schemas

router = APIRouter()

@router.get("/", response_model=List[schemas.AlertResponse])
def get_alerts(status: Optional[str] = None, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    query = db.query(models.Alert)
    if status:
        query = query.filter(models.Alert.status == status)
    alerts = query.order_by(models.Alert.timestamp.desc()).offset(skip).limit(limit).all()
    return alerts

@router.get("/{alert_id}", response_model=schemas.AlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
