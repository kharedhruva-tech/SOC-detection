from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.models import IncidentEvidence, IncidentTimeline
from app.models.schemas import IncidentEvidenceResponse, IncidentTimelineResponse
from app.routers.auth import get_current_user

router = APIRouter(prefix="/forensics", tags=["Digital Forensics"])

@router.get("/evidence", response_model=List[IncidentEvidenceResponse])
def get_all_evidence(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    return db.query(IncidentEvidence).order_by(IncidentEvidence.uploaded_at.desc()).all()

@router.get("/timeline", response_model=List[IncidentTimelineResponse])
def get_system_timeline(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """
    Returns unified chronological events logged across all system-level incidents.
    """
    return db.query(IncidentTimeline).order_by(IncidentTimeline.timestamp.desc()).all()
