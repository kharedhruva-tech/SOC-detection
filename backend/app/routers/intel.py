from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional, Dict
from pydantic import BaseModel
from app.database import get_db
from app.models.models import IOC, Alert
from app.models.schemas import IOCResponse, IOCCreate
from app.routers.auth import get_current_user

router = APIRouter(prefix="/intel", tags=["Threat Intelligence"])

class ReputationRequest(BaseModel):
    value: str
    type: str

@router.get("/iocs", response_model=List[IOCResponse])
def get_iocs(ioc_type: Optional[str] = None, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    query = db.query(IOC)
    if ioc_type:
        query = query.filter(IOC.type == ioc_type)
    return query.order_by(IOC.last_seen.desc()).all()

@router.post("/iocs", response_model=IOCResponse)
def create_ioc(ioc_in: IOCCreate, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    # Check if IOC already exists
    existing = db.query(IOC).filter(IOC.value == ioc_in.value).first()
    if existing:
        raise HTTPException(status_code=400, detail="IOC value already exists")
        
    ioc = IOC(
        value=ioc_in.value,
        type=ioc_in.type,
        reputation=ioc_in.reputation or "Unknown",
        category=ioc_in.category,
        threat_actor=ioc_in.threat_actor or "Unknown",
        description=ioc_in.description
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc

@router.post("/reputation-check")
def check_ioc_reputation(req: ReputationRequest, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    # Query database to see if we have this IOC already registered
    match = db.query(IOC).filter(func.lower(IOC.value) == req.value.lower()).first()
    
    if match:
        return {
            "value": match.value,
            "type": match.type,
            "reputation": match.reputation,
            "score": 95 if match.reputation == "Malicious" else (50 if match.reputation == "Suspicious" else 5),
            "threat_actor": match.threat_actor,
            "category": match.category,
            "details": f"Matches threat intel database signature. Tagged as {match.category} associated with actor: {match.threat_actor}.",
            "source": "Internal SOC Threat Intel DB"
        }
        
    # Standard mocks for new queries
    val = req.value.lower()
    if "evil" in val or "malicious" in val or "185.220.101.4" in val or "45.227.254.10" in val:
        return {
            "value": req.value,
            "type": req.type,
            "reputation": "Malicious",
            "score": 90,
            "threat_actor": "APT29 (Cozy Bear) / Wizard Spider",
            "category": "Command and Control Node",
            "details": "Known active Tor exit node or bad actor C2 gateway. Flagged by AbuseIPDB (88/100) and VirusTotal (24/70 engines).",
            "source": "AbuseIPDB & VirusTotal Feed"
        }
    else:
        return {
            "value": req.value,
            "type": req.type,
            "reputation": "Safe",
            "score": 0,
            "threat_actor": "None",
            "category": "Clean Utility",
            "details": "No threat indicators detected for this indicator. Safe whitelist match.",
            "source": "Global Whitelist Feed"
        }

@router.get("/mitre-heatmap")
def get_mitre_heatmap(db: Session = Depends(get_db), current_user = Depends(get_current_user)) -> Dict[str, int]:
    """
    Scans all database alerts and returns technique frequency counts.
    Returns e.g. {"T1110": 5, "T1047": 2}
    """
    alerts = db.query(Alert).filter(Alert.is_duplicate == False).all()
    heatmap = {}
    for alert in alerts:
        techniques = alert.mitre_techniques or []
        for tech in techniques:
            heatmap[tech] = heatmap.get(tech, 0) + 1
    return heatmap
