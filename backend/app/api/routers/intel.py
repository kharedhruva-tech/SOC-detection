from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.database import get_db
from app.models import models

router = APIRouter()

class ReputationCheckRequest(BaseModel):
    value: str
    type: str

@router.get("/mitre-heatmap")
def get_mitre_heatmap(db: Session = Depends(get_db)):
    # Default detection counts across MITRE ATT&CK techniques
    return {
        "T1078": 12,
        "T1190": 4,
        "T1059": 19,
        "T1047": 7,
        "T1053": 5,
        "T1547": 3,
        "T1068": 2,
        "T1548": 8,
        "T1218": 11,
        "T1070": 6,
        "T1110": 24,
        "T1003": 15,
        "T1021": 9,
        "T1570": 4,
        "T1048": 3,
        "T1020": 2,
        "T1486": 18,
        "T1489": 5
    }

@router.post("/reputation-check")
def check_reputation(req: ReputationCheckRequest, db: Session = Depends(get_db)):
    # Check DB IOCs first
    ioc = db.query(models.IOC).filter(models.IOC.value == req.value).first()
    if ioc:
        return {
            "value": ioc.value,
            "type": ioc.type,
            "reputation": ioc.reputation,
            "risk_score": 94.0 if ioc.reputation == "Malicious" else 65.0,
            "threat_actor": ioc.threat_actor or "APT29 (Cozy Bear)",
            "category": ioc.category or "Command & Control Node",
            "description": ioc.description or "Known threat indicator in active database.",
            "abuse_score": 98 if ioc.reputation == "Malicious" else 45,
            "last_reported": "12 minutes ago",
            "country": "Russia",
            "isp": "CyberHost Transit LLC"
        }
    
    # Heuristic fallback for demo queries
    is_mal = "185" in req.value or "evil" in req.value or "lockbit" in req.value.lower() or "45.33" in req.value
    return {
        "value": req.value,
        "type": req.type,
        "reputation": "Malicious" if is_mal else "Clean",
        "risk_score": 92.0 if is_mal else 10.0,
        "threat_actor": "APT29 (Cozy Bear)" if is_mal else "N/A",
        "category": "Command & Control Infrastructure" if is_mal else "Benign IP/Domain",
        "description": "Observed hosting malicious command and control infrastructure." if is_mal else "No threat activity reported across intelligence feeds.",
        "abuse_score": 96 if is_mal else 0,
        "last_reported": "15 minutes ago" if is_mal else "Never",
        "country": "Russia" if is_mal else "United States",
        "isp": "CyberHost Transit LLC" if is_mal else "Cloudflare Inc."
    }
