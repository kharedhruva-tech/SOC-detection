from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from app.database import get_db
from app.models.models import Alert
from app.routers.auth import get_current_user

router = APIRouter(prefix="/ueba", tags=["UEBA Engine"])

@router.get("/users")
def get_user_risk_baselines(db: Session = Depends(get_db), current_user = Depends(get_current_user)) -> List[Dict[str, Any]]:
    """
    Simulates UEBA anomalies scoring. Synthesizes data based on actual security alerts
    associated with users in the database, combined with entity profiling logic.
    """
    # Grab alerts containing usernames or impossible travel logs
    alerts = db.query(Alert).all()
    
    # Static profiles as default base
    users = {
        "ceo_sec": {"username": "ceo_sec", "risk_score": 15, "anomalies": []},
        "administrator": {"username": "administrator", "risk_score": 10, "anomalies": []},
        "admin": {"username": "admin", "risk_score": 5, "anomalies": []},
        "jdoe": {"username": "jdoe", "risk_score": 5, "anomalies": []},
        "db_admin": {"username": "db_admin", "risk_score": 8, "anomalies": []}
    }
    
    # Process DB alert telemetry to dynamically raise scores
    for alert in alerts:
        desc = alert.description.lower()
        title = alert.title.lower()
        
        target_user = None
        if "ceo_sec" in desc or "ceo_sec" in title:
            target_user = "ceo_sec"
        elif "administrator" in desc or "administrator" in title:
            target_user = "administrator"
        elif "admin" in desc or "admin" in title:
            target_user = "admin"
        elif "jdoe" in desc or "jdoe" in title:
            target_user = "jdoe"
        elif "db_admin" in desc or "db_admin" in title:
            target_user = "db_admin"
            
        if target_user:
            users[target_user]["risk_score"] = min(100, users[target_user]["risk_score"] + 25)
            users[target_user]["anomalies"].append({
                "alert_id": alert.id,
                "title": alert.title,
                "category": alert.category,
                "timestamp": alert.timestamp.isoformat()
            })
            
    # Include default baselines of normal logins to contrast anomalous spikes
    result = []
    for user_key, data in users.items():
        # High scores indicate anomalous activity
        severity_tag = "Low"
        if data["risk_score"] > 75:
            severity_tag = "Critical"
        elif data["risk_score"] > 45:
            severity_tag = "High"
        elif data["risk_score"] > 20:
            severity_tag = "Medium"
            
        result.append({
            "username": data["username"],
            "risk_score": data["risk_score"],
            "severity": severity_tag,
            "anomalies_count": len(data["anomalies"]),
            "anomalies": data["anomalies"],
            "login_baseline": {
                "workplace": "Offices, VPN IP pool",
                "normal_hours": "08:00 - 18:00",
                "trusted_devices": ["LAPTOP-ENTERPRISE-01", "DESKTOP-DEV-02"]
            }
        })
        
    return sorted(result, key=lambda x: x["risk_score"], reverse=True)
