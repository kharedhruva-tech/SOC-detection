from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import Incident, Alert, Vulnerability
from app.routers.auth import get_current_user
from datetime import datetime
import csv
import io

router = APIRouter(prefix="/reports", tags=["Executive & Compliance Reporting"])

@router.get("/summary")
def get_soc_report_summary(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """
    Returns aggregated SOC metrics for executive dashboard reporting.
    """
    total_incidents = db.query(Incident).count()
    open_incidents = db.query(Incident).filter(Incident.status == "Open").count()
    closed_incidents = db.query(Incident).filter(Incident.status == "Closed").count()
    
    total_alerts = db.query(Alert).count()
    new_alerts = db.query(Alert).filter(Alert.status == "New").count()
    
    unpatched_vulns = db.query(Vulnerability).filter(Vulnerability.patch_status == "Unpatched").count()
    critical_vulns = db.query(Vulnerability).filter(Vulnerability.cvss_score >= 9.0).count()
    
    # Calculate average resolution time (mock)
    resolution_time = "34 minutes"
    
    # MITRE ATT&CK coverage score
    compliance_score = 92  # out of 100
    
    # Threat trend percentages
    threat_trends = [
        {"month": "Feb", "incidents": 12},
        {"month": "Mar", "incidents": 18},
        {"month": "Apr", "incidents": 15},
        {"month": "May", "incidents": 25},
        {"month": "Jun", "incidents": 22},
        {"month": "Jul", "incidents": 30}
    ]

    return {
        "report_generated_at": datetime.utcnow().isoformat(),
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "closed_incidents": closed_incidents,
        "total_alerts": total_alerts,
        "new_alerts": new_alerts,
        "unpatched_vulns": unpatched_vulns,
        "critical_vulns": critical_vulns,
        "average_response_time": "12 minutes",
        "average_resolution_time": resolution_time,
        "compliance_score": compliance_score,
        "threat_trends": threat_trends,
        "accuracy_score": 98.4,
        "analyst_performance": [
            {"name": "Tier 1 Analyst", "closed": 15, "sla": "98%"},
            {"name": "Tier 2 Analyst", "closed": 10, "sla": "95%"},
            {"name": "Threat Hunter", "closed": 5, "sla": "100%"}
        ]
    }

@router.get("/export/csv")
def export_incidents_csv(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """
    Generates a downloadable CSV containing the entire active incident log.
    """
    incidents = db.query(Incident).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        "Incident ID", "Title", "Severity", "Status", "Risk Score", 
        "Assigned To", "Creator", "Created At", "Closed At"
    ])
    
    # Write rows
    for inc in incidents:
        writer.writerow([
            inc.id, inc.title, inc.severity, inc.status, inc.risk_score,
            inc.assigned_to or "Unassigned", inc.creator, 
            inc.created_at.isoformat(), 
            inc.closed_at.isoformat() if inc.closed_at else "N/A"
        ])
        
    output.seek(0)
    response = Response(content=output.getvalue(), media_type="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=soc_incidents_report.csv"
    return response
