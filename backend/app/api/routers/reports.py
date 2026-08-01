from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from datetime import datetime
from app.database import get_db
from app.models import models

router = APIRouter()

@router.get("/summary")
def get_reports_summary(db: Session = Depends(get_db)):
    total_incidents = db.query(models.Incident).count()
    open_incidents = db.query(models.Incident).filter(models.Incident.status != "Closed").count()
    closed_incidents = db.query(models.Incident).filter(models.Incident.status == "Closed").count()

    total_alerts = db.query(models.Alert).count()
    new_alerts = db.query(models.Alert).filter(models.Alert.status == "New").count()

    unpatched_vulns = db.query(models.Vulnerability).filter(models.Vulnerability.patch_status == "Unpatched").count()
    critical_vulns = db.query(models.Vulnerability).filter(models.Vulnerability.cvss_score >= 9.0).count()

    return {
        "report_generated_at": datetime.utcnow().isoformat(),
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "closed_incidents": closed_incidents,
        "total_alerts": total_alerts,
        "new_alerts": new_alerts,
        "unpatched_vulns": unpatched_vulns,
        "critical_vulns": critical_vulns,
        "average_response_time": "14.2 mins",
        "average_resolution_time": "1.8 hours",
        "compliance_score": 94.5,
        "analyst_performance": [
            {"analyst": "SecOps Commander", "closed_count": 18, "avg_time": "12m"},
            {"analyst": "Tier 2 Analyst", "closed_count": 12, "avg_time": "24m"},
            {"analyst": "Tier 1 Analyst", "closed_count": 9, "avg_time": "35m"}
        ]
    }

@router.get("/export/csv")
def export_reports_csv(db: Session = Depends(get_db)):
    incidents = db.query(models.Incident).all()
    csv_lines = ["ID,Title,Severity,Status,Risk Score,Assigned To,Created At"]
    for inc in incidents:
        created = inc.created_at.isoformat() if inc.created_at else ""
        title_escaped = f'"{inc.title.replace(chr(34), chr(34)+chr(34))}"'
        csv_lines.append(f"{inc.id},{title_escaped},{inc.severity},{inc.status},{inc.risk_score},{inc.assigned_to or ''},{created}")

    csv_content = "\n".join(csv_lines)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="soc_incidents_report.csv"'}
    )
