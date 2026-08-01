from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db

router = APIRouter()

@router.get("/users")
def get_ueba_users(db: Session = Depends(get_db)):
    return [
        {
            "username": "jsmith",
            "risk_score": 88.5,
            "severity": "Critical",
            "anomalies_count": 4,
            "anomalies": [
                {"type": "Unusual Login Time", "details": "Authenticated at 03:14 AM EST", "timestamp": "2 hours ago"},
                {"type": "Mass Data Access", "details": "Downloaded 4.2GB from \\FinanceRecords", "timestamp": "1 hour ago"},
                {"type": "Password Spray Target", "details": "Targeted by 15 failed authentication attempts", "timestamp": "3 hours ago"},
                {"type": "Process Execution Anomaly", "details": "Executed powershell.exe with base64 encoded payload", "timestamp": "30 mins ago"}
            ],
            "login_baseline": {
                "workplace": "HQ - New York",
                "normal_hours": "09:00 - 18:00 EST",
                "trusted_devices": ["WORKSTATION-JSMITH", "IPHONE-14-JSMITH"]
            }
        },
        {
            "username": "bwayne",
            "risk_score": 78.0,
            "severity": "High",
            "anomalies_count": 2,
            "anomalies": [
                {"type": "Geographical Velocity (Impossible Travel)", "details": "New York -> Moscow in 4 minutes", "timestamp": "3 hours ago"},
                {"type": "Unrecognized Device Login", "details": "Authenticated from Linux host on VPN subnetwork", "timestamp": "3 hours ago"}
            ],
            "login_baseline": {
                "workplace": "Wayne Enterprises HQ",
                "normal_hours": "08:00 - 20:00 EST",
                "trusted_devices": ["BAT-TERMINAL-01", "MACBOOK-PRO-BW"]
            }
        },
        {
            "username": "admin_svc",
            "risk_score": 45.0,
            "severity": "Medium",
            "anomalies_count": 1,
            "anomalies": [
                {"type": "Privilege Escalation Utility", "details": "Ran certutil.exe with external web parameters", "timestamp": "5 hours ago"}
            ],
            "login_baseline": {
                "workplace": "Internal DMZ",
                "normal_hours": "24/7 Automated Service",
                "trusted_devices": ["DC-01", "FINANCE-SRV-01"]
            }
        }
    ]
