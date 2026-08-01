import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from sqlalchemy.orm import Session
from app.database import SessionLocal, engine, Base
from app.models import models
from datetime import datetime, timedelta

def seed_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # 0. Seed admin user
        if db.query(models.User).filter(models.User.username == "admin").count() == 0:
            admin_user = models.User(
                username="admin",
                email="admin@aegis-soc.corp",
                hashed_password="2006",  # demo plain password
                full_name="System Administrator",
                role="Super Admin",
                is_active=True
            )
            db.add(admin_user)
            db.commit()

        # 0b. Seed demo user
        if db.query(models.User).filter(models.User.username == "user").count() == 0:
            demo_user = models.User(
                username="user",
                email="user@aegis-soc.corp",
                hashed_password="user",  # demo plain password
                full_name="Operations Specialist",
                role="SOC User",
                is_active=True
            )
            db.add(demo_user)
            db.commit()

        # 1. Check if playbooks exist
        if db.query(models.Playbook).count() == 0:
            pb1 = models.Playbook(
                name="Ransomware Host Isolation & AD Revocation",
                description="Automated response playbook triggered on high volume file encryption signals. Immediately isolates host interface and disables victim credentials in Active Directory.",
                is_active=True,
                nodes=[
                    {"id": "1", "data": {"label": "Trigger: Ransomware Signal", "action": "trigger"}, "position": {"x": 100, "y": 100}},
                    {"id": "2", "data": {"label": "Isolate Host Interface", "action": "isolate_host", "target": "10.0.1.5"}, "position": {"x": 100, "y": 200}},
                    {"id": "3", "data": {"label": "Disable User Credentials", "action": "disable_user", "target": "jsmith"}, "position": {"x": 100, "y": 300}},
                    {"id": "4", "data": {"label": "Notify SOC Commander Email", "action": "send_email", "target": "soc-leads@company.com"}, "position": {"x": 100, "y": 400}}
                ],
                edges=[
                    {"id": "e1-2", "source": "1", "target": "2"},
                    {"id": "e2-3", "source": "2", "target": "3"},
                    {"id": "e3-4", "source": "3", "target": "4"}
                ],
                creator="Automated Defense Rule"
            )
            pb2 = models.Playbook(
                name="Credential Theft & Impossible Travel Mitigation",
                description="Forces mandatory MFA step-up authentication, terminates active OAuth refresh tokens, and blocks source perimeter IP addresses.",
                is_active=True,
                nodes=[
                    {"id": "1", "data": {"label": "Trigger: Impossible Travel", "action": "trigger"}, "position": {"x": 100, "y": 100}},
                    {"id": "2", "data": {"label": "Block Attacker Source IP", "action": "block_ip", "target": "185.12.33.44"}, "position": {"x": 100, "y": 200}},
                    {"id": "3", "data": {"label": "Reset OAuth Sessions", "action": "disable_user", "target": "bwayne"}, "position": {"x": 100, "y": 300}}
                ],
                edges=[
                    {"id": "e1-2", "source": "1", "target": "2"},
                    {"id": "e2-3", "source": "2", "target": "3"}
                ],
                creator="Identity Protection System"
            )
            db.add_all([pb1, pb2])
            db.commit()

        # 2. Check if assets exist
        if db.query(models.Asset).count() == 0:
            a1 = models.Asset(name="FINANCE-SRV-01", ip_address="10.0.1.5", hostname="fin-srv01.corp", os="Windows Server 2022", criticality="Critical", risk_score=88.5, owner="Finance Dept", business_unit="Financial Operations", network_location="Internal Corporate DMZ")
            a2 = models.Asset(name="VPN-GATEWAY-EAST", ip_address="10.0.0.1", hostname="vpn-east.corp", os="Linux Ubuntu 22.04", criticality="High", risk_score=72.0, owner="Network Infra", business_unit="IT Security", network_location="Perimeter VPN")
            a3 = models.Asset(name="WORKSTATION-JSMITH", ip_address="10.0.2.50", hostname="ws-jsmith.corp", os="Windows 11 Enterprise", criticality="Medium", risk_score=65.0, owner="John Smith", business_unit="Accounting", network_location="User Subnet")
            db.add_all([a1, a2, a3])
            db.commit()

        # 3. Check if incidents exist
        if db.query(models.Incident).count() == 0:
            inc1 = models.Incident(
                title="Ransomware Behavior Detected on FINANCE-SRV-01",
                description="High frequency volume file modifications detected in C:\\FinanceRecords. File headers match LockBit 3.0 ransomware entropy signatures.",
                severity="Critical",
                status="Investigating",
                risk_score=94.0,
                mitre_tactics=["Defense Evasion", "Impact"],
                mitre_techniques=["T1486 Data Encrypted for Impact", "T1490 Inhibit System Recovery"],
                assigned_to="SecOps Commander",
                creator="SIEM Threat Engine",
                ai_summary="AI Analysis: Critical confidence (94%). Process unknown.exe spawned shadowcopy deletion commands followed by rapid file encryption. Immediate host isolation recommended."
            )
            inc2 = models.Incident(
                title="Impossible Travel VPN Login Anomaly",
                description="User account 'bwayne' authenticated successfully from New York (203.0.113.5) and 4 minutes later from Moscow (185.12.33.44).",
                severity="High",
                status="Open",
                risk_score=78.5,
                mitre_tactics=["Credential Access", "Initial Access"],
                mitre_techniques=["T1078 Valid Accounts", "T1110 Brute Force"],
                assigned_to="Tier 2 Analyst",
                creator="Identity Anomaly Guard",
                ai_summary="AI Analysis: Geographical velocity exceeds max physical transport speed (4500 mph delta). High probability of compromised credentials."
            )
            inc3 = models.Incident(
                title="Multiple Failed Authentication Spikes on DC-01",
                description="Over 45 failed Kerberos authentication attempts within 60 seconds targeting service accounts.",
                severity="Medium",
                status="Open",
                risk_score=52.0,
                mitre_tactics=["Credential Access"],
                mitre_techniques=["T1110.003 Password Spraying"],
                assigned_to=None,
                creator="Active Directory Monitor",
                ai_summary="AI Analysis: Pattern matches automated password spraying tool execution. Source IP 45.33.22.11."
            )
            db.add_all([inc1, inc2, inc3])
            db.commit()
            db.refresh(inc1)
            db.refresh(inc2)

            # Add tasks to inc1
            t1 = models.IncidentTask(incident_id=inc1.id, description="Isolate host FINANCE-SRV-01 from corporate network", status="Completed", assigned_to="SecOps Commander", completed_at=datetime.utcnow())
            t2 = models.IncidentTask(incident_id=inc1.id, description="Dump memory payload from unknown.exe for YARA signature generation", status="Pending", assigned_to="SecOps Commander")
            t3 = models.IncidentTask(incident_id=inc1.id, description="Verify backup integrity for volume restore", status="Pending", assigned_to="Tier 2 Analyst")

            # Add timeline entries
            tl1 = models.IncidentTimeline(incident_id=inc1.id, event_type="log_ingested", message="Detection Rule 'Ransomware File Entropy High' triggered alert ALT-105", actor="SIEM Engine")
            tl2 = models.IncidentTimeline(incident_id=inc1.id, event_type="playbook_run", message="Automated Playbook 'Ransomware Host Isolation' executed successfully", actor="SOAR Engine")

            # Add comments
            c1 = models.IncidentComment(incident_id=inc1.id, comment_text="Primary host isolated via network policy. Host interface 10.0.1.5 is now non-routable.", author="SecOps Commander")
            c2 = models.IncidentComment(incident_id=inc1.id, comment_text="AI Copilot recommendation applied: Memory dump task queued.", author="AI Analyst Copilot")

            db.add_all([t1, t2, t3, tl1, tl2, c1, c2])
            db.commit()

        # 4. Check IOCs
        if db.query(models.IOC).count() == 0:
            ioc1 = models.IOC(value="185.12.33.44", type="IP", reputation="Malicious", category="APT29 C2 Server", threat_actor="Cozy Bear", description="Observed hosting malicious command and control infrastructure.", last_seen=datetime.utcnow())
            ioc2 = models.IOC(value="45.33.22.11", type="IP", reputation="Suspicious", category="Password Spray Proxy", threat_actor="Unknown", description="Known TOR exit node used for brute force scanning.", last_seen=datetime.utcnow())
            ioc3 = models.IOC(value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", type="Hash", reputation="Malicious", category="LockBit Payload", threat_actor="LockBit Ransomware Gang", description="LockBit 3.0 executable payload sample.", last_seen=datetime.utcnow())
            db.add_all([ioc1, ioc2, ioc3])
            db.commit()

    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
