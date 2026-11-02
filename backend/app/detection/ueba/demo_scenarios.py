"""
UEBA Synthetic Demonstration Scenarios.
Generates safe, non-destructive, strictly labeled (is_demo=True) anomalous activities
illustrating all 5 core UEBA detection patterns.
"""
from typing import Dict, Any, List
from datetime import datetime, timedelta
import uuid
from sqlalchemy.orm import Session

from app.detection.engine import detection_engine
from app.detection.ueba.baseline_engine import baseline_engine
from app.detection.ueba.finding_manager import finding_manager


class UEBADemoService:
    """Generates synthetic UEBA scenarios for live demonstration."""

    def run_scenario(self, db: Session, scenario: str = "all", entity_id: str = None) -> Dict[str, Any]:
        """
        Executes chosen UEBA demo scenario(s).
        Ensures baseline is seeded, creates anomalous event, runs through detection pipeline,
        and returns generated findings.
        """
        # Ensure default baseline profiles are initialized
        baseline_engine.seed_default_sample_profiles(db)

        scenarios_to_run = []
        if scenario == "all":
            scenarios_to_run = ["unusual_login_time", "dormant_account", "mass_resource_access", "auth_velocity", "bulk_data_exfiltration"]
        else:
            scenarios_to_run = [scenario]

        results = []
        for sc in scenarios_to_run:
            generator = getattr(self, f"_scenario_{sc}", None)
            if generator:
                res = generator(db, entity_id)
                results.append(res)

        return {
            "status": "success",
            "message": f"Successfully generated {len(results)} UEBA demonstration scenario(s).",
            "scenarios": results,
            "timestamp": datetime.utcnow().isoformat()
        }

    def _scenario_unusual_login_time(self, db: Session, target_user: str = None) -> Dict[str, Any]:
        """Scenario 1: User logs in at an unusual off-hours time (03:15 AM)."""
        username = target_user or "jsmith"
        now = datetime.utcnow()
        # Set timestamp to 03:15 AM
        anomaly_time = now.replace(hour=3, minute=15, second=22)

        raw_event = {
            "event_id": f"DEMO-UEBA-TIME-{uuid.uuid4().hex[:6].upper()}",
            "event_type": "login_success",
            "category": "Authentication",
            "severity": "medium",
            "username": username,
            "source_ip": "10.0.1.45",
            "dest_ip": "10.0.1.10",
            "source": "ActiveDirectory",
            "timestamp": anomaly_time.isoformat(),
            "details": {
                "workstation": "WKSTN-FIN-04",
                "auth_method": "Kerberos",
                "logon_type": 10,
                "_demo_scenario": "Unusual Login Time (03:15 AM)"
            },
            "is_demo": True
        }

        # Process through detection engine
        proc = detection_engine.process_event(db, raw_event)
        return {
            "scenario": "unusual_login_time",
            "entity": username,
            "event_id": raw_event["event_id"],
            "description": f"User @{username} logged in at 03:15 AM UTC (Baseline: 09:00-17:00 UTC)",
            "pipeline_result": proc
        }

    def _scenario_dormant_account(self, db: Session, target_user: str = None) -> Dict[str, Any]:
        """Scenario 2: Reactivation of an account dormant for > 90 days."""
        username = target_user or "sarah_hr"
        now = datetime.utcnow()

        raw_event = {
            "event_id": f"DEMO-UEBA-DORM-{uuid.uuid4().hex[:6].upper()}",
            "event_type": "login_success",
            "category": "Account Management",
            "severity": "high",
            "username": username,
            "source_ip": "198.51.100.99",
            "dest_ip": "10.0.1.5",
            "source": "Azure-AD",
            "timestamp": now.isoformat(),
            "details": {
                "is_dormant": True,
                "days_inactive": 94,
                "last_active": (now - timedelta(days=94)).isoformat(),
                "account_status": "Dormant / Leave of Absence",
                "_demo_scenario": "Dormant Account Reactivation (94 Days Inactive)"
            },
            "is_demo": True
        }

        proc = detection_engine.process_event(db, raw_event)
        return {
            "scenario": "dormant_account",
            "entity": username,
            "event_id": raw_event["event_id"],
            "description": f"Account @{username} activated after 94 days of dormancy.",
            "pipeline_result": proc
        }

    def _scenario_mass_resource_access(self, db: Session, target_user: str = None) -> Dict[str, Any]:
        """Scenario 3: User accesses unusual number of files/shares in a single session."""
        username = target_user or "bwayne"
        now = datetime.utcnow()

        raw_event = {
            "event_id": f"DEMO-UEBA-RES-{uuid.uuid4().hex[:6].upper()}",
            "event_type": "file_access",
            "category": "File Activity",
            "severity": "high",
            "username": username,
            "source_ip": "10.0.1.10",
            "dest_ip": "10.0.2.50",
            "source": "Windows-FileServer",
            "timestamp": now.isoformat(),
            "details": {
                "resource_count": 45,
                "shares_accessed_count": 45,
                "resources_list": [
                    "\\\\CORP-FS\\Finance\\Payroll_2026.xlsx",
                    "\\\\CORP-FS\\Exec\\Strategic_M&A.pdf",
                    "\\\\CORP-FS\\R&D\\SourceCode_Repository.zip",
                    "\\\\CORP-FS\\HR\\Executive_Salaries.csv"
                ],
                "action": "bulk_read",
                "_demo_scenario": "Mass Resource Access (45 Confidential Shares)"
            },
            "is_demo": True
        }

        proc = detection_engine.process_event(db, raw_event)
        return {
            "scenario": "mass_resource_access",
            "entity": username,
            "event_id": raw_event["event_id"],
            "description": f"User @{username} accessed 45 sensitive enterprise shares in 3 minutes.",
            "pipeline_result": proc
        }

    def _scenario_auth_velocity(self, db: Session, target_user: str = None) -> Dict[str, Any]:
        """Scenario 4: Account targeted by repeated rapid authentication failures from foreign IP."""
        username = target_user or "jsmith"
        now = datetime.utcnow()

        raw_event = {
            "event_id": f"DEMO-UEBA-AUTH-{uuid.uuid4().hex[:6].upper()}",
            "event_type": "login_failed",
            "category": "Authentication",
            "severity": "high",
            "username": username,
            "source_ip": "203.0.113.195",
            "dest_ip": "10.0.1.10",
            "source": "Okta-SSO",
            "timestamp": now.isoformat(),
            "details": {
                "failed_attempts": 18,
                "geo_location": "External / Unregistered Hosting Subnet",
                "failure_reason": "Invalid MFA Token / Bad Credentials",
                "_demo_scenario": "Repeated Authentication Failures & Velocity Spike"
            },
            "is_demo": True
        }

        proc = detection_engine.process_event(db, raw_event)
        return {
            "scenario": "auth_velocity",
            "entity": username,
            "event_id": raw_event["event_id"],
            "description": f"Account @{username} targeted by 18 rapid failed attempts from foreign IP.",
            "pipeline_result": proc
        }

    def _scenario_bulk_data_exfiltration(self, db: Session, target_user: str = None) -> Dict[str, Any]:
        """Scenario 5: Massive outbound data transfer exceeding baseline with high Z-score."""
        username = target_user or "bwayne"
        now = datetime.utcnow()

        raw_event = {
            "event_id": f"DEMO-UEBA-EXFIL-{uuid.uuid4().hex[:6].upper()}",
            "event_type": "network_connection",
            "category": "Network Security",
            "severity": "critical",
            "username": username,
            "source_ip": "10.0.1.10",
            "dest_ip": "198.51.100.80",
            "source": "PaloAlto-Firewall",
            "timestamp": now.isoformat(),
            "details": {
                "bytes_transferred": 8450.0,
                "data_mb": 8450.0,
                "protocol": "HTTPS / TLS",
                "dest_port": 443,
                "destination_hostname": "mega-cloud-storage-transfer.com",
                "_demo_scenario": "Massive Outbound Data Transfer (8.45 GB, Z-Score > 6.0)"
            },
            "is_demo": True
        }

        proc = detection_engine.process_event(db, raw_event)
        return {
            "scenario": "bulk_data_exfiltration",
            "entity": username,
            "event_id": raw_event["event_id"],
            "description": f"Entity @{username} transferred 8.45 GB outbound (Z-score: > 6.0).",
            "pipeline_result": proc
        }


ueba_demo_service = UEBADemoService()

