"""
Safe Synthetic Security Event Generator for SIEM Demo Scenarios.
Generates simulated, non-destructive security events for all 10 detection rules.
All events are strictly tagged with is_demo=True and perform no real system mutations.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.detection.engine import detection_engine
from app.models.models import SecurityEvent, SecurityAlert, Alert


class DemoEventGenerator:
    """Generates synthetic security events tailored for each detection rule."""

    @staticmethod
    def _create_event(event_type: str, username: Optional[str] = None,
                      source_ip: Optional[str] = None, dest_ip: Optional[str] = None,
                      source: str = "demo_telemetry", severity: str = "low",
                      details: Optional[Dict[str, Any]] = None,
                      timestamp_offset_seconds: int = 0) -> Dict[str, Any]:
        ts = datetime.utcnow() + timedelta(seconds=timestamp_offset_seconds)
        dt = details or {}
        dt["_demo_disclaimer"] = "SAFE SYNTHETIC DEMONSTRATION LOG. NO REAL SYSTEM COMPROMISE."
        return {
            "event_id": f"DEMO-{uuid.uuid4().hex[:8].upper()}",
            "event_type": event_type,
            "username": username,
            "source_ip": source_ip or "192.168.100.45",
            "dest_ip": dest_ip or "10.0.1.10",
            "timestamp": ts.isoformat(),
            "source": source,
            "severity": severity,
            "details": dt,
            "is_demo": True
        }

    # --- Scenario Generators for each of the 10 Rules ---

    @classmethod
    def generate_brute_force_scenario(cls) -> List[Dict[str, Any]]:
        """BR-001: 6 repeated failed logins for user 'admin' from same IP."""
        events = []
        attacker_ip = "198.51.100.88"
        for i in range(6):
            events.append(cls._create_event(
                event_type="login_failed",
                username="admin",
                source_ip=attacker_ip,
                source="ActiveDirectory",
                severity="medium",
                details={
                    "event_id": 4625,
                    "failure_reason": "Bad password supplied",
                    "sub_status": "0xC000006A",
                    "workstation": "ATTACK-BOX"
                },
                timestamp_offset_seconds=-20 + (i * 2)
            ))
        return events

    @classmethod
    def generate_password_spray_scenario(cls) -> List[Dict[str, Any]]:
        """PS-002: Failed logins across 4 distinct accounts from 1 single IP."""
        events = []
        attacker_ip = "203.0.113.142"
        target_users = ["alice.walker", "bob.finance", "charlie.it", "david.exec"]
        for i, user in enumerate(target_users):
            events.append(cls._create_event(
                event_type="login_failed",
                username=user,
                source_ip=attacker_ip,
                source="Okta-Identity",
                severity="medium",
                details={
                    "auth_method": "Password",
                    "user_agent": "Python-requests/2.28.1",
                    "spray_batch": "Batch-001"
                },
                timestamp_offset_seconds=-30 + (i * 5)
            ))
        return events

    @classmethod
    def generate_multiple_failed_login_scenario(cls) -> List[Dict[str, Any]]:
        """LF-003: 4 failed logins on single account 'jsmith' across distinct IPs."""
        events = []
        ips = ["192.168.1.105", "10.50.2.14", "198.51.100.40", "172.16.5.99"]
        for i, ip in enumerate(ips):
            events.append(cls._create_event(
                event_type="login_failed",
                username="jsmith",
                source_ip=ip,
                source="SSO-Portal",
                severity="low",
                details={
                    "failure_code": "AUTH_FAILED",
                    "attempt_number": i + 1
                },
                timestamp_offset_seconds=-40 + (i * 8)
            ))
        return events

    @classmethod
    def generate_unusual_login_time_scenario(cls) -> List[Dict[str, Any]]:
        """UL-004: Login attempt at 03:15 AM UTC for unauthorized standard user."""
        night_time = datetime.utcnow().replace(hour=3, minute=15, second=0)
        return [{
            "event_id": f"DEMO-{uuid.uuid4().hex[:8].upper()}",
            "event_type": "login_success",
            "username": "night_auditor_guest",
            "source_ip": "10.0.10.22",
            "dest_ip": "10.0.1.5",
            "timestamp": night_time.isoformat(),
            "source": "VPN-Gateway",
            "severity": "medium",
            "details": {
                "vpn_profile": "Standard-Remote",
                "session_type": "Interactive"
            },
            "is_demo": True
        }]

    @classmethod
    def generate_privilege_escalation_scenario(cls) -> List[Dict[str, Any]]:
        """PE-005: Standard user granted Super Admin by unauthorized actor."""
        return [cls._create_event(
            event_type="privilege_change",
            username="intern_bob",
            source_ip="10.0.2.55",
            source="Windows-Security",
            severity="high",
            details={
                "event_id": 4728,
                "target_user": "intern_bob",
                "new_role": "Super Admin",
                "delegator": "unauthorized_script_svc",
                "group_name": "Domain Admins",
                "command_line": "net localgroup administrators intern_bob /add"
            }
        )]

    @classmethod
    def generate_suspicious_file_scenario(cls) -> List[Dict[str, Any]]:
        """FA-006: Unauthorized modification to /etc/shadow or Windows SAM."""
        return [cls._create_event(
            event_type="file_modify",
            username="daemon_service",
            source_ip="10.0.1.5",
            source="Sysmon-Linux",
            severity="high",
            details={
                "event_id": 11,
                "file_path": "/etc/shadow",
                "action": "modify",
                "process": "unknown_injector.elf",
                "process_id": 9412
            }
        )]

    @classmethod
    def generate_malware_indicator_scenario(cls) -> List[Dict[str, Any]]:
        """MD-007: Endpoint detection of Mimikatz LSASS memory dumper."""
        return [cls._create_event(
            event_type="malware_detected",
            username="bwayne",
            source_ip="10.0.2.100",
            source="CrowdStrike-Falcon",
            severity="critical",
            details={
                "threat_name": "HackTool:Win64/Mimikatz.A!dha",
                "file_hash": "44d88612fea8a8f36de82e1278abb02f",
                "process_name": "mimikatz.exe",
                "detection_engine": "Behavioral Heuristics",
                "action_taken": "Quarantined"
            }
        )]

    @classmethod
    def generate_port_scan_scenario(cls) -> List[Dict[str, Any]]:
        """PS-008: Rapid connection attempts to 7 distinct network ports."""
        events = []
        scanner_ip = "192.168.200.77"
        ports = [21, 22, 23, 80, 443, 3389, 8080]
        for i, port in enumerate(ports):
            events.append(cls._create_event(
                event_type="network_connection",
                source_ip=scanner_ip,
                dest_ip="10.0.1.5",
                source="PaloAlto-Firewall",
                severity="low",
                details={
                    "dest_port": port,
                    "protocol": "TCP",
                    "action": "DENY"
                },
                timestamp_offset_seconds=-15 + (i * 2)
            ))
        return events

    @classmethod
    def generate_data_exfiltration_scenario(cls) -> List[Dict[str, Any]]:
        """DE-009: Outbound transfer of 45 MB to external IP."""
        return [cls._create_event(
            event_type="data_transfer",
            username="backup_contractor",
            source_ip="10.0.1.20",
            dest_ip="185.220.101.5",
            source="Zeek-Bro-IDS",
            severity="high",
            details={
                "bytes_sent": 47185920,  # ~45 MB
                "protocol": "HTTPS",
                "destination_country": "Anonymous Proxy",
                "direction": "outbound"
            }
        )]

    @classmethod
    def generate_unexpected_account_creation_scenario(cls) -> List[Dict[str, Any]]:
        """AC-010: Unauthorized creation of account 'temp_backdoor_admin'."""
        return [cls._create_event(
            event_type="account_created",
            username="temp_backdoor_admin",
            source_ip="10.0.5.12",
            source="ActiveDirectory",
            severity="medium",
            details={
                "event_id": 4720,
                "created_account": "temp_backdoor_admin",
                "creator": "guest_operator",
                "assigned_privilege": "Local-User"
            }
        )]

    @classmethod
    def generate_normal_activity_scenario(cls) -> List[Dict[str, Any]]:
        """Legitimate normal events that should NOT trigger alerts."""
        normal_events = [
            cls._create_event(
                event_type="login_success",
                username="admin",
                source_ip="10.0.1.15",
                source="ActiveDirectory",
                details={"event_id": 4624, "message": "Standard admin logon"}
            ),
            cls._create_event(
                event_type="file_modify",
                username="developer",
                source_ip="10.0.2.80",
                source="FileServer",
                details={"file_path": "/var/www/html/index.html", "action": "write"}
            ),
            cls._create_event(
                event_type="network_connection",
                source_ip="10.0.2.80",
                dest_ip="8.8.8.8",
                source="Firewall",
                details={"dest_port": 443, "protocol": "TCP", "action": "ALLOW"}
            )
        ]
        return normal_events

    @classmethod
    def run_scenario(cls, db: Session, scenario_key: str) -> Dict[str, Any]:
        """Executes a chosen synthetic scenario through the detection engine."""
        scenario_map = {
            "BR-001": cls.generate_brute_force_scenario,
            "PS-002": cls.generate_password_spray_scenario,
            "LF-003": cls.generate_multiple_failed_login_scenario,
            "UL-004": cls.generate_unusual_login_time_scenario,
            "PE-005": cls.generate_privilege_escalation_scenario,
            "FA-006": cls.generate_suspicious_file_scenario,
            "MD-007": cls.generate_malware_indicator_scenario,
            "PS-008": cls.generate_port_scan_scenario,
            "DE-009": cls.generate_data_exfiltration_scenario,
            "AC-010": cls.generate_unexpected_account_creation_scenario,
            "normal": cls.generate_normal_activity_scenario,
        }

        # Run all if "all" is requested
        if scenario_key.lower() == "all":
            all_results = []
            for k, func in scenario_map.items():
                if k == "normal":
                    continue
                events = func()
                for evt in events:
                    res = detection_engine.process_event(db, evt)
                    all_results.append(res)
            return {
                "scenario": "ALL_10_RULES",
                "processed_count": len(all_results),
                "summary": "Simulated all 10 cyber attack scenarios successfully."
            }

        generator_func = scenario_map.get(scenario_key.upper()) or scenario_map.get(scenario_key.lower())
        if not generator_func:
            # Fallback to normal activity
            generator_func = cls.generate_normal_activity_scenario

        events = generator_func()
        results = []
        for evt in events:
            res = detection_engine.process_event(db, evt)
            results.append(res)

        alerts_created = []
        for r in results:
            alerts_created.extend(r.get("alerts_created", []))

        return {
            "scenario": scenario_key,
            "events_generated": len(events),
            "alerts_created": alerts_created,
            "results": results
        }

    @staticmethod
    def reset_demo_data(db: Session) -> Dict[str, Any]:
        """Safely removes all DEMO events and DEMO alerts from the database."""
        deleted_alerts = db.query(SecurityAlert).filter(SecurityAlert.is_demo == True).delete()
        deleted_legacy = db.query(Alert).filter(Alert.is_demo == True).delete()
        deleted_events = db.query(SecurityEvent).filter(SecurityEvent.is_demo == True).delete()
        db.commit()

        from app.detection.correlation import correlation_tracker
        correlation_tracker.reset()

        return {
            "message": "Demo simulation data successfully purged.",
            "deleted_events_count": deleted_events,
            "deleted_alerts_count": deleted_alerts + deleted_legacy
        }

