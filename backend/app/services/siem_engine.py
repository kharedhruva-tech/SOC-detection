import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.models import Alert, Asset, IOC, Incident, IncidentTimeline, IncidentTask
from app.database import SessionLocal

# Simple custom rule schema mock
# Rules can be defined as structured dicts that map logs to alerts.
RULES = [
    {
        "id": "RULE_001",
        "name": "Brute Force Attack Detected",
        "category": "Credential Abuse",
        "severity": "High",
        "description": "Multiple failed login attempts detected in a short time window on a single host.",
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110.001"],
        "condition": lambda log: log.get("event_id") == 4625 and log.get("failed_count", 0) >= 5
    },
    {
        "id": "RULE_002",
        "name": "Ransomware Behavior - Rapid File Modification",
        "category": "Ransomware",
        "severity": "Critical",
        "description": "Mass file renaming/modification activity with suspicious extensions (.locked, .crypt).",
        "mitre_tactics": ["Impact"],
        "mitre_techniques": ["T1486"],
        "condition": lambda log: log.get("source") == "Sysmon" and log.get("event_id") == 11 and log.get("file_extension") in [".locked", ".crypt", ".enc"]
    },
    {
        "id": "RULE_003",
        "name": "Lateral Movement - WMI Command Execution",
        "category": "Lateral Movement",
        "severity": "High",
        "description": "Remote execution of commands via WMI or WinRM detected.",
        "mitre_tactics": ["Execution", "Lateral Movement"],
        "mitre_techniques": ["T1047", "T1021.006"],
        "condition": lambda log: "wmic.exe" in log.get("command_line", "").lower() or "winrshost.exe" in log.get("command_line", "").lower()
    },
    {
        "id": "RULE_004",
        "name": "Data Exfiltration to Suspicious Domain",
        "category": "Data Exfiltration",
        "severity": "High",
        "description": "Large DNS query payload or outbound traffic to newly registered/suspicious domain.",
        "mitre_tactics": ["Exfiltration"],
        "mitre_techniques": ["T1048"],
        "condition": lambda log: log.get("category") == "DNS" and log.get("bytes_sent", 0) > 10000000  # >10MB
    },
    {
        "id": "RULE_005",
        "name": "Living off the Land - Suspicious Certutil Download",
        "category": "Defense Evasion",
        "severity": "Medium",
        "description": "Certutil command-line utility used to download external payload.",
        "mitre_tactics": ["Defense Evasion", "Command and Control"],
        "mitre_techniques": ["T1218.004", "T1105"],
        "condition": lambda log: "certutil" in log.get("command_line", "").lower() and ("-urlcache" in log.get("command_line", "").lower() or "-split" in log.get("command_line", "").lower())
    },
    {
        "id": "RULE_006",
        "name": "Impossible Travel Connection",
        "category": "UEBA Anomaly",
        "severity": "Medium",
        "description": "Successful logins from different geographic locations within an impossible timeframe.",
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1078"],
        "condition": lambda log: log.get("event_type") == "impossible_travel"
    }
]

class SIEMEngine:
    def __init__(self):
        # Keeps track of sliding window states (e.g., login failures per IP)
        self.failed_logins: Dict[str, List[datetime]] = {}
        self.active_connections = [] # For websocket alerts broadcast

    def register_websocket(self, websocket):
        self.active_connections.append(websocket)

    def unregister_websocket(self, websocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_alert(self, alert_data: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(alert_data))
            except Exception:
                # Connection might be dead, handled by socket close
                pass

    def ingest_log(self, db: Session, raw_log: Dict[str, Any]) -> List[Alert]:
        """
        Accepts a normalized or raw log, parses it, checks for correlation rules and IOCs,
        and generates database alerts.
        """
        alerts_generated = []
        
        # 1. Normalize Log Fields
        normalized = self._normalize_log(raw_log)
        
        # 2. Check for Bruteforce State
        if normalized.get("event_id") == 4625:  # Windows Security Log Failed Login
            ip = normalized.get("source_ip", "unknown")
            now = datetime.utcnow()
            
            if ip not in self.failed_logins:
                self.failed_logins[ip] = []
            
            # Prune attempts older than 1 minute
            self.failed_logins[ip] = [t for t in self.failed_logins[ip] if now - t < timedelta(minutes=1)]
            self.failed_logins[ip].append(now)
            
            normalized["failed_count"] = len(self.failed_logins[ip])

        # 3. Match against IOCs in Database
        ioc_match = self._check_iocs(db, normalized)
        if ioc_match:
            alert = self._create_alert_from_ioc(db, normalized, ioc_match)
            alerts_generated.append(alert)

        # 4. Check correlation rules
        for rule in RULES:
            try:
                if rule["condition"](normalized):
                    alert = self._create_alert_from_rule(db, normalized, rule)
                    alerts_generated.append(alert)
            except Exception as e:
                # Log or handle exceptions in rule evaluation
                pass
                
        # Broadcast generated alerts via WebSocket
        if alerts_generated:
            from app.ws_manager import ws_manager
            for alert in alerts_generated:
                alert_dict = {
                    "id": alert.id,
                    "title": alert.title,
                    "category": alert.category,
                    "severity": alert.severity,
                    "timestamp": alert.timestamp.isoformat() if alert.timestamp else "",
                    "status": alert.status
                }
                ws_manager.sync_broadcast(alert_dict)

        return alerts_generated

    def _normalize_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes raw logs from different structures to a standard schema.
        """
        # Ensure default values
        norm = log.copy()
        if "event_id" in norm:
            norm["event_id"] = int(norm["event_id"])
        return norm

    def _check_iocs(self, db: Session, log: Dict[str, Any]) -> Optional[IOC]:
        """
        Scans logs for known malicious IP, domain, URL, or hashes present in DB.
        """
        # Check source IP, destination IP, domains, and file hashes
        indicators = []
        if log.get("source_ip"):
            indicators.append((log["source_ip"], "IP"))
        if log.get("destination_ip"):
            indicators.append((log["destination_ip"], "IP"))
        if log.get("domain"):
            indicators.append((log["domain"], "Domain"))
        if log.get("file_hash"):
            indicators.append((log["file_hash"], "Hash"))

        for value, ioc_type in indicators:
            match = db.query(IOC).filter(IOC.value == value, IOC.reputation == "Malicious").first()
            if match:
                return match
        return None

    def _create_alert_from_ioc(self, db: Session, log: Dict[str, Any], ioc: IOC) -> Alert:
        # Resolve target asset if possible
        asset_id = None
        ip_to_check = log.get("source_ip") or log.get("host_ip")
        if ip_to_check:
            asset = db.query(Asset).filter(Asset.ip_address == ip_to_check).first()
            if asset:
                asset_id = asset.id

        alert = Alert(
            title=f"Malicious IOC Connection Detected: {ioc.value}",
            category="Threat Intelligence Match",
            severity="High",
            description=f"Outbound or inbound connection associated with malicious indicator: {ioc.value}. IOC Details: {ioc.description or 'No description'}. Category: {ioc.category}. Actor: {ioc.threat_actor}.",
            mitre_tactics=["Command and Control"],
            mitre_techniques=["T1071"],
            source_log=json.dumps(log),
            status="New",
            asset_id=asset_id,
            timestamp=datetime.utcnow()
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        self._auto_aggregate_to_incident(db, alert)
        return alert

    def _create_alert_from_rule(self, db: Session, log: Dict[str, Any], rule: Dict[str, Any]) -> Alert:
        asset_id = None
        ip_to_check = log.get("source_ip") or log.get("host_ip")
        if ip_to_check:
            asset = db.query(Asset).filter(Asset.ip_address == ip_to_check).first()
            if asset:
                asset_id = asset.id

        # Deduplication check: see if a similar active alert was raised for this asset in the last 5 mins
        five_mins_ago = datetime.utcnow() - timedelta(minutes=5)
        existing_alert = db.query(Alert).filter(
            Alert.title == rule["name"],
            Alert.asset_id == asset_id,
            Alert.timestamp >= five_mins_ago
        ).first()

        if existing_alert:
            # Mark as duplicate and return it
            alert = Alert(
                title=rule["name"],
                category=rule["category"],
                severity=rule["severity"],
                description=rule["description"] + f" (Duplicate of alert {existing_alert.id})",
                mitre_tactics=rule["mitre_tactics"],
                mitre_techniques=rule["mitre_techniques"],
                source_log=json.dumps(log),
                status="Acknowledged",
                is_duplicate=True,
                asset_id=asset_id,
                timestamp=datetime.utcnow()
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            return alert

        alert = Alert(
            title=rule["name"],
            category=rule["category"],
            severity=rule["severity"],
            description=rule["description"],
            mitre_tactics=rule["mitre_tactics"],
            mitre_techniques=rule["mitre_techniques"],
            source_log=json.dumps(log),
            status="New",
            asset_id=asset_id,
            timestamp=datetime.utcnow()
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        
        # Trigger incident grouping or auto-creation
        self._auto_aggregate_to_incident(db, alert)
        return alert

    def _auto_aggregate_to_incident(self, db: Session, alert: Alert):
        """
        Groups incoming alerts into related incidents or creates a new incident if none exists.
        Grouping is based on category and asset within the last 15 minutes.
        """
        if alert.is_duplicate:
            return

        fifteen_mins_ago = datetime.utcnow() - timedelta(minutes=15)
        # Search for an open incident with same asset or similar tactics
        matching_incident = db.query(Incident).filter(
            Incident.status == "Open",
            Incident.created_at >= fifteen_mins_ago
        ).order_by(Incident.created_at.desc()).first()
        
        # Simple grouping logic: if they share the asset or tactic
        is_grouped = False
        if matching_incident and alert.asset_id:
            # Check if any alert in incident has same asset_id
            asset_matches = db.query(Alert).filter(
                Alert.incident_id == matching_incident.id,
                Alert.asset_id == alert.asset_id
            ).first()
            if asset_matches:
                alert.incident_id = matching_incident.id
                # Append tactics / techniques
                tactics = set(matching_incident.mitre_tactics or [])
                techniques = set(matching_incident.mitre_techniques or [])
                tactics.update(alert.mitre_tactics)
                techniques.update(alert.mitre_techniques)
                matching_incident.mitre_tactics = list(tactics)
                matching_incident.mitre_techniques = list(techniques)
                
                # Recalculate incident risk score based on severity of alerts
                matching_incident.risk_score = min(100.0, matching_incident.risk_score + 15.0)
                
                # Add to timeline
                timeline_entry = IncidentTimeline(
                    incident_id=matching_incident.id,
                    event_type="alert_aggregated",
                    message=f"Alert '{alert.title}' aggregated into incident automatically.",
                    actor="SIEM Engine"
                )
                db.add(timeline_entry)
                db.commit()
                is_grouped = True

        if not is_grouped:
            # Create a brand new incident
            severity_risk_map = {"Informational": 10.0, "Low": 25.0, "Medium": 50.0, "High": 75.0, "Critical": 95.0}
            risk_score = severity_risk_map.get(alert.severity, 50.0)
            
            new_incident = Incident(
                title=f"Incident: {alert.title}",
                description=f"Automated incident generated for alert: {alert.description}",
                severity=alert.severity,
                status="Open",
                risk_score=risk_score,
                mitre_tactics=alert.mitre_tactics,
                mitre_techniques=alert.mitre_techniques,
                creator="SIEM Engine"
            )
            db.add(new_incident)
            db.commit()
            db.refresh(new_incident)
            
            # Associate alert
            alert.incident_id = new_incident.id
            
            # Create timeline entry
            timeline_entry = IncidentTimeline(
                incident_id=new_incident.id,
                event_type="incident_created",
                message=f"Incident created automatically from alert '{alert.title}'.",
                actor="SIEM Engine"
            )
            db.add(timeline_entry)
            
            # Prepopulate standard response tasks based on severity/category
            tasks = [
                "Investigate raw logs and asset configuration.",
                "Verify alert source validity (check for false positives).",
                "Review host timeline and check for lateral movement."
            ]
            if alert.severity in ["High", "Critical"]:
                tasks.extend([
                    "Isolate host if active infection is confirmed.",
                    "Verify user credentials and reset password if compromised."
                ])
                
            for task_desc in tasks:
                task = IncidentTask(
                    incident_id=new_incident.id,
                    description=task_desc,
                    status="Pending"
                )
                db.add(task)
            
            db.commit()

    # Alias so log_generator can call self.siem.process_log()
    def process_log(self, db: Session, raw_log: Dict[str, Any]) -> List[Alert]:
        return self.ingest_log(db, raw_log)

siem_engine = SIEMEngine()
