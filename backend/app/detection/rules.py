"""
Concrete SIEM Detection Rules (BR-001 through AC-010).
Modular rule implementations with customizable thresholds, evidence generation,
and MITRE ATT&CK mappings.
"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field

from app.detection.event_normalizer import StandardizedEvent
from app.detection.correlation import CorrelationTracker
from app.detection.rule_config import CATEGORIES, SEVERITIES


class DetectionMatch(BaseModel):
    """Represents a successful detection rule match with forensic evidence."""
    rule_id: str
    rule_name: str
    alert_title: str
    description: str
    severity: str
    category: str
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    matched_event_ids: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    entity_key: str  # Used for cooldown tracking (e.g., source IP, user, host)


class BaseDetectionRule(ABC):
    """Base class for all SIEM detection rules."""

    def __init__(self, rule_id: str, name: str, category: str, severity: str,
                 description: str, mitre_tactics: List[str], mitre_techniques: List[str],
                 enabled: bool = True, configuration: Optional[Dict[str, Any]] = None):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.description = description
        self.mitre_tactics = mitre_tactics
        self.mitre_techniques = mitre_techniques
        self.enabled = enabled
        self.config = configuration or {}

    @abstractmethod
    def evaluate(self, event: StandardizedEvent, correlation: CorrelationTracker) -> Optional[DetectionMatch]:
        """Evaluates an event against the detection rule logic."""
        pass


# ==========================================
# RULE 1: BRUTE FORCE DETECTION (BR-001)
# ==========================================
class BruteForceRule(BaseDetectionRule):
    """
    BR-001: Identify repeated failed login attempts associated with the same source IP and account.
    Example: 5 or more failed login events from the same source IP within 1 minute.
    """
    def evaluate(self, event: StandardizedEvent, correlation: CorrelationTracker) -> Optional[DetectionMatch]:
        if not self.enabled:
            return None

        if event.event_type != "login_failed":
            return None

        threshold = int(self.config.get("failed_attempts_threshold", 5))
        window_seconds = int(self.config.get("time_window_seconds", 60))
        cooldown_seconds = int(self.config.get("cooldown_seconds", 120))

        source_ip = event.source_ip or "unknown"
        username = (event.username or "unknown").lower()
        entity_key = f"{source_ip}::{username}"

        # Record event in correlation window
        correlation.record_failed_login(source_ip, username, event.timestamp, event.event_id)

        # Query sliding window
        matched_records = correlation.get_failed_logins_for_ip_user(
            source_ip, username, window_seconds, event.timestamp
        )

        if len(matched_records) >= threshold:
            if correlation.is_in_cooldown(self.rule_id, entity_key, cooldown_seconds):
                return None

            event_ids = [eid for _, eid in matched_records]
            evidence = {
                "rule_id": self.rule_id,
                "trigger_condition": f"Observed {len(matched_records)} failed logins for account '{username}' from IP '{source_ip}' within {window_seconds}s (Threshold: {threshold})",
                "source_ip": source_ip,
                "target_account": username,
                "observed_count": len(matched_records),
                "threshold": threshold,
                "window_seconds": window_seconds,
                "first_attempt": matched_records[0][0].isoformat(),
                "latest_attempt": matched_records[-1][0].isoformat(),
                "risk_assessment": "High probability of automated dictionary or brute force credential attack targeting a specific account."
            }

            return DetectionMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                alert_title="Possible Brute Force Attempt",
                description=f"Possible Brute Force attack detected against account '{username}' from source IP {source_ip}.",
                severity=self.severity,
                category=self.category,
                mitre_tactics=self.mitre_tactics,
                mitre_techniques=self.mitre_techniques,
                matched_event_ids=event_ids,
                evidence=evidence,
                entity_key=entity_key
            )
        return None


# ==========================================
# RULE 2: PASSWORD SPRAYING DETECTION (PS-002)
# ==========================================
class PasswordSprayingRule(BaseDetectionRule):
    """
    PS-002: Identify repeated authentication failures involving multiple distinct accounts
    associated with the same source.
    """
    def evaluate(self, event: StandardizedEvent, correlation: CorrelationTracker) -> Optional[DetectionMatch]:
        if not self.enabled:
            return None

        if event.event_type != "login_failed":
            return None

        distinct_threshold = int(self.config.get("distinct_users_threshold", 3))
        window_seconds = int(self.config.get("time_window_seconds", 180))
        cooldown_seconds = int(self.config.get("cooldown_seconds", 180))

        source_ip = event.source_ip or "unknown"
        username = (event.username or "unknown").lower()
        entity_key = f"spray::{source_ip}"

        # In case Rule 1 hasn't recorded it yet
        correlation.record_failed_login(source_ip, username, event.timestamp, event.event_id)

        user_map = correlation.get_distinct_failed_users_for_ip(source_ip, window_seconds, event.timestamp)
        distinct_users = list(user_map.keys())

        if len(distinct_users) >= distinct_threshold:
            if correlation.is_in_cooldown(self.rule_id, entity_key, cooldown_seconds):
                return None

            all_event_ids = []
            for u in distinct_users:
                all_event_ids.extend(user_map[u])

            evidence = {
                "rule_id": self.rule_id,
                "trigger_condition": f"Observed failed logins across {len(distinct_users)} distinct accounts from single IP '{source_ip}' within {window_seconds}s (Threshold: {distinct_threshold} accounts)",
                "source_ip": source_ip,
                "distinct_accounts_count": len(distinct_users),
                "targeted_accounts": distinct_users,
                "threshold": distinct_threshold,
                "window_seconds": window_seconds,
                "risk_assessment": "Characteristics match horizontal password spraying designed to circumvent single-account lockout policies."
            }

            return DetectionMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                alert_title="Possible Password Spraying Activity",
                description=f"Possible Password Spraying detected from source IP {source_ip} targeting {len(distinct_users)} distinct user accounts.",
                severity=self.severity,
                category=self.category,
                mitre_tactics=self.mitre_tactics,
                mitre_techniques=self.mitre_techniques,
                matched_event_ids=all_event_ids[:20],
                evidence=evidence,
                entity_key=entity_key
            )
        return None


# ==========================================
# RULE 3: MULTIPLE FAILED LOGIN DETECTION (LF-003)
# ==========================================
class MultipleFailedLoginRule(BaseDetectionRule):
    """
    LF-003: Identify repeated login failures associated with an individual account across any sources.
    """
    def evaluate(self, event: StandardizedEvent, correlation: CorrelationTracker) -> Optional[DetectionMatch]:
        if not self.enabled:
            return None

        if event.event_type != "login_failed":
            return None

        threshold = int(self.config.get("failed_attempts_threshold", 3))
        window_seconds = int(self.config.get("time_window_seconds", 120))
        cooldown_seconds = int(self.config.get("cooldown_seconds", 120))

        username = (event.username or "").lower()
        if not username:
            return None

        entity_key = f"user_fail::{username}"
        correlation.record_failed_login(event.source_ip, username, event.timestamp, event.event_id)

        matched_records = correlation.get_failed_logins_for_user(username, window_seconds, event.timestamp)

        if len(matched_records) >= threshold:
            if correlation.is_in_cooldown(self.rule_id, entity_key, cooldown_seconds):
                return None

            event_ids = [eid for _, eid in matched_records]
            evidence = {
                "rule_id": self.rule_id,
                "trigger_condition": f"Observed {len(matched_records)} authentication failures for account '{username}' within {window_seconds}s (Threshold: {threshold})",
                "target_account": username,
                "failure_count": len(matched_records),
                "threshold": threshold,
                "window_seconds": window_seconds,
                "source_ip": event.source_ip,
                "risk_assessment": "Repeated login failures on account indicate potential unauthorized access attempts or forgotten credentials."
            }

            return DetectionMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                alert_title="Suspicious Login Activity",
                description=f"Suspicious repeated login failures for account '{username}' ({len(matched_records)} failures in {window_seconds}s).",
                severity=self.severity,
                category=self.category,
                mitre_tactics=self.mitre_tactics,
                mitre_techniques=self.mitre_techniques,
                matched_event_ids=event_ids,
                evidence=evidence,
                entity_key=entity_key
            )
        return None


# ==========================================
# RULE 4: UNUSUAL LOGIN TIME DETECTION (UL-004)
# ==========================================
class UnusualLoginTimeRule(BaseDetectionRule):
    """
    UL-004: Identify login activity outside a configurable normal login schedule with timezone
    and whitelist exemptions.
    """
    def evaluate(self, event: StandardizedEvent, correlation: CorrelationTracker) -> Optional[DetectionMatch]:
        if not self.enabled:
            return None

        if event.event_type not in ["login_success", "login_failed"]:
            return None

        username = (event.username or "").lower()
        if not username:
            return None

        authorized_users = [u.lower() for u in self.config.get("authorized_users", ["admin", "system_service", "backup_agent", "soc_manager"])]
        if username in authorized_users:
            return None

        start_hour = int(self.config.get("business_hours_start", 8))
        end_hour = int(self.config.get("business_hours_end", 18))
        utc_offset = float(self.config.get("utc_offset_hours", 0.0))
        allowed_weekdays = self.config.get("allowed_weekdays", [0, 1, 2, 3, 4])
        cooldown_seconds = int(self.config.get("cooldown_seconds", 60))

        # Calculate localized hour and weekday
        adjusted_hour = (event.timestamp.hour + int(utc_offset)) % 24
        weekday = event.timestamp.weekday()

        is_off_hours = adjusted_hour < start_hour or adjusted_hour >= end_hour
        is_weekend = weekday not in allowed_weekdays

        if is_off_hours or is_weekend:
            entity_key = f"unusual_time::{username}"
            if correlation.is_in_cooldown(self.rule_id, entity_key, cooldown_seconds):
                return None

            reason = "Off-hours login" if is_off_hours else "Weekend login"
            if is_off_hours and is_weekend:
                reason = "Off-hours and weekend login"

            evidence = {
                "rule_id": self.rule_id,
                "trigger_condition": f"Authentication occurred at {adjusted_hour:02d}:{event.timestamp.minute:02d} (Local UTC{utc_offset:+g}), outside normal business hours ({start_hour:02d}:00-{end_hour:02d}:00)",
                "account": username,
                "source_ip": event.source_ip,
                "event_status": "Successful Logon" if event.event_type == "login_success" else "Failed Logon",
                "local_hour": adjusted_hour,
                "business_hours": f"{start_hour:02d}:00 - {end_hour:02d}:00",
                "weekday": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][weekday],
                "reason": reason,
                "risk_assessment": "Login outside standard operational hours may indicate compromised credentials utilized in foreign timezones or after-hours insider activity."
            }

            return DetectionMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                alert_title="Unusual Login Time Detected",
                description=f"Unusual login time detected for user '{username}' at {adjusted_hour:02d}:{event.timestamp.minute:02d} ({reason}).",
                severity=self.severity,
                category=self.category,
                mitre_tactics=self.mitre_tactics,
                mitre_techniques=self.mitre_techniques,
                matched_event_ids=[event.event_id],
                evidence=evidence,
                entity_key=entity_key
            )
        return None


# ==========================================
# RULE 5: PRIVILEGE ESCALATION DETECTION (PE-005)
# ==========================================
class PrivilegeEscalationRule(BaseDetectionRule):
    """
    PE-005: Identify unexpected user privilege or role changes.
    """
    def evaluate(self, event: StandardizedEvent, correlation: CorrelationTracker) -> Optional[DetectionMatch]:
        if not self.enabled:
            return None

        target_roles = [r.lower() for r in self.config.get("target_roles", ["admin", "super admin", "root", "wheel", "domain admin", "administrator", "sudo"])]
        authorized_delegators = [d.lower() for d in self.config.get("authorized_delegators", ["admin", "root", "super admin", "system_provisioner"])]
        suspicious_cmds = [c.lower() for c in self.config.get("suspicious_commands", ["net localgroup administrators /add", "usermod -ag sudo", "usermod -ag wheel", "chmod +s"])]
        cooldown_seconds = int(self.config.get("cooldown_seconds", 60))

        matched = False
        reason = ""
        user = event.username or event.details.get("target_user") or "unknown"
        delegator = (event.details.get("delegator") or event.details.get("actor") or event.details.get("created_by") or "").lower()
        new_role = (event.details.get("new_role") or event.details.get("role") or event.details.get("group") or "").lower()
        cmd_line = (event.details.get("command_line") or event.details.get("process") or "").lower()

        if event.event_type in ["privilege_change", "special_privilege_assigned", "role_change"]:
            if any(tr in new_role for tr in target_roles):
                if delegator not in authorized_delegators:
                    matched = True
                    reason = f"Account '{user}' was granted privileged role '{new_role}' by unauthorized actor '{delegator or 'System/Unknown'}'"

        if not matched and cmd_line:
            for sc in suspicious_cmds:
                if sc in cmd_line:
                    matched = True
                    reason = f"Execution of privilege escalation command: '{cmd_line}'"
                    break

        if matched:
            entity_key = f"priv_esc::{user}::{event.source_ip}"
            if correlation.is_in_cooldown(self.rule_id, entity_key, cooldown_seconds):
                return None

            evidence = {
                "rule_id": self.rule_id,
                "trigger_condition": reason,
                "target_user": user,
                "delegator": delegator or "Unverified / Malicious process",
                "assigned_role": new_role or "Administrative Group",
                "command_line": cmd_line,
                "source_ip": event.source_ip,
                "risk_assessment": "Unauthorized elevation of privilege can allow adversaries to bypass security controls, access sensitive repositories, or persist undetected."
            }

            return DetectionMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                alert_title="Possible Privilege Escalation",
                description=f"Possible Privilege Escalation detected for user '{user}'. {reason}.",
                severity=self.severity,
                category=self.category,
                mitre_tactics=self.mitre_tactics,
                mitre_techniques=self.mitre_techniques,
                matched_event_ids=[event.event_id],
                evidence=evidence,
                entity_key=entity_key
            )
        return None


# ==========================================
# RULE 6: SUSPICIOUS FILE ACTIVITY DETECTION (FA-006)
# ==========================================
class SuspiciousFileActivityRule(BaseDetectionRule):
    """
    FA-006: Identify unexpected modifications to configured sensitive files or monitored directories.
    """
    def evaluate(self, event: StandardizedEvent, correlation: CorrelationTracker) -> Optional[DetectionMatch]:
        if not self.enabled:
            return None

        if event.event_type not in ["file_modify", "file_delete", "file_create", "file_write"]:
            return None

        monitored_paths = [p.lower() for p in self.config.get("monitored_paths", [
            "/etc/shadow", "/etc/passwd", "/etc/sudoers",
            "c:\\windows\\system32\\drivers\\etc\\hosts",
            "c:\\windows\\system32\\config\\sam",
            "/var/log/auth.log"
        ])]
        monitored_actions = [a.lower() for a in self.config.get("monitored_actions", ["modify", "delete", "write", "rename", "permission_change"])]
        cooldown_seconds = int(self.config.get("cooldown_seconds", 60))

        target_file = (
            event.details.get("file_path")
            or event.details.get("path")
            or event.details.get("target_file")
            or event.details.get("file")
            or ""
        ).lower()

        if not target_file:
            return None

        action = (event.details.get("action") or event.event_type.replace("file_", "")).lower()

        # Check if file path matches any monitored path
        matched_path = None
        for mp in monitored_paths:
            if mp in target_file or target_file.endswith(mp.replace("\\", "/")) or target_file.endswith(mp):
                matched_path = mp
                break

        if matched_path and any(act in action for act in monitored_actions):
            entity_key = f"file_mod::{target_file}"
            if correlation.is_in_cooldown(self.rule_id, entity_key, cooldown_seconds):
                return None

            process_name = event.details.get("process") or event.details.get("process_name") or "unknown.exe"
            evidence = {
                "rule_id": self.rule_id,
                "trigger_condition": f"Monitored sensitive file '{target_file}' experienced action '{action}' by process '{process_name}'",
                "file_path": target_file,
                "action": action,
                "process": process_name,
                "user": event.username,
                "source_ip": event.source_ip,
                "risk_assessment": "Modification or deletion of sensitive system configuration, credentials, or audit logs signifies defense evasion or system tampering."
            }

            return DetectionMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                alert_title="Suspicious File Modification Detected",
                description=f"Suspicious file {action} on monitored critical asset '{target_file}'.",
                severity=self.severity,
                category=self.category,
                mitre_tactics=self.mitre_tactics,
                mitre_techniques=self.mitre_techniques,
                matched_event_ids=[event.event_id],
                evidence=evidence,
                entity_key=entity_key
            )
        return None


# ==========================================
# RULE 7: MALWARE INDICATOR DETECTION (MD-007)
# ==========================================
class MalwareIndicatorRule(BaseDetectionRule):
    """
    MD-007: Identify malware indicators reported by authorized endpoint security logs
    or supplied threat intelligence data.
    """
    def evaluate(self, event: StandardizedEvent, correlation: CorrelationTracker) -> Optional[DetectionMatch]:
        if not self.enabled:
            return None

        known_hashes = [h.lower() for h in self.config.get("known_malicious_hashes", [])]
        known_signatures = [s.lower() for s in self.config.get("known_signatures", [])]
        cooldown_seconds = int(self.config.get("cooldown_seconds", 60))

        file_hash = (
            event.details.get("file_hash")
            or event.details.get("hash")
            or event.details.get("sha256")
            or event.details.get("md5")
            or ""
        ).lower()

        threat_name = (
            event.details.get("threat_name")
            or event.details.get("malware_family")
            or event.details.get("signature")
            or event.details.get("threat")
            or ""
        ).lower()

        process_name = (
            event.details.get("process_name")
            or event.details.get("process")
            or event.details.get("image")
            or ""
        ).lower()

        matched_indicator = None
        indicator_type = None

        if file_hash and file_hash in known_hashes:
            matched_indicator = file_hash
            indicator_type = "Malicious File Hash (SHA-256/MD5)"
        elif threat_name and any(sig in threat_name for sig in known_signatures):
            matched_indicator = threat_name
            indicator_type = "Endpoint Antivirus / EDR Threat Signature"
        elif process_name and any(sig in process_name for sig in known_signatures):
            matched_indicator = process_name
            indicator_type = "Known Threat / Hacking Tool Process"
        elif event.event_type == "malware_detected":
            matched_indicator = threat_name or process_name or "Heuristic EDR Detection"
            indicator_type = "EDR Security Alert"

        if matched_indicator:
            entity_key = f"malware::{matched_indicator}::{event.source_ip}"
            if correlation.is_in_cooldown(self.rule_id, entity_key, cooldown_seconds):
                return None

            evidence = {
                "rule_id": self.rule_id,
                "trigger_condition": f"Identified malware indicator '{matched_indicator}' ({indicator_type})",
                "indicator_type": indicator_type,
                "matched_value": matched_indicator,
                "source": event.source,
                "host_ip": event.source_ip,
                "user": event.username,
                "file_hash": file_hash,
                "threat_name": threat_name,
                "process_name": process_name,
                "risk_assessment": "Known malware execution or presence threatens complete host compromise, lateral movement, or data encryption."
            }

            return DetectionMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                alert_title="Possible Malware Activity Detected",
                description=f"Possible Malware Activity Detected: {indicator_type} '{matched_indicator}' on host {event.source_ip or 'endpoint'}.",
                severity=self.severity,
                category=self.category,
                mitre_tactics=self.mitre_tactics,
                mitre_techniques=self.mitre_techniques,
                matched_event_ids=[event.event_id],
                evidence=evidence,
                entity_key=entity_key
            )
        return None


# ==========================================
# RULE 8: PORT SCAN DETECTION (PS-008)
# ==========================================
class PortScanRule(BaseDetectionRule):
    """
    PS-008: Identify unusual network connection patterns from authorized network logs
    across distinct destination ports.
    """
    def evaluate(self, event: StandardizedEvent, correlation: CorrelationTracker) -> Optional[DetectionMatch]:
        if not self.enabled:
            return None

        if event.event_type not in ["network_connection", "port_scan", "firewall_block"]:
            return None

        distinct_threshold = int(self.config.get("distinct_ports_threshold", 5))
        window_seconds = int(self.config.get("time_window_seconds", 60))
        cooldown_seconds = int(self.config.get("cooldown_seconds", 120))

        source_ip = event.source_ip or "unknown"
        dest_port = event.details.get("dest_port") or event.details.get("port") or event.details.get("destination_port")
        if dest_port is not None:
            try:
                dest_port = int(dest_port)
            except (ValueError, TypeError):
                dest_port = None

        if dest_port is not None:
            correlation.record_network_connection(source_ip, dest_port, event.timestamp, event.event_id)

        port_map = correlation.get_distinct_ports_for_ip(source_ip, window_seconds, event.timestamp)
        distinct_ports = sorted(list(port_map.keys()))

        if len(distinct_ports) >= distinct_threshold:
            entity_key = f"scan::{source_ip}"
            if correlation.is_in_cooldown(self.rule_id, entity_key, cooldown_seconds):
                return None

            all_event_ids = []
            for p in distinct_ports:
                all_event_ids.extend(port_map[p])

            evidence = {
                "rule_id": self.rule_id,
                "trigger_condition": f"Source IP '{source_ip}' connected to {len(distinct_ports)} distinct destination ports within {window_seconds}s (Threshold: {distinct_threshold} ports)",
                "source_ip": source_ip,
                "destination_ip": event.dest_ip,
                "distinct_ports_count": len(distinct_ports),
                "ports_scanned": distinct_ports,
                "threshold": distinct_threshold,
                "window_seconds": window_seconds,
                "risk_assessment": "Reconnaissance scan detected mapping active services, commonly preceding targeted exploitation."
            }

            return DetectionMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                alert_title="Possible Port Scanning Activity",
                description=f"Possible Port Scanning Activity from {source_ip} targeting {len(distinct_ports)} distinct ports.",
                severity=self.severity,
                category=self.category,
                mitre_tactics=self.mitre_tactics,
                mitre_techniques=self.mitre_techniques,
                matched_event_ids=all_event_ids[:20],
                evidence=evidence,
                entity_key=entity_key
            )
        return None


# ==========================================
# RULE 9: DATA EXFILTRATION INDICATOR (DE-009)
# ==========================================
class DataExfiltrationRule(BaseDetectionRule):
    """
    DE-009: Identify unusual outbound data-transfer patterns exceeding baseline thresholds.
    """
    def evaluate(self, event: StandardizedEvent, correlation: CorrelationTracker) -> Optional[DetectionMatch]:
        if not self.enabled:
            return None

        if event.event_type not in ["data_transfer", "network_outbound", "exfiltration"]:
            return None

        threshold_bytes = int(self.config.get("threshold_bytes", 10485760))  # 10 MB default
        window_seconds = int(self.config.get("time_window_seconds", 300))
        cooldown_seconds = int(self.config.get("cooldown_seconds", 180))

        source_ip = event.source_ip or "unknown"
        bytes_sent = event.details.get("bytes_sent") or event.details.get("bytes") or event.details.get("size_bytes") or 0
        try:
            bytes_sent = int(bytes_sent)
        except (ValueError, TypeError):
            bytes_sent = 0

        correlation.record_data_transfer(source_ip, bytes_sent, event.timestamp, event.event_id)

        total_bytes, event_ids = correlation.get_total_transfer_for_ip(source_ip, window_seconds, event.timestamp)

        if total_bytes >= threshold_bytes:
            entity_key = f"exfil::{source_ip}"
            if correlation.is_in_cooldown(self.rule_id, entity_key, cooldown_seconds):
                return None

            mb_transferred = round(total_bytes / (1024 * 1024), 2)
            mb_threshold = round(threshold_bytes / (1024 * 1024), 2)

            evidence = {
                "rule_id": self.rule_id,
                "trigger_condition": f"Observed outbound data volume of {mb_transferred} MB from '{source_ip}' within {window_seconds}s (Threshold: {mb_threshold} MB)",
                "source_ip": source_ip,
                "destination_ip": event.dest_ip or "External Cloud / Host",
                "total_bytes_transferred": total_bytes,
                "megabytes_transferred": mb_transferred,
                "threshold_megabytes": mb_threshold,
                "window_seconds": window_seconds,
                "risk_assessment": "Note: Anomaly indicator based on abnormal transfer volume spike. Requires analyst verification to corroborate data staging or authorized backup transfer."
            }

            return DetectionMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                alert_title="Possible Data Exfiltration Indicator",
                description=f"Possible Data Exfiltration Indicator: {mb_transferred} MB outbound traffic from {source_ip}.",
                severity=self.severity,
                category=self.category,
                mitre_tactics=self.mitre_tactics,
                mitre_techniques=self.mitre_techniques,
                matched_event_ids=event_ids[:20],
                evidence=evidence,
                entity_key=entity_key
            )
        return None


# ==========================================
# RULE 10: UNEXPECTED ACCOUNT CREATION DETECTION (AC-010)
# ==========================================
class UnexpectedAccountCreationRule(BaseDetectionRule):
    """
    AC-010: Identify unexpected creation of user accounts outside authorized policies.
    """
    def evaluate(self, event: StandardizedEvent, correlation: CorrelationTracker) -> Optional[DetectionMatch]:
        if not self.enabled:
            return None

        if event.event_type not in ["account_created", "user_added", "user_create"]:
            return None

        authorized_creators = [c.lower() for c in self.config.get("authorized_creators", ["admin", "iam_service", "hr_provisioning", "system_installer"])]
        suspicious_patterns = [p.lower() for p in self.config.get("suspicious_patterns", ["temp_", "backdoor", "test_", "hidden", "adm_", "svc_tmp", "guest_admin"])]
        require_authorized = bool(self.config.get("require_authorized_creator", True))
        cooldown_seconds = int(self.config.get("cooldown_seconds", 60))

        new_account = (
            event.details.get("created_account")
            or event.details.get("target_user")
            or event.username
            or ""
        ).lower()

        creator = (
            event.details.get("creator")
            or event.details.get("actor")
            or event.details.get("created_by")
            or "unknown"
        ).lower()

        matched = False
        reasons = []

        if require_authorized and creator not in authorized_creators:
            matched = True
            reasons.append(f"Account creator '{creator}' is not an authorized provisioning identity")

        for pattern in suspicious_patterns:
            if pattern in new_account:
                matched = True
                reasons.append(f"Account name '{new_account}' matches suspicious nomenclature pattern '{pattern}'")
                break

        if matched:
            entity_key = f"acct_create::{new_account}"
            if correlation.is_in_cooldown(self.rule_id, entity_key, cooldown_seconds):
                return None

            evidence = {
                "rule_id": self.rule_id,
                "trigger_condition": "; ".join(reasons),
                "created_account": new_account,
                "creator": creator,
                "source_ip": event.source_ip,
                "reasons": reasons,
                "risk_assessment": "Unsanctioned account provisioning is frequently leveraged as an initial persistence mechanism (MITRE T1136)."
            }

            return DetectionMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                alert_title="Unexpected Account Creation Detected",
                description=f"Unexpected Account Creation Detected for '{new_account}' by '{creator}'.",
                severity=self.severity,
                category=self.category,
                mitre_tactics=self.mitre_tactics,
                mitre_techniques=self.mitre_techniques,
                matched_event_ids=[event.event_id],
                evidence=evidence,
                entity_key=entity_key
            )
        return None

