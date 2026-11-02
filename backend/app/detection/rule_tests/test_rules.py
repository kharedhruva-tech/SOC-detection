"""
Automated Unit Tests for All 10 SIEM Detection Rules.
Verifies matching events, normal event ignorance, threshold modifications,
disabled state, malformed input handling, and duplicate alert cooldowns.
"""
import pytest
from datetime import datetime, timezone, timedelta

from app.detection.event_normalizer import EventNormalizer, StandardizedEvent, EventValidationError
from app.detection.correlation import CorrelationTracker
from app.detection.rules import (
    BruteForceRule,
    PasswordSprayingRule,
    MultipleFailedLoginRule,
    UnusualLoginTimeRule,
    PrivilegeEscalationRule,
    SuspiciousFileActivityRule,
    MalwareIndicatorRule,
    PortScanRule,
    DataExfiltrationRule,
    UnexpectedAccountCreationRule,
)


@pytest.fixture
def correlation():
    return CorrelationTracker()


# ==========================================
# 1. BRUTE FORCE DETECTION (BR-001)
# ==========================================
def test_rule_brute_force_matches_and_cooldown(correlation):
    rule = BruteForceRule(
        rule_id="BR-001", name="Brute Force", category="Authentication",
        severity="High", description="", mitre_tactics=[], mitre_techniques=[],
        enabled=True, configuration={"failed_attempts_threshold": 5, "time_window_seconds": 60, "cooldown_seconds": 120}
    )

    now = datetime.utcnow()
    # 4 failed attempts - threshold not met
    for i in range(4):
        event = StandardizedEvent(
            event_id=f"EVT-BF-{i}", event_type="login_failed",
            source_ip="192.168.1.50", username="target_admin", timestamp=now + timedelta(seconds=i)
        )
        assert rule.evaluate(event, correlation) is None

    # 5th attempt - threshold met!
    event5 = StandardizedEvent(
        event_id="EVT-BF-5", event_type="login_failed",
        source_ip="192.168.1.50", username="target_admin", timestamp=now + timedelta(seconds=5)
    )
    match = rule.evaluate(event5, correlation)
    assert match is not None
    assert match.rule_id == "BR-001"
    assert match.alert_title == "Possible Brute Force Attempt"
    assert match.severity == "High"
    assert len(match.matched_event_ids) == 5

    # Trigger cooldown
    correlation.record_alert_fired(match.rule_id, match.entity_key)

    # 6th attempt within cooldown window should be suppressed
    event6 = StandardizedEvent(
        event_id="EVT-BF-6", event_type="login_failed",
        source_ip="192.168.1.50", username="target_admin", timestamp=now + timedelta(seconds=6)
    )
    assert rule.evaluate(event6, correlation) is None


def test_rule_brute_force_ignores_normal_logins(correlation):
    rule = BruteForceRule(
        rule_id="BR-001", name="Brute Force", category="Authentication",
        severity="High", description="", mitre_tactics=[], mitre_techniques=[],
        enabled=True, configuration={"failed_attempts_threshold": 5, "time_window_seconds": 60}
    )
    for i in range(10):
        event = StandardizedEvent(
            event_id=f"EVT-OK-{i}", event_type="login_success",
            source_ip="192.168.1.50", username="target_admin"
        )
        assert rule.evaluate(event, correlation) is None


# ==========================================
# 2. PASSWORD SPRAYING DETECTION (PS-002)
# ==========================================
def test_rule_password_spraying(correlation):
    rule = PasswordSprayingRule(
        rule_id="PS-002", name="Password Spray", category="Authentication",
        severity="High", description="", mitre_tactics=[], mitre_techniques=[],
        enabled=True, configuration={"distinct_users_threshold": 3, "time_window_seconds": 180, "cooldown_seconds": 180}
    )
    now = datetime.utcnow()
    attacker_ip = "10.10.10.200"

    # Failed login on user 1
    e1 = StandardizedEvent(event_id="PS-1", event_type="login_failed", source_ip=attacker_ip, username="user1", timestamp=now)
    assert rule.evaluate(e1, correlation) is None

    # Failed login on user 2
    e2 = StandardizedEvent(event_id="PS-2", event_type="login_failed", source_ip=attacker_ip, username="user2", timestamp=now + timedelta(seconds=5))
    assert rule.evaluate(e2, correlation) is None

    # Failed login on user 3 - triggers threshold
    e3 = StandardizedEvent(event_id="PS-3", event_type="login_failed", source_ip=attacker_ip, username="user3", timestamp=now + timedelta(seconds=10))
    match = rule.evaluate(e3, correlation)
    assert match is not None
    assert match.rule_id == "PS-002"
    assert match.alert_title == "Possible Password Spraying Activity"
    assert match.evidence["distinct_accounts_count"] == 3


# ==========================================
# 3. MULTIPLE FAILED LOGIN (LF-003)
# ==========================================
def test_rule_multiple_failed_login(correlation):
    rule = MultipleFailedLoginRule(
        rule_id="LF-003", name="Multiple Failed Login", category="Account Security",
        severity="Medium", description="", mitre_tactics=[], mitre_techniques=[],
        enabled=True, configuration={"failed_attempts_threshold": 3, "time_window_seconds": 120, "cooldown_seconds": 120}
    )
    now = datetime.utcnow()
    user = "victim_account"

    # From IP 1
    e1 = StandardizedEvent(event_id="LF-1", event_type="login_failed", source_ip="1.1.1.1", username=user, timestamp=now)
    rule.evaluate(e1, correlation)
    # From IP 2
    e2 = StandardizedEvent(event_id="LF-2", event_type="login_failed", source_ip="2.2.2.2", username=user, timestamp=now + timedelta(seconds=10))
    rule.evaluate(e2, correlation)
    # From IP 3
    e3 = StandardizedEvent(event_id="LF-3", event_type="login_failed", source_ip="3.3.3.3", username=user, timestamp=now + timedelta(seconds=20))
    match = rule.evaluate(e3, correlation)

    assert match is not None
    assert match.rule_id == "LF-003"
    assert match.alert_title == "Suspicious Login Activity"
    assert match.evidence["failure_count"] == 3


# ==========================================
# 4. UNUSUAL LOGIN TIME DETECTION (UL-004)
# ==========================================
def test_rule_unusual_login_time(correlation):
    rule = UnusualLoginTimeRule(
        rule_id="UL-004", name="Unusual Login Time", category="Account Security",
        severity="Medium", description="", mitre_tactics=[], mitre_techniques=[],
        enabled=True, configuration={
            "business_hours_start": 8, "business_hours_end": 18,
            "utc_offset_hours": 0.0,
            "authorized_users": ["admin", "backup_agent"],
            "allowed_weekdays": [0, 1, 2, 3, 4],
            "cooldown_seconds": 60
        }
    )

    # Off-hours login at 02:30 UTC for non-whitelisted user
    night_ts = datetime(2026, 11, 2, 2, 30, 0) # Monday 02:30 AM
    evt = StandardizedEvent(
        event_id="UL-1", event_type="login_success",
        username="contractor_guest", source_ip="10.0.1.10", timestamp=night_ts
    )
    match = rule.evaluate(evt, correlation)
    assert match is not None
    assert match.rule_id == "UL-004"
    assert match.alert_title == "Unusual Login Time Detected"

    # Same off-hours login for whitelisted admin should be ignored
    admin_evt = StandardizedEvent(
        event_id="UL-2", event_type="login_success",
        username="admin", source_ip="10.0.1.10", timestamp=night_ts
    )
    assert rule.evaluate(admin_evt, correlation) is None


# ==========================================
# 5. PRIVILEGE ESCALATION DETECTION (PE-005)
# ==========================================
def test_rule_privilege_escalation(correlation):
    rule = PrivilegeEscalationRule(
        rule_id="PE-005", name="Privilege Escalation", category="Privilege Management",
        severity="Critical", description="", mitre_tactics=[], mitre_techniques=[],
        enabled=True, configuration={
            "target_roles": ["Admin", "Super Admin", "root"],
            "authorized_delegators": ["admin", "root"],
            "suspicious_commands": ["net localgroup administrators", "chmod +s"]
        }
    )

    # Unauthorized role grant
    evt = StandardizedEvent(
        event_id="PE-1", event_type="privilege_change",
        username="intern_bob", source_ip="10.0.5.10",
        details={"new_role": "Super Admin", "delegator": "unknown_script"}
    )
    match = rule.evaluate(evt, correlation)
    assert match is not None
    assert match.rule_id == "PE-005"
    assert match.severity == "Critical"
    assert match.alert_title == "Possible Privilege Escalation"

    # Suspicious command execution
    cmd_evt = StandardizedEvent(
        event_id="PE-2", event_type="process_creation",
        username="hacker", source_ip="10.0.5.10",
        details={"command_line": "net localgroup administrators test /add"}
    )
    cmd_match = rule.evaluate(cmd_evt, correlation)
    assert cmd_match is not None


# ==========================================
# 6. SUSPICIOUS FILE ACTIVITY DETECTION (FA-006)
# ==========================================
def test_rule_suspicious_file_activity(correlation):
    rule = SuspiciousFileActivityRule(
        rule_id="FA-006", name="Suspicious File Activity", category="File Monitoring",
        severity="High", description="", mitre_tactics=[], mitre_techniques=[],
        enabled=True, configuration={
            "monitored_paths": ["/etc/shadow", "c:\\windows\\system32\\drivers\\etc\\hosts"],
            "monitored_actions": ["modify", "delete", "write"]
        }
    )

    evt = StandardizedEvent(
        event_id="FA-1", event_type="file_modify",
        username="bad_actor", source_ip="10.0.1.5",
        details={"file_path": "/etc/shadow", "action": "modify", "process": "injector.sh"}
    )
    match = rule.evaluate(evt, correlation)
    assert match is not None
    assert match.rule_id == "FA-006"
    assert match.alert_title == "Suspicious File Modification Detected"

    # Normal file modification should not match
    normal_evt = StandardizedEvent(
        event_id="FA-2", event_type="file_modify",
        username="user", source_ip="10.0.1.5",
        details={"file_path": "/home/user/document.txt", "action": "modify"}
    )
    assert rule.evaluate(normal_evt, correlation) is None


# ==========================================
# 7. MALWARE INDICATOR DETECTION (MD-007)
# ==========================================
def test_rule_malware_indicator(correlation):
    rule = MalwareIndicatorRule(
        rule_id="MD-007", name="Malware Indicator", category="Malware Detection",
        severity="Critical", description="", mitre_tactics=[], mitre_techniques=[],
        enabled=True, configuration={
            "known_malicious_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            "known_signatures": ["mimikatz", "wannacry", "cobalt strike"]
        }
    )

    # Match by known signature
    evt = StandardizedEvent(
        event_id="MD-1", event_type="malware_detected",
        username="analyst", source_ip="10.0.2.10",
        details={"process_name": "mimikatz.exe", "threat_name": "HackTool.Mimikatz"}
    )
    match = rule.evaluate(evt, correlation)
    assert match is not None
    assert match.rule_id == "MD-007"
    assert match.severity == "Critical"
    assert match.alert_title == "Possible Malware Activity Detected"


# ==========================================
# 8. PORT SCAN DETECTION (PS-008)
# ==========================================
def test_rule_port_scan(correlation):
    rule = PortScanRule(
        rule_id="PS-008", name="Port Scan", category="Network Security",
        severity="High", description="", mitre_tactics=[], mitre_techniques=[],
        enabled=True, configuration={"distinct_ports_threshold": 5, "time_window_seconds": 60, "cooldown_seconds": 120}
    )
    now = datetime.utcnow()
    scanner_ip = "192.168.99.1"
    ports = [21, 22, 80, 443, 3389]

    for i, port in enumerate(ports):
        evt = StandardizedEvent(
            event_id=f"SCAN-{i}", event_type="network_connection",
            source_ip=scanner_ip, dest_ip="10.0.1.1",
            details={"dest_port": port}, timestamp=now + timedelta(seconds=i)
        )
        match = rule.evaluate(evt, correlation)
        if i == 4:
            assert match is not None
            assert match.rule_id == "PS-008"
            assert match.alert_title == "Possible Port Scanning Activity"
            assert len(match.evidence["ports_scanned"]) == 5


# ==========================================
# 9. DATA EXFILTRATION INDICATOR (DE-009)
# ==========================================
def test_rule_data_exfiltration(correlation):
    rule = DataExfiltrationRule(
        rule_id="DE-009", name="Data Exfiltration", category="Network Security",
        severity="Critical", description="", mitre_tactics=[], mitre_techniques=[],
        enabled=True, configuration={"threshold_bytes": 10485760, "time_window_seconds": 300, "cooldown_seconds": 180} # 10MB
    )
    now = datetime.utcnow()
    source_ip = "10.0.1.50"

    # Transfer of 15 MB
    evt = StandardizedEvent(
        event_id="EXFIL-1", event_type="data_transfer",
        source_ip=source_ip, dest_ip="198.51.100.5",
        details={"bytes_sent": 15728640}, timestamp=now
    )
    match = rule.evaluate(evt, correlation)
    assert match is not None
    assert match.rule_id == "DE-009"
    assert match.severity == "Critical"
    assert match.alert_title == "Possible Data Exfiltration Indicator"
    assert match.evidence["megabytes_transferred"] == 15.0


# ==========================================
# 10. UNEXPECTED ACCOUNT CREATION (AC-010)
# ==========================================
def test_rule_unexpected_account_creation(correlation):
    rule = UnexpectedAccountCreationRule(
        rule_id="AC-010", name="Unexpected Account Creation", category="Account Security",
        severity="Medium", description="", mitre_tactics=[], mitre_techniques=[],
        enabled=True, configuration={
            "authorized_creators": ["admin", "iam_service"],
            "suspicious_patterns": ["temp_", "backdoor", "test_"],
            "require_authorized_creator": True
        }
    )

    # Creation of suspicious backdoor account by unauthorized creator
    evt = StandardizedEvent(
        event_id="AC-1", event_type="account_created",
        username="guest_attacker", source_ip="10.0.1.100",
        details={"created_account": "temp_backdoor", "creator": "intruder"}
    )
    match = rule.evaluate(evt, correlation)
    assert match is not None
    assert match.rule_id == "AC-010"
    assert match.alert_title == "Unexpected Account Creation Detected"

    # Legitimate account creation by authorized admin should be ignored if name is normal
    normal_evt = StandardizedEvent(
        event_id="AC-2", event_type="account_created",
        username="admin", source_ip="10.0.1.5",
        details={"created_account": "john_doe", "creator": "admin"}
    )
    assert rule.evaluate(normal_evt, correlation) is None


# ==========================================
# DISABLED RULE & MALFORMED EVENT HANDLING
# ==========================================
def test_disabled_rule_does_not_fire(correlation):
    rule = BruteForceRule(
        rule_id="BR-001", name="Brute Force", category="Authentication",
        severity="High", description="", mitre_tactics=[], mitre_techniques=[],
        enabled=False, configuration={"failed_attempts_threshold": 1}
    )
    evt = StandardizedEvent(
        event_id="DIS-1", event_type="login_failed",
        source_ip="10.0.0.1", username="admin"
    )
    assert rule.evaluate(evt, correlation) is None


def test_malformed_event_normalization():
    # Missing fields should be handled gracefully with defaults
    norm = EventNormalizer.normalize({"event_type": "login_failed"})
    assert norm.event_type == "login_failed"
    assert norm.source == "generic"
    assert norm.event_id.startswith("EVT-")
    assert isinstance(norm.timestamp, datetime)

    # Invalid payload raises safe validation error
    with pytest.raises(EventValidationError):
        EventNormalizer.normalize([1, 2, 3])

