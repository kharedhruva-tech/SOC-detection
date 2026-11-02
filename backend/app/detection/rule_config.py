"""
Detection Rule Configurations and Default Schemas.
Provides predefined metadata, thresholds, time windows, and whitelists for all 10 SIEM rules.
"""
from typing import Dict, Any, List

# Standard Rule Categories required by the SOC Dashboard
CATEGORIES = {
    "AUTHENTICATION": "Authentication",
    "ACCOUNT_SECURITY": "Account Security",
    "PRIVILEGE_MANAGEMENT": "Privilege Management",
    "FILE_MONITORING": "File Monitoring",
    "MALWARE_DETECTION": "Malware Detection",
    "NETWORK_SECURITY": "Network Security",
}

# Standard Severities
SEVERITIES = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}

DEFAULT_RULES_CONFIG: List[Dict[str, Any]] = [
    {
        "rule_id": "BR-001",
        "name": "Brute Force Detection",
        "description": "Identify repeated failed login attempts associated with the same source IP and account within a short time window.",
        "category": CATEGORIES["AUTHENTICATION"],
        "severity": SEVERITIES["HIGH"],
        "enabled": True,
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110.001"],
        "configuration": {
            "failed_attempts_threshold": 5,
            "time_window_seconds": 60,
            "cooldown_seconds": 120,
            "match_user_and_ip": True
        }
    },
    {
        "rule_id": "PS-002",
        "name": "Password Spraying Detection",
        "description": "Identify repeated authentication failures involving multiple distinct accounts associated with the same source IP.",
        "category": CATEGORIES["AUTHENTICATION"],
        "severity": SEVERITIES["HIGH"],
        "enabled": True,
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110.003"],
        "configuration": {
            "distinct_users_threshold": 3,
            "time_window_seconds": 180,
            "cooldown_seconds": 180
        }
    },
    {
        "rule_id": "LF-003",
        "name": "Multiple Failed Login Detection",
        "description": "Identify repeated login failures associated with an individual account across one or multiple sources.",
        "category": CATEGORIES["ACCOUNT_SECURITY"],
        "severity": SEVERITIES["MEDIUM"],
        "enabled": True,
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110"],
        "configuration": {
            "failed_attempts_threshold": 3,
            "time_window_seconds": 120,
            "cooldown_seconds": 120
        }
    },
    {
        "rule_id": "UL-004",
        "name": "Unusual Login Time Detection",
        "description": "Identify login activity outside a configurable normal login schedule with timezone offset and authorized exemptions.",
        "category": CATEGORIES["ACCOUNT_SECURITY"],
        "severity": SEVERITIES["MEDIUM"],
        "enabled": True,
        "mitre_tactics": ["Initial Access", "Persistence"],
        "mitre_techniques": ["T1078"],
        "configuration": {
            "business_hours_start": 8,   # 08:00
            "business_hours_end": 18,    # 18:00
            "utc_offset_hours": 0.0,
            "authorized_users": ["admin", "system_service", "backup_agent", "soc_manager", "cron_executor"],
            "allowed_weekdays": [0, 1, 2, 3, 4],  # Monday to Friday
            "ignore_successful_if_whitelisted": True,
            "cooldown_seconds": 60
        }
    },
    {
        "rule_id": "PE-005",
        "name": "Privilege Escalation Detection",
        "description": "Identify unexpected user privilege or role changes, such as granting administrative rights to standard accounts.",
        "category": CATEGORIES["PRIVILEGE_MANAGEMENT"],
        "severity": SEVERITIES["CRITICAL"],
        "enabled": True,
        "mitre_tactics": ["Privilege Escalation"],
        "mitre_techniques": ["T1078.002", "T1548"],
        "configuration": {
            "target_roles": ["Admin", "Super Admin", "root", "wheel", "Domain Admin", "Administrator", "sudo"],
            "authorized_delegators": ["admin", "root", "Super Admin", "system_provisioner"],
            "suspicious_commands": [
                "net localgroup administrators /add",
                "usermod -ag sudo",
                "usermod -ag wheel",
                "chmod +s",
                "visudo",
                "/etc/sudoers"
            ],
            "cooldown_seconds": 60
        }
    },
    {
        "rule_id": "FA-006",
        "name": "Suspicious File Activity Detection",
        "description": "Identify unexpected modifications or deletions to configured sensitive system files and directories.",
        "category": CATEGORIES["FILE_MONITORING"],
        "severity": SEVERITIES["HIGH"],
        "enabled": True,
        "mitre_tactics": ["Defense Evasion", "Impact"],
        "mitre_techniques": ["T1070.004", "T1565.001"],
        "configuration": {
            "monitored_paths": [
                "/etc/shadow",
                "/etc/passwd",
                "/etc/sudoers",
                "c:\\windows\\system32\\drivers\\etc\\hosts",
                "c:\\windows\\system32\\config\\sam",
                "/var/log/auth.log",
                "/etc/ssh/sshd_config"
            ],
            "monitored_actions": ["modify", "delete", "write", "rename", "permission_change"],
            "cooldown_seconds": 60
        }
    },
    {
        "rule_id": "MD-007",
        "name": "Malware Indicator Detection",
        "description": "Identify malware indicators reported by authorized endpoint security logs or supplied threat intelligence data.",
        "category": CATEGORIES["MALWARE_DETECTION"],
        "severity": SEVERITIES["CRITICAL"],
        "enabled": True,
        "mitre_tactics": ["Execution", "Defense Evasion"],
        "mitre_techniques": ["T1204", "T1059"],
        "configuration": {
            "known_malicious_hashes": [
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "44d88612fea8a8f36de82e1278abb02f",
                "b9972322300b90e9c4f74d08b3e851c2",
                "7d793037a0760186574b0282f2f435e7",
                "c75877c8e96bfcf09e45e763138b7245a9071015f6068305e50529d846cf2428"
            ],
            "known_signatures": [
                "mimikatz",
                "cobalt strike",
                "meterpreter",
                "wannacry",
                "lockbit",
                "agenttesla",
                "emotet",
                "revil",
                "darkside",
                "redline"
            ],
            "trusted_sources": ["edr", "defender", "crowdstrike", "threatintel", "endpoint", "antivirus", "sysmon"],
            "cooldown_seconds": 60
        }
    },
    {
        "rule_id": "PS-008",
        "name": "Port Scan Detection",
        "description": "Identify unusual network connection attempts across an unusually large number of distinct destination ports within a short window.",
        "category": CATEGORIES["NETWORK_SECURITY"],
        "severity": SEVERITIES["HIGH"],
        "enabled": True,
        "mitre_tactics": ["Discovery"],
        "mitre_techniques": ["T1046"],
        "configuration": {
            "distinct_ports_threshold": 5,
            "time_window_seconds": 60,
            "cooldown_seconds": 120
        }
    },
    {
        "rule_id": "DE-009",
        "name": "Data Exfiltration Indicator",
        "description": "Identify unusual outbound data-transfer volumes exceeding configurable thresholds or baseline spikes.",
        "category": CATEGORIES["NETWORK_SECURITY"],
        "severity": SEVERITIES["CRITICAL"],
        "enabled": True,
        "mitre_tactics": ["Exfiltration"],
        "mitre_techniques": ["T1048", "T1041"],
        "configuration": {
            "threshold_bytes": 10485760,  # 10 MB
            "time_window_seconds": 300,
            "cooldown_seconds": 180,
            "flag_suspicious_protocols": ["dns", "icmp", "https"]
        }
    },
    {
        "rule_id": "AC-010",
        "name": "Unexpected Account Creation Detection",
        "description": "Identify unexpected creation of user accounts, especially by unauthorized creators or with suspicious naming patterns.",
        "category": CATEGORIES["ACCOUNT_SECURITY"],
        "severity": SEVERITIES["MEDIUM"],
        "enabled": True,
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1136.001", "T1136.002"],
        "configuration": {
            "authorized_creators": ["admin", "iam_service", "hr_provisioning", "system_installer"],
            "suspicious_patterns": ["temp_", "backdoor", "test_", "hidden", "adm_", "svc_tmp", "guest_admin"],
            "require_authorized_creator": True,
            "cooldown_seconds": 60
        }
    }
]

