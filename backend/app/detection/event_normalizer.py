"""
Standardized Security Event Normalizer.
Normalizes heterogeneous logs (Windows Events, Sysmon, Firewall, Web, Identity, Custom)
into a unified SecurityEvent format with UTC timestamps and validation.
"""
import uuid
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union
from pydantic import BaseModel, Field, ValidationError


class EventValidationError(Exception):
    """Raised when an incoming event cannot be normalized due to fatal format errors."""
    pass


class StandardizedEvent(BaseModel):
    """Validated standardized security event."""
    event_id: str = Field(default_factory=lambda: f"EVT-{uuid.uuid4().hex[:12].upper()}")
    event_type: str
    category: str = "Authentication"
    username: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "generic"
    severity: str = "low"
    details: Dict[str, Any] = Field(default_factory=dict)
    raw_event: Optional[str] = None
    is_demo: bool = False

    class Config:
        arbitrary_types_allowed = True


# Known event type mappings from common telemetry sources
WINDOWS_EVENT_TYPE_MAP = {
    4624: "login_success",
    4625: "login_failed",
    4672: "special_privilege_assigned",
    4720: "account_created",
    4722: "account_enabled",
    4726: "account_deleted",
    4728: "privilege_change",  # Member added to security group
    4732: "privilege_change",  # Member added to local group
    4738: "account_modified",
}

SYSMON_EVENT_TYPE_MAP = {
    1: "process_creation",
    3: "network_connection",
    7: "image_loaded",
    11: "file_modify",
    13: "registry_value_set",
    23: "file_delete",
}


class EventNormalizer:
    """Normalizes raw input dictionaries or string payloads into StandardizedEvent."""

    @staticmethod
    def _parse_timestamp(raw_ts: Any) -> datetime:
        """Converts diverse timestamp formats into a naive UTC datetime."""
        if isinstance(raw_ts, datetime):
            if raw_ts.tzinfo is not None:
                return raw_ts.astimezone(timezone.utc).replace(tzinfo=None)
            return raw_ts
        if isinstance(raw_ts, (int, float)):
            try:
                return datetime.fromtimestamp(raw_ts, tz=timezone.utc).replace(tzinfo=None)
            except Exception:
                return datetime.utcnow()
        if isinstance(raw_ts, str):
            clean_ts = raw_ts.strip().rstrip("Z")
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
            ):
                try:
                    return datetime.strptime(clean_ts, fmt)
                except ValueError:
                    continue
        return datetime.utcnow()

    @staticmethod
    def determine_category(event_type: str, details: Optional[Dict[str, Any]] = None) -> str:
        """
        Maps an event type and its attributes to one of the 7 enterprise SIEM categories:
        - Authentication
        - Network Security
        - Endpoint Security
        - File Activity
        - Account Management
        - Web Application Security
        - Malware Indicators
        """
        et = (event_type or "").lower().strip()
        det = details or {}

        # 1. Malware Indicators
        if any(w in et for w in ("malware", "ransom", "c2", "beacon", "trojan", "virus")) or "threat_name" in det or "file_hash" in det:
            return "Malware Indicators"

        # 2. Web Application Security
        if any(w in et for w in ("sql", "xss", "web", "http", "api_abuse", "csrf", "lfi", "rfi")) or "url" in det or "method" in det:
            return "Web Application Security"

        # 3. File Activity
        if any(w in et for w in ("file", "directory", "folder", "share")) or "file_path" in det or "file_name" in det:
            return "File Activity"

        # 4. Account Management & Privilege
        if any(w in et for w in ("account", "role", "privilege", "group_member", "user_create", "password_reset")):
            return "Account Management"

        # 5. Network Security
        if any(w in et for w in ("port", "network", "firewall", "dns", "traffic", "exfil", "scan", "packet")) or "dest_port" in det or "bytes_sent" in det:
            return "Network Security"

        # 6. Endpoint Security
        if any(w in et for w in ("process", "service", "registry", "sysmon", "command", "task")) or "command_line" in det or "process_name" in det:
            return "Endpoint Security"

        # 7. Authentication (Default)
        return "Authentication"

    @classmethod
    def normalize(cls, raw: Union[Dict[str, Any], str, StandardizedEvent]) -> StandardizedEvent:
        """
        Main entry point for normalizing any incoming raw payload.
        Handles missing fields, normalizes types, preserves original data.
        """
        if isinstance(raw, StandardizedEvent):
            return raw

        if isinstance(raw, str):
            try:
                raw_dict = json.loads(raw)
            except Exception as e:
                raise EventValidationError(f"Invalid JSON string payload: {str(e)}")
        elif isinstance(raw, dict):
            raw_dict = dict(raw)
        else:
            raise EventValidationError(f"Unsupported payload type: {type(raw).__name__}")

        # Preserve string representation of raw event
        raw_repr = json.dumps(raw_dict, default=str)

        # 1. Resolve event_id
        event_id = str(raw_dict.get("event_id") or raw_dict.get("id") or f"EVT-{uuid.uuid4().hex[:10].upper()}")

        # 2. Resolve event_type
        event_type = raw_dict.get("event_type") or raw_dict.get("action") or raw_dict.get("type") or ""

        # Map Windows Event IDs if provided
        win_id = raw_dict.get("EventID") or raw_dict.get("event_id")
        if isinstance(win_id, int) or (isinstance(win_id, str) and win_id.isdigit()):
            win_num = int(win_id)
            if win_num in WINDOWS_EVENT_TYPE_MAP:
                event_type = WINDOWS_EVENT_TYPE_MAP[win_num]
            elif win_num in SYSMON_EVENT_TYPE_MAP:
                event_type = SYSMON_EVENT_TYPE_MAP[win_num]

        # Canonicalize common naming variations
        event_type = str(event_type).lower().strip()
        type_aliases = {
            "failed_login": "login_failed",
            "logon_failure": "login_failed",
            "auth_failure": "login_failed",
            "authentication_failure": "login_failed",
            "user_login_failed": "login_failed",
            "successful_login": "login_success",
            "logon_success": "login_success",
            "auth_success": "login_success",
            "file_modified": "file_modify",
            "file_write": "file_modify",
            "file_created": "file_create",
            "file_deleted": "file_delete",
            "priv_escalation": "privilege_change",
            "role_change": "privilege_change",
            "group_member_add": "privilege_change",
            "port_scan": "network_connection",
            "malware": "malware_detected",
            "threat_detected": "malware_detected",
            "exfiltration": "data_transfer",
            "data_exfil": "data_transfer",
            "outbound_transfer": "data_transfer",
            "user_creation": "account_created",
            "user_added": "account_created",
            "create_user": "account_created",
        }
        event_type = type_aliases.get(event_type, event_type)
        if not event_type:
            event_type = "generic_event"

        # 3. Resolve user
        username = (
            raw_dict.get("username")
            or raw_dict.get("user")
            or raw_dict.get("target_user")
            or raw_dict.get("account")
            or raw_dict.get("TargetUserName")
        )
        if username:
            username = str(username).strip()

        # 4. Resolve IPs
        source_ip = (
            raw_dict.get("source_ip")
            or raw_dict.get("src_ip")
            or raw_dict.get("ip")
            or raw_dict.get("IpAddress")
            or raw_dict.get("client_ip")
        )
        if source_ip:
            source_ip = str(source_ip).strip()

        dest_ip = (
            raw_dict.get("dest_ip")
            or raw_dict.get("destination_ip")
            or raw_dict.get("dst_ip")
            or raw_dict.get("target_ip")
        )
        if dest_ip:
            dest_ip = str(dest_ip).strip()

        # 5. Normalize timestamp
        raw_ts = raw_dict.get("timestamp") or raw_dict.get("TimeCreated") or raw_dict.get("time")
        timestamp = cls._parse_timestamp(raw_ts)

        # 6. Source and severity
        source = str(raw_dict.get("source") or raw_dict.get("log_type") or raw_dict.get("Channel") or "generic")
        severity = str(raw_dict.get("severity") or "low").lower()

        # 7. Extract detailed attributes
        details = raw_dict.get("details")
        if not isinstance(details, dict):
            details = {}
            # Flatten or copy relevant top-level keys into details
            for k, v in raw_dict.items():
                if k not in {"event_id", "event_type", "username", "source_ip", "dest_ip", "timestamp", "source", "severity", "raw_event"}:
                    details[k] = v

        is_demo = bool(raw_dict.get("is_demo", False))
        category = str(raw_dict.get("category") or cls.determine_category(event_type, details))

        return StandardizedEvent(
            event_id=event_id,
            event_type=event_type,
            category=category,
            username=username,
            source_ip=source_ip,
            dest_ip=dest_ip,
            timestamp=timestamp,
            source=source,
            severity=severity,
            details=details,
            raw_event=raw_repr,
            is_demo=is_demo,
        )

