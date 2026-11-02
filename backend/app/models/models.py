from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text, JSON, Table
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String)
    role = Column(String, default="Tier 1 Analyst")  # Super Admin, SOC Manager, Tier 1/2/3 Analyst, etc.
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Asset(Base):
    __tablename__ = "assets"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    ip_address = Column(String, index=True, nullable=False)
    hostname = Column(String, unique=True, index=True)
    os = Column(String)  # Windows, Linux, macOS, Cloud, etc.
    criticality = Column(String, default="Medium")  # Low, Medium, High, Critical
    risk_score = Column(Float, default=0.0)  # 0 to 100
    owner = Column(String)
    business_unit = Column(String)
    network_location = Column(String)  # DMZ, Internal, User VPN, Cloud VPC
    installed_software = Column(JSON, default=list)  # List of software dicts
    created_at = Column(DateTime, default=datetime.utcnow)
    
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="asset")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    cve_id = Column(String, index=True, nullable=False)  # CVE-YYYY-NNNN
    title = Column(String, nullable=False)
    description = Column(Text)
    cvss_score = Column(Float, default=0.0)
    patch_status = Column(String, default="Unpatched")  # Unpatched, Patched, Mitigated
    exploit_available = Column(Boolean, default=False)
    ai_remediation = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    asset = relationship("Asset", back_populates="vulnerabilities")

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    category = Column(String, index=True, nullable=False)  # Ransomware, Lateral Movement, etc.
    severity = Column(String, index=True, default="Low")  # Informational, Low, Medium, High, Critical
    description = Column(Text)
    mitre_tactics = Column(JSON, default=list)  # ["Persistence", "Execution"]
    mitre_techniques = Column(JSON, default=list)  # ["T1053", "T1059"]
    source_log = Column(Text)  # RAW syslog or EventLog payload
    status = Column(String, default="New")  # New, Acknowledged, Resolved, Investigating, False Positive
    is_duplicate = Column(Boolean, default=False)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # SIEM Detection Engine fields
    rule_id = Column(String, index=True, nullable=True)
    alert_code = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    username = Column(String, nullable=True)
    evidence = Column(JSON, default=dict)
    matched_event_ids = Column(JSON, default=list)
    is_demo = Column(Boolean, default=False)
    
    asset = relationship("Asset", back_populates="alerts")
    incident = relationship("Incident", back_populates="alerts")

class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    description = Column(Text)
    severity = Column(String, default="Medium")  # Low, Medium, High, Critical
    status = Column(String, default="Open")  # Open, Investigating, Contained, Resolved, Closed
    risk_score = Column(Float, default=0.0)
    mitre_tactics = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    assigned_to = Column(String, nullable=True)  # Username
    creator = Column(String, default="SIEM Engine")
    ai_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    closed_at = Column(DateTime, nullable=True)
    
    alerts = relationship("Alert", back_populates="incident")
    timeline = relationship("IncidentTimeline", back_populates="incident", cascade="all, delete-orphan")
    evidence = relationship("IncidentEvidence", back_populates="incident", cascade="all, delete-orphan")
    tasks = relationship("IncidentTask", back_populates="incident", cascade="all, delete-orphan")
    comments = relationship("IncidentComment", back_populates="incident", cascade="all, delete-orphan")

class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String, nullable=False)  # log_ingested, host_isolated, note_added, etc.
    message = Column(Text, nullable=False)
    actor = Column(String, default="System")
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    incident = relationship("Incident", back_populates="timeline")

class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    file_name = Column(String, nullable=False)
    file_hash = Column(String, nullable=False)  # SHA-256
    file_size = Column(Integer)  # bytes
    chain_of_custody = Column(Text)  # Audit log of who touched it and when
    uploaded_by = Column(String, nullable=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    
    incident = relationship("Incident", back_populates="evidence")

class IncidentTask(Base):
    __tablename__ = "incident_tasks"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    description = Column(String, nullable=False)
    status = Column(String, default="Pending")  # Pending, Completed
    assigned_to = Column(String, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    incident = relationship("Incident", back_populates="tasks")

class IncidentComment(Base):
    __tablename__ = "incident_comments"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    comment_text = Column(Text, nullable=False)
    author = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    incident = relationship("Incident", back_populates="comments")

class Playbook(Base):
    __tablename__ = "playbooks"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    trigger_condition = Column(JSON, default=dict)  # Alert category/severity rules
    nodes = Column(JSON, default=list)  # React Flow node definitions
    edges = Column(JSON, default=list)  # React Flow connection definitions
    version = Column(Integer, default=1)
    creator = Column(String, default="SOC Engineer")
    created_at = Column(DateTime, default=datetime.utcnow)

class PlaybookRun(Base):
    __tablename__ = "playbook_runs"
    
    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    status = Column(String, default="Running")  # Running, Completed, Failed, Pending Approval
    triggered_by = Column(String, default="Automation Engine")
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    log = Column(Text)  # Detailed log trace of nodes executed

class IOC(Base):
    __tablename__ = "iocs"
    
    id = Column(Integer, primary_key=True, index=True)
    value = Column(String, unique=True, index=True, nullable=False)  # IP, domain, hash, URL
    type = Column(String, nullable=False)  # IP, Domain, URL, Hash
    reputation = Column(String, default="Unknown")  # Safe, Suspicious, Malicious
    category = Column(String)  # Ransomware C2, Phishing Domain, etc.
    threat_actor = Column(String, default="Unknown")
    description = Column(Text)
    last_seen = Column(DateTime, default=datetime.utcnow)

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, index=True, nullable=False)
    description = Column(Text)
    category = Column(String, index=True, nullable=False)
    severity = Column(String, index=True, default="Medium")
    enabled = Column(Boolean, default=True)
    configuration = Column(JSON, default=dict)
    mitre_tactics = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    total_detections = Column(Integer, default=0)
    last_triggered_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String, unique=True, index=True, nullable=False)
    event_type = Column(String, index=True, nullable=False)
    category = Column(String, index=True, default="Authentication")
    detection_status = Column(String, index=True, default="Normal")  # Normal, Alert Triggered, Under Triage
    matched_rule_id = Column(String, index=True, nullable=True)
    risk_score = Column(Float, default=0.0)
    username = Column(String, index=True, nullable=True)
    source_ip = Column(String, index=True, nullable=True)
    dest_ip = Column(String, nullable=True)
    timestamp = Column(DateTime, index=True, default=datetime.utcnow)
    source = Column(String, default="generic")
    severity = Column(String, default="low")
    details = Column(JSON, default=dict)
    raw_event = Column(Text, nullable=True)
    is_demo = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, index=True, nullable=False)
    rule_id = Column(String, index=True, nullable=False)
    rule_name = Column(String, nullable=False)
    title = Column(String, index=True, nullable=False)
    description = Column(Text)
    severity = Column(String, index=True, default="Medium")
    category = Column(String, index=True, default="General")
    source_ip = Column(String, nullable=True, index=True)
    username = Column(String, nullable=True, index=True)
    event_timestamp = Column(DateTime, default=datetime.utcnow)
    detection_timestamp = Column(DateTime, default=datetime.utcnow)
    matched_event_ids = Column(JSON, default=list)
    evidence = Column(JSON, default=dict)
    status = Column(String, index=True, default="New")  # New, Investigating, Escalated, Resolved, False Positive
    assigned_to = Column(String, nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    is_demo = Column(Boolean, default=False)
    
    # Advanced Live Triage, Deduplication & Threat Intelligence
    occurrence_count = Column(Integer, default=1)
    is_duplicate = Column(Boolean, default=False)
    dedup_key = Column(String, index=True, nullable=True)
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime, default=datetime.utcnow)
    destination_ip = Column(String, nullable=True)
    correlation_id = Column(String, index=True, nullable=True)
    risk_score = Column(Float, default=0.0)  # 0 to 100
    risk_factors = Column(JSON, default=list)
    threat_intel = Column(JSON, default=dict)
    ai_analysis = Column(JSON, default=dict)
    priority = Column(String, default="P3")  # P1, P2, P3, P4
    notes = Column(JSON, default=list)
    audit_trail = Column(JSON, default=list)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ==========================================
# UEBA (User and Entity Behaviour Analytics)
# ==========================================

class UEBAProfile(Base):
    __tablename__ = "ueba_profiles"

    id = Column(Integer, primary_key=True, index=True)
    entity_id = Column(String, unique=True, index=True, nullable=False)  # username, hostname, or IP
    entity_type = Column(String, index=True, default="user")  # user, endpoint, server, ip, service_account
    display_name = Column(String, nullable=True)
    baseline_status = Column(String, index=True, default="Learning")  # Learning, Established, Insufficient Data, Outdated
    risk_score = Column(Float, default=0.0)  # 0 to 100
    risk_level = Column(String, default="Low")  # Low, Medium, High, Critical
    learning_started_at = Column(DateTime, default=datetime.utcnow)
    last_updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    baseline_version = Column(Integer, default=1)
    metadata_info = Column(JSON, default=dict)  # department, role, device_type, os, criticality
    anomalies_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    baselines = relationship("UEBABaseline", back_populates="profile", cascade="all, delete-orphan")


class UEBABaseline(Base):
    __tablename__ = "ueba_baselines"

    id = Column(Integer, primary_key=True, index=True)
    profile_id = Column(Integer, ForeignKey("ueba_profiles.id", ondelete="CASCADE"), nullable=False)
    behaviour_category = Column(String, index=True, nullable=False)  # login_hours, login_frequency, login_locations, resource_access, data_volume, session_duration
    baseline_data = Column(JSON, default=dict)  # e.g. {"typical_hours": [9, 10, ...], "mean_data_mb": 15.2, "std_data_mb": 4.1}
    sample_count = Column(Integer, default=0)
    confidence = Column(Float, default=0.0)  # 0.0 to 1.0
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    profile = relationship("UEBAProfile", back_populates="baselines")


class UEBAFinding(Base):
    __tablename__ = "ueba_findings"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(String, unique=True, index=True, nullable=False)  # UEBA-XXXX
    entity_id = Column(String, index=True, nullable=False)
    entity_type = Column(String, index=True, default="user")
    anomaly_type = Column(String, index=True, nullable=False)  # Unusual Login Time, Inactive Account Activity, etc.
    detection_method = Column(String, default="Statistical Z-Score")  # Statistical Z-Score, Rule-Based Baseline, Behavioral Deviation, Isolation Forest
    risk_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.8)  # 0.0 to 1.0
    severity = Column(String, index=True, default="Medium")  # Low, Medium, High, Critical
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(JSON, default=dict)  # current_value, expected_range, deviation_score, z_score, threshold
    related_event_ids = Column(JSON, default=list)
    recommended_steps = Column(JSON, default=list)  # investigation recommendations
    status = Column(String, index=True, default="New")  # New, Investigating, Escalated, Resolved, False Positive
    assigned_to = Column(String, nullable=True)
    is_demo = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class UEBAFeedback(Base):
    __tablename__ = "ueba_feedback"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(String, index=True, nullable=False)
    analyst_id = Column(String, nullable=False)
    feedback_type = Column(String, nullable=False)  # True Positive, False Positive, Expected Deviation, Authorized Testing
    comments = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


