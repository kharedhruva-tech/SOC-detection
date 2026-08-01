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
    status = Column(String, default="New")  # New, Acknowledged, Resolved
    is_duplicate = Column(Boolean, default=False)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
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
