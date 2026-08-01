from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

# --- Shared Request/Update helpers (used by routers) ---
class IncidentStatusUpdate(BaseModel):
    status: str

class CommentCreate(BaseModel):
    comment_text: str

class PlaybookExecuteRequest(BaseModel):
    incident_id: int

# --- Token Schemas ---
class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

# --- User Schemas ---
class UserLogin(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    full_name: Optional[str] = None
    role: Optional[str] = "Tier 1 Analyst"

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

# --- Vulnerability Schemas ---
class VulnerabilityResponse(BaseModel):
    id: int
    asset_id: int
    cve_id: str
    title: str
    description: Optional[str] = None
    cvss_score: float
    patch_status: str
    exploit_available: bool
    ai_remediation: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

# --- Asset Schemas ---
class AssetResponse(BaseModel):
    id: int
    name: str
    ip_address: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    criticality: str
    risk_score: float
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    network_location: Optional[str] = None
    installed_software: List[Dict[str, Any]] = []
    created_at: datetime
    vulnerabilities: List[VulnerabilityResponse] = []

    class Config:
        from_attributes = True

# --- Alert Schemas ---
class AlertResponse(BaseModel):
    id: int
    title: str
    category: str
    severity: str
    description: Optional[str] = None
    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []
    source_log: Optional[str] = None
    status: str
    is_duplicate: bool
    incident_id: Optional[int] = None
    asset_id: Optional[int] = None
    timestamp: datetime

    class Config:
        from_attributes = True

class AlertUpdate(BaseModel):
    status: Optional[str] = None
    incident_id: Optional[int] = None

# --- Incident Timeline ---
class IncidentTimelineResponse(BaseModel):
    id: int
    incident_id: int
    event_type: str
    message: str
    actor: str
    timestamp: datetime

    class Config:
        from_attributes = True

# --- Incident Evidence ---
class IncidentEvidenceResponse(BaseModel):
    id: int
    incident_id: int
    file_name: str
    file_hash: str
    file_size: Optional[int] = None
    chain_of_custody: Optional[str] = None
    uploaded_by: str
    uploaded_at: datetime

    class Config:
        from_attributes = True

# --- Incident Tasks ---
class IncidentTaskCreate(BaseModel):
    description: str
    assigned_to: Optional[str] = None

class IncidentTaskUpdate(BaseModel):
    status: Optional[str] = None
    completed_at: Optional[datetime] = None

class IncidentTaskResponse(BaseModel):
    id: int
    incident_id: int
    description: str
    status: str
    assigned_to: Optional[str] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# --- Incident Comments ---
class IncidentCommentCreate(BaseModel):
    comment_text: str

class IncidentCommentResponse(BaseModel):
    id: int
    incident_id: int
    comment_text: str
    author: str
    timestamp: datetime

    class Config:
        from_attributes = True

# --- Incident Schemas ---
class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: Optional[str] = "Medium"
    alert_ids: Optional[List[int]] = []

class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    assigned_to: Optional[str] = None
    risk_score: Optional[float] = None

class IncidentResponse(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    risk_score: float
    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []
    assigned_to: Optional[str] = None
    creator: str
    ai_summary: Optional[str] = None
    created_at: datetime
    closed_at: Optional[datetime] = None
    
    alerts: List[AlertResponse] = []
    timeline: List[IncidentTimelineResponse] = []
    evidence: List[IncidentEvidenceResponse] = []
    tasks: List[IncidentTaskResponse] = []
    comments: List[IncidentCommentResponse] = []

    class Config:
        from_attributes = True

# --- Playbook Schemas ---
class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_condition: Dict[str, Any] = {}
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

class PlaybookUpdate(BaseModel):
    description: Optional[str] = None
    is_active: Optional[bool] = None
    trigger_condition: Optional[Dict[str, Any]] = None
    nodes: Optional[List[Dict[str, Any]]] = None
    edges: Optional[List[Dict[str, Any]]] = None
    version: Optional[int] = None

class PlaybookResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    is_active: bool
    trigger_condition: Dict[str, Any] = {}
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    version: int
    creator: str
    created_at: datetime

    class Config:
        from_attributes = True

class PlaybookRunResponse(BaseModel):
    id: int
    playbook_id: int
    incident_id: int
    status: str
    triggered_by: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    log: Optional[str] = None

    class Config:
        from_attributes = True

# --- IOC Schemas ---
class IOCCreate(BaseModel):
    value: str
    type: str
    reputation: Optional[str] = "Unknown"
    category: Optional[str] = None
    threat_actor: Optional[str] = "Unknown"
    description: Optional[str] = None

class IOCResponse(BaseModel):
    id: int
    value: str
    type: str
    reputation: str
    category: Optional[str] = None
    threat_actor: str
    description: Optional[str] = None
    last_seen: datetime

    class Config:
        from_attributes = True

# --- Aliases for backward-compat with routers ---
TimelineResponse = IncidentTimelineResponse
CommentResponse = IncidentCommentResponse
