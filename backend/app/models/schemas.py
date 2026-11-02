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
class AssetCreate(BaseModel):
    name: str
    ip_address: str
    hostname: Optional[str] = None
    os: Optional[str] = "Linux"
    criticality: Optional[str] = "Medium"
    risk_score: Optional[float] = 0.0
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    network_location: Optional[str] = "Internal"
    installed_software: List[Dict[str, Any]] = []

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

# --- SIEM Detection Engine Schemas ---
class SecurityEventCreate(BaseModel):
    event_id: Optional[str] = None
    event_type: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    timestamp: Optional[datetime] = None
    source: Optional[str] = "generic"
    severity: Optional[str] = "low"
    details: Optional[Dict[str, Any]] = Field(default_factory=dict)
    raw_event: Optional[Any] = None
    is_demo: Optional[bool] = False

class SecurityEventResponse(BaseModel):
    id: int
    event_id: str
    event_type: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    timestamp: datetime
    source: str
    severity: str
    details: Dict[str, Any] = Field(default_factory=dict)
    raw_event: Optional[str] = None
    is_demo: bool = False
    created_at: datetime

    class Config:
        from_attributes = True

class DetectionRuleResponse(BaseModel):
    id: int
    rule_id: str
    name: str
    description: Optional[str] = None
    category: str
    severity: str
    enabled: bool
    configuration: Dict[str, Any] = Field(default_factory=dict)
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    total_detections: int = 0
    last_triggered_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class DetectionRuleUpdate(BaseModel):
    enabled: Optional[bool] = None
    configuration: Optional[Dict[str, Any]] = None
    severity: Optional[str] = None

class SecurityAlertResponse(BaseModel):
    id: int
    alert_id: str
    rule_id: str
    rule_name: str
    title: str
    description: Optional[str] = None
    severity: str
    category: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_timestamp: datetime
    detection_timestamp: datetime
    matched_event_ids: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    status: str
    assigned_to: Optional[str] = None
    incident_id: Optional[int] = None
    is_demo: bool = False
    
    # Advanced Live Triage Fields
    occurrence_count: int = 1
    is_duplicate: bool = False
    correlation_id: Optional[str] = None
    risk_score: float = 0.0
    priority: str = "P3"
    risk_factors: List[Dict[str, Any]] = Field(default_factory=list)
    threat_intel: Dict[str, Any] = Field(default_factory=dict)
    ai_analysis: Dict[str, Any] = Field(default_factory=dict)
    notes: List[Dict[str, Any]] = Field(default_factory=list)
    audit_trail: List[Dict[str, Any]] = Field(default_factory=list)

    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class SecurityAlertUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    priority: Optional[str] = None
    note: Optional[str] = None

class RemediationRequest(BaseModel):
    action: str  # block_ip, isolate_host, disable_user, trigger_playbook
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)
    approved: bool = True

class DemoGenerateRequest(BaseModel):
    rule_id: Optional[str] = None
    count: Optional[int] = 1

class DemoResetResponse(BaseModel):
    message: str
    deleted_events_count: int
    deleted_alerts_count: int

# --- Security Events Schemas for Live Recent Activity Feed ---
class SecurityEventResponse(BaseModel):
    id: int
    event_id: str
    event_type: str
    category: str
    severity: str
    detection_status: str
    matched_rule_id: Optional[str] = None
    risk_score: float = 0.0
    source_ip: Optional[str] = None
    username: Optional[str] = None
    dest_ip: Optional[str] = None
    source: str
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime
    is_demo: bool = False

    class Config:
        from_attributes = True

class SecurityEventDetailResponse(SecurityEventResponse):
    raw_event: Optional[str] = None
    matched_rule: Optional[Dict[str, Any]] = None
    detection_explanation: Optional[str] = None
    related_events: List[SecurityEventResponse] = Field(default_factory=list)

class SecurityEventListResponse(BaseModel):
    items: List[SecurityEventResponse]
    total: int
    skip: int
    limit: int


# ==========================================
# UEBA Schemas
# ==========================================

class UEBABaselineResponse(BaseModel):
    id: int
    behaviour_category: str
    baseline_data: Dict[str, Any] = Field(default_factory=dict)
    sample_count: int
    confidence: float
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class UEBAProfileResponse(BaseModel):
    id: int
    entity_id: str
    entity_type: str
    display_name: Optional[str] = None
    baseline_status: str
    risk_score: float
    risk_level: str
    learning_started_at: datetime
    last_updated_at: datetime
    baseline_version: int
    metadata_info: Dict[str, Any] = Field(default_factory=dict)
    anomalies_count: int
    created_at: datetime

    class Config:
        from_attributes = True

class UEBAProfileDetailResponse(UEBAProfileResponse):
    baselines: List[UEBABaselineResponse] = Field(default_factory=list)
    active_findings_count: int = 0
    recent_activity_count: int = 0

class UEBAFindingResponse(BaseModel):
    id: int
    finding_id: str
    entity_id: str
    entity_type: str
    anomaly_type: str
    detection_method: str
    risk_score: float
    confidence: float
    severity: str
    title: str
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    related_event_ids: List[str] = Field(default_factory=list)
    recommended_steps: List[str] = Field(default_factory=list)
    status: str
    assigned_to: Optional[str] = None
    is_demo: bool = False
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class UEBAFindingStatusUpdate(BaseModel):
    status: str
    assigned_to: Optional[str] = None
    comments: Optional[str] = None

class UEBAFeedbackCreate(BaseModel):
    finding_id: str
    feedback_type: str  # True Positive, False Positive, Expected Deviation, Authorized Testing
    comments: Optional[str] = None

class UEBAFeedbackResponse(BaseModel):
    id: int
    finding_id: str
    analyst_id: str
    feedback_type: str
    comments: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

class UEBADashboardStats(BaseModel):
    total_monitored_users: int
    total_monitored_entities: int
    entities_with_anomalies: int
    high_risk_entities_count: int
    new_findings_count: int
    baseline_status_breakdown: Dict[str, int]
    risk_distribution: Dict[str, int]
    anomaly_categories: Dict[str, int]
    recent_findings: List[UEBAFindingResponse]

class UEBARiskScoreItem(BaseModel):
    entity_id: str
    entity_type: str
    risk_score: float
    risk_level: str
    deviation_score: float
    anomalies_count: int
    contributing_factors: List[Dict[str, Any]] = Field(default_factory=list)

class UEBATimelineItem(BaseModel):
    timestamp: datetime
    event_type: str
    category: str
    is_anomaly: bool
    title: str
    severity: str
    details: Dict[str, Any] = Field(default_factory=dict)

class UEBADemoGenerateRequest(BaseModel):
    scenario: Optional[str] = "all"  # unusual_login_time, dormant_account, mass_resource_access, auth_velocity, bulk_data_exfiltration, all
    entity_id: Optional[str] = None


# ──────────────────────────────────────────────
# Vulnerability & Exposure Management (VEM) Schemas
# ──────────────────────────────────────────────

class VulnerabilityFindingResponse(BaseModel):
    id: int
    finding_id: str
    assessment_id: Optional[int] = None
    asset_id: Optional[int] = None
    cve_id: Optional[str] = None
    category: str
    title: str
    description: Optional[str] = None
    severity: str
    cvss_score: float
    risk_score: float
    confidence: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation: Optional[str] = None
    status: str
    assigned_to: Optional[str] = None
    due_date: Optional[str] = None
    remediation_notes: Optional[str] = None
    audit_history: List[Dict[str, Any]] = Field(default_factory=list)
    is_demo: bool = False
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class VulnerabilityFindingUpdate(BaseModel):
    status: Optional[str] = None  # Open, In Progress, Fixed, Accepted Risk, Verified
    assigned_to: Optional[str] = None
    due_date: Optional[str] = None
    remediation_notes: Optional[str] = None
    verification_notes: Optional[str] = None


class VulnerabilityAssessmentResponse(BaseModel):
    id: int
    assessment_id: str
    title: str
    tool_name: str
    target: str
    status: str
    findings_count: int
    risk_score: float
    summary: Optional[str] = None
    raw_results: Dict[str, Any] = Field(default_factory=dict)
    initiated_by: str
    is_demo: bool = False
    created_at: datetime

    class Config:
        from_attributes = True


class VulnerabilityDashboardStats(BaseModel):
    total_assets: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    remediated_count: int
    average_risk_score: float
    risk_distribution: Dict[str, int]
    category_distribution: Dict[str, int]
    top_vulnerable_assets: List[Dict[str, Any]]
    recent_assessments: List[VulnerabilityAssessmentResponse]
    recent_findings: List[VulnerabilityFindingResponse]


# Tool Request Payloads
class ToolHeaderCheckRequest(BaseModel):
    url: str
    asset_id: Optional[int] = None


class ToolCertCheckRequest(BaseModel):
    host: str
    port: Optional[int] = 443
    asset_id: Optional[int] = None


class ToolDependencyCheckRequest(BaseModel):
    manifest_content: str
    filename: Optional[str] = "requirements.txt"
    asset_id: Optional[int] = None


class ToolCVELookupRequest(BaseModel):
    query: str  # CVE ID or software name


class ToolPortCheckRequest(BaseModel):
    asset_id: Optional[int] = None
    asset_name: Optional[str] = "Authorized Gateway"
    ip_address: Optional[str] = "192.168.1.50"
    open_ports: Optional[List[int]] = None
    scan_text: Optional[str] = None
    is_internet_facing: Optional[bool] = True


class ToolWebAppCheckRequest(BaseModel):
    url: str
    asset_id: Optional[int] = None


class ToolConfigCheckRequest(BaseModel):
    config_content: str
    filename: Optional[str] = "settings.py"
    asset_id: Optional[int] = None


class ToolRiskCalculateRequest(BaseModel):
    cvss_score: float
    asset_criticality: Optional[str] = "Medium"
    network_exposure: Optional[str] = "Internet-facing"
    exploit_available: Optional[bool] = False
    cisa_kev: Optional[bool] = False
    confidence: Optional[str] = "Confirmed"


class ToolRemediateRequest(BaseModel):
    finding_id: int
    status: str
    notes: Optional[str] = ""
    assigned_to: Optional[str] = None
    due_date: Optional[str] = None


class ToolReportGenerateRequest(BaseModel):
    title: Optional[str] = "Comprehensive Security Assessment Report"
    target_name: Optional[str] = "Production Infrastructure"
    assessment_type: Optional[str] = "Full Defensive Surface Audit"
    report_type: Optional[str] = "technical"


# ──────────────────────────────────────────────
# Attack Surface Management (ASM) Schemas
# ──────────────────────────────────────────────

class ASMAssetResponse(BaseModel):
    id: int
    asset_id: str
    name: str
    asset_type: str
    domain_name: Optional[str] = None
    ip_address: Optional[str] = None
    environment: str
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    criticality: str
    authorization_status: str
    discovery_source: str
    exposure_level: str
    risk_score: float
    status: str
    first_seen: datetime
    last_seen: datetime
    metadata_info: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class ASMAssetCreate(BaseModel):
    name: str
    asset_type: str
    domain_name: Optional[str] = None
    ip_address: Optional[str] = None
    environment: Optional[str] = "Production"
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    criticality: Optional[str] = "Medium"
    exposure_level: Optional[str] = "Public Internet"
    discovery_source: Optional[str] = "Manual"


class ASMAssetUpdate(BaseModel):
    name: Optional[str] = None
    criticality: Optional[str] = None
    owner: Optional[str] = None
    status: Optional[str] = None
    authorization_status: Optional[str] = None
    exposure_level: Optional[str] = None


class ASMDomainResponse(BaseModel):
    id: int
    domain_id: str
    root_domain: str
    subdomain: str
    ip_addresses: List[str] = Field(default_factory=list)
    cname_target: Optional[str] = None
    dns_status: str
    is_apex: bool
    is_active: bool
    discovered_via: str
    first_seen: datetime
    last_seen: datetime
    flagged_review: bool

    class Config:
        from_attributes = True


class ASMDomainCreate(BaseModel):
    root_domain: str
    subdomain: str
    ip_addresses: Optional[List[str]] = None
    cname_target: Optional[str] = None


class ASMCertificateResponse(BaseModel):
    id: int
    cert_id: str
    domain_name: str
    port: int
    issuer: Optional[str] = None
    subject_cn: Optional[str] = None
    sans: List[str] = Field(default_factory=list)
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    days_remaining: int
    status: str
    tls_version: str
    cipher_suite: Optional[str] = None
    chain_status: str
    last_checked: datetime

    class Config:
        from_attributes = True


class ASMServiceResponse(BaseModel):
    id: int
    service_id: str
    asset_id: Optional[str] = None
    hostname: str
    ip_address: Optional[str] = None
    port: int
    protocol: str
    service_name: str
    version: Optional[str] = None
    is_approved_baseline: bool
    exposure_status: str
    risk_level: str
    last_assessed: datetime

    class Config:
        from_attributes = True


class ASMServiceUpdate(BaseModel):
    is_approved_baseline: Optional[bool] = None
    exposure_status: Optional[str] = None


class ASMChangeLogResponse(BaseModel):
    id: int
    change_id: str
    asset_id: str
    asset_name: str
    change_type: str
    previous_value: Optional[str] = None
    current_value: Optional[str] = None
    severity: str
    description: str
    timestamp: datetime
    reviewed: bool
    reviewed_by: Optional[str] = None

    class Config:
        from_attributes = True


class ASMDNSCheckRequest(BaseModel):
    domain: str
    dkim_selector: Optional[str] = "default"


class ASMDashboardStats(BaseModel):
    total_assets: int
    total_domains: int
    total_certificates: int
    expiring_certificates_count: int
    total_services: int
    unexpected_services_count: int
    active_change_events: int
    average_attack_surface_risk: float
    asset_types_distribution: Dict[str, int]
    exposure_distribution: Dict[str, int]
    environment_distribution: Dict[str, int]
    critical_perimeter_assets: List[ASMAssetResponse]
    recent_changes: List[ASMChangeLogResponse]
    expiring_certificates: List[ASMCertificateResponse]
    unexpected_services: List[ASMServiceResponse]




