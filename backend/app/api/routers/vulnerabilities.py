import random
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from app.database import get_db
from app.models import models, schemas
from app.vulnerability import (
    header_checker,
    cert_checker,
    dependency_scanner,
    cve_lookup_service,
    port_exposure_service,
    webapp_scanner,
    misconfig_checker,
    risk_prioritizer,
    remediation_service,
    report_generator,
)

router = APIRouter()

# ──────────────────────────────────────────────
# Helper: Seed default sample findings if empty
# ──────────────────────────────────────────────
def ensure_default_sample_findings(db: Session):
    existing = db.query(models.VulnerabilityFinding).first()
    if existing:
        return

    # Check assets
    asset = db.query(models.Asset).first()
    asset_id = asset.id if asset else None

    # Create an initial assessment
    initial_asm = models.VulnerabilityAssessment(
        assessment_id=f"ASM-{datetime.now(timezone.utc).strftime('%Y%m%d')}-001",
        title="Baseline Production Surface Audit",
        tool_name="Full Defensive Surface Audit",
        target="api.enterprise-soc.local",
        status="Completed",
        findings_count=5,
        risk_score=78.5,
        summary="Automated multi-tool assessment identified 2 Critical and 2 High findings across security headers, dependencies, and configuration.",
        initiated_by="Automated Scheduled Scanner",
        is_demo=True,
    )
    db.add(initial_asm)
    db.commit()
    db.refresh(initial_asm)

    sample_findings = [
        {
            "finding_id": f"VULN-{datetime.now(timezone.utc).strftime('%Y')}-001",
            "assessment_id": initial_asm.id,
            "asset_id": asset_id,
            "cve_id": "CVE-2021-44228",
            "category": "Dependencies",
            "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
            "description": "Critical unauthenticated JNDI lookup vulnerability in log4j-core allows arbitrary remote code execution via LDAP lookup strings.",
            "severity": "Critical",
            "cvss_score": 10.0,
            "risk_score": 96.0,
            "confidence": "Confirmed",
            "evidence": {"package": "log4j-core", "installed": "2.14.1", "affected_range": "<2.17.1"},
            "remediation": "Upgrade Apache Log4j to version 2.17.1 or higher immediately.",
            "status": "In Progress",
            "assigned_to": "Sarah Connor (AppSec)",
            "due_date": (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%d"),
            "remediation_notes": "Emergency maintenance window scheduled for container base image update.",
            "audit_history": [
                {"timestamp": datetime.now(timezone.utc).isoformat(), "analyst": "Automated Scanner", "action": "Finding Logged", "notes": "Discovered via Dependency Scanner"},
                {"timestamp": datetime.now(timezone.utc).isoformat(), "analyst": "Alex Mercer", "action": "Status changed to In Progress", "notes": "Assigned P1 ticket to AppSec lead."}
            ],
            "is_demo": True,
        },
        {
            "finding_id": f"VULN-{datetime.now(timezone.utc).strftime('%Y')}-002",
            "assessment_id": initial_asm.id,
            "asset_id": asset_id,
            "cve_id": None,
            "category": "Security Headers",
            "title": "Missing Strict-Transport-Security (HSTS) Header",
            "description": "The web application does not transmit the Strict-Transport-Security header, leaving users vulnerable to SSL-stripping and MITM attacks.",
            "severity": "High",
            "cvss_score": 7.4,
            "risk_score": 72.0,
            "confidence": "Confirmed",
            "evidence": {"header": "Strict-Transport-Security", "status": "Missing"},
            "remediation": "Add header 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to web server configuration.",
            "status": "Open",
            "assigned_to": "David Kim (DevOps)",
            "due_date": (datetime.now(timezone.utc) + timedelta(days=3)).strftime("%Y-%m-%d"),
            "audit_history": [
                {"timestamp": datetime.now(timezone.utc).isoformat(), "analyst": "Automated Scanner", "action": "Finding Logged", "notes": "Header check completed"}
            ],
            "is_demo": True,
        },
        {
            "finding_id": f"VULN-{datetime.now(timezone.utc).strftime('%Y')}-003",
            "assessment_id": initial_asm.id,
            "asset_id": asset_id,
            "cve_id": None,
            "category": "Misconfiguration",
            "title": "Debug Mode Enabled in Production Environment",
            "description": "The configuration file defines DEBUG = True, exposing interactive execution tracebacks and environment variable secrets.",
            "severity": "Critical",
            "cvss_score": 8.8,
            "risk_score": 89.5,
            "confidence": "Confirmed",
            "evidence": {"setting": "DEBUG", "value": "True", "line": 42},
            "remediation": "Set DEBUG = False and configure centralized logging for error reporting.",
            "status": "Open",
            "assigned_to": "Elena Rostova (DevSecOps)",
            "due_date": (datetime.now(timezone.utc) + timedelta(days=2)).strftime("%Y-%m-%d"),
            "audit_history": [
                {"timestamp": datetime.now(timezone.utc).isoformat(), "analyst": "Automated Scanner", "action": "Finding Logged", "notes": "Static configuration check"}
            ],
            "is_demo": True,
        },
        {
            "finding_id": f"VULN-{datetime.now(timezone.utc).strftime('%Y')}-004",
            "assessment_id": initial_asm.id,
            "asset_id": asset_id,
            "cve_id": "CVE-2023-32681",
            "category": "Dependencies",
            "title": "Proxy-Authorization Header Leak to HTTPS Destination",
            "description": "Python requests library prior to 2.31.0 forwards Proxy-Authorization headers when following redirects to different hostnames.",
            "severity": "Medium",
            "cvss_score": 6.1,
            "risk_score": 54.0,
            "confidence": "Confirmed",
            "evidence": {"package": "requests", "installed": "2.28.1", "affected_range": "<2.31.0"},
            "remediation": "Upgrade requests to version 2.31.0 or higher in requirements.txt.",
            "status": "Verified",
            "assigned_to": "DevOps Pipeline",
            "due_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "remediation_notes": "Automated PR merged, dependencies updated and verified in staging.",
            "audit_history": [
                {"timestamp": datetime.now(timezone.utc).isoformat(), "analyst": "Automated Scanner", "action": "Finding Logged", "notes": "Requirements scan"},
                {"timestamp": datetime.now(timezone.utc).isoformat(), "analyst": "Alex Mercer", "action": "Status changed to Verified", "notes": "Confirmed pip check passes on v2.31.0"}
            ],
            "is_demo": True,
        },
        {
            "finding_id": f"VULN-{datetime.now(timezone.utc).strftime('%Y')}-005",
            "assessment_id": initial_asm.id,
            "asset_id": asset_id,
            "cve_id": None,
            "category": "Exposed Port",
            "title": "Unauthenticated Redis Database Exposed on External Port 6379",
            "description": "In-memory database port 6379 is accessible from public network interface without access control list restrictions.",
            "severity": "High",
            "cvss_score": 7.5,
            "risk_score": 82.0,
            "confidence": "Confirmed",
            "evidence": {"port": 6379, "service": "Redis", "exposure": "Publicly Exposed"},
            "remediation": "Bind Redis only to 127.0.0.1 or internal VPC interface, and enforce strong requirepass password authentication.",
            "status": "In Progress",
            "assigned_to": "David Kim (DevOps)",
            "due_date": (datetime.now(timezone.utc) + timedelta(days=2)).strftime("%Y-%m-%d"),
            "audit_history": [
                {"timestamp": datetime.now(timezone.utc).isoformat(), "analyst": "Automated Scanner", "action": "Finding Logged", "notes": "Port exposure assessment"}
            ],
            "is_demo": True,
        }
    ]

    for item in sample_findings:
        f = models.VulnerabilityFinding(**item)
        db.add(f)
    db.commit()


# ──────────────────────────────────────────────
# 1. Dashboard Statistics & Overview
# ──────────────────────────────────────────────
@router.get("/dashboard", response_model=schemas.VulnerabilityDashboardStats)
def get_vulnerability_dashboard(db: Session = Depends(get_db)):
    ensure_default_sample_findings(db)

    total_assets = db.query(models.Asset).count()
    all_findings = db.query(models.VulnerabilityFinding).all()
    total_findings = len(all_findings)

    crit_count = sum(1 for f in all_findings if f.severity == "Critical")
    high_count = sum(1 for f in all_findings if f.severity == "High")
    med_count = sum(1 for f in all_findings if f.severity == "Medium")
    low_count = sum(1 for f in all_findings if f.severity == "Low")

    remediated_count = sum(1 for f in all_findings if f.status in ("Fixed", "Verified"))
    avg_risk = round(sum(f.risk_score for f in all_findings) / max(1, total_findings), 1)

    # Risk tier distribution
    risk_dist = {
        "Critical (85-100)": sum(1 for f in all_findings if f.risk_score >= 85),
        "High (70-84)": sum(1 for f in all_findings if 70 <= f.risk_score < 85),
        "Medium (45-69)": sum(1 for f in all_findings if 45 <= f.risk_score < 70),
        "Low (0-44)": sum(1 for f in all_findings if f.risk_score < 45),
    }

    # Category distribution
    cat_dist: Dict[str, int] = {}
    for f in all_findings:
        cat_dist[f.category] = cat_dist.get(f.category, 0) + 1

    # Top vulnerable assets
    top_assets_data: List[Dict[str, Any]] = []
    assets = db.query(models.Asset).limit(5).all()
    for a in assets:
        asset_findings = [f for f in all_findings if f.asset_id == a.id]
        top_assets_data.append({
            "id": a.id,
            "name": a.name,
            "ip_address": a.ip_address,
            "hostname": a.hostname,
            "criticality": a.criticality,
            "risk_score": a.risk_score,
            "findings_count": len(asset_findings),
        })

    recent_assessments = db.query(models.VulnerabilityAssessment).order_by(desc(models.VulnerabilityAssessment.created_at)).limit(6).all()
    recent_findings = db.query(models.VulnerabilityFinding).order_by(desc(models.VulnerabilityFinding.created_at)).limit(10).all()

    return schemas.VulnerabilityDashboardStats(
        total_assets=max(total_assets, 1),
        total_vulnerabilities=total_findings,
        critical_count=crit_count,
        high_count=high_count,
        medium_count=med_count,
        low_count=low_count,
        remediated_count=remediated_count,
        average_risk_score=avg_risk,
        risk_distribution=risk_dist,
        category_distribution=cat_dist,
        top_vulnerable_assets=top_assets_data,
        recent_assessments=recent_assessments,
        recent_findings=recent_findings,
    )


# ──────────────────────────────────────────────
# 2. Findings Management
# ──────────────────────────────────────────────
@router.get("/findings", response_model=List[schemas.VulnerabilityFindingResponse])
def get_vulnerability_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    asset_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    ensure_default_sample_findings(db)
    query = db.query(models.VulnerabilityFinding)

    if severity and severity != "All":
        query = query.filter(models.VulnerabilityFinding.severity == severity.capitalize())
    if status and status != "All":
        query = query.filter(models.VulnerabilityFinding.status == status)
    if category and category != "All":
        query = query.filter(models.VulnerabilityFinding.category == category)
    if asset_id:
        query = query.filter(models.VulnerabilityFinding.asset_id == asset_id)
    if search:
        search_fmt = f"%{search}%"
        query = query.filter(
            (models.VulnerabilityFinding.title.ilike(search_fmt)) |
            (models.VulnerabilityFinding.finding_id.ilike(search_fmt)) |
            (models.VulnerabilityFinding.cve_id.ilike(search_fmt)) |
            (models.VulnerabilityFinding.description.ilike(search_fmt))
        )

    return query.order_by(desc(models.VulnerabilityFinding.risk_score)).offset(skip).limit(limit).all()


@router.get("/findings/{finding_id}", response_model=schemas.VulnerabilityFindingResponse)
def get_finding_detail(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(models.VulnerabilityFinding).filter(models.VulnerabilityFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/findings/{finding_id}", response_model=schemas.VulnerabilityFindingResponse)
def update_finding(finding_id: int, update_data: schemas.VulnerabilityFindingUpdate, db: Session = Depends(get_db)):
    finding = db.query(models.VulnerabilityFinding).filter(models.VulnerabilityFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    old_status = finding.status
    if update_data.status:
        if update_data.status == "Verified" and not (update_data.verification_notes or update_data.remediation_notes):
            raise HTTPException(status_code=400, detail="Verification requires confirmation notes explaining how the fix was validated.")
        finding.status = update_data.status

    if update_data.assigned_to is not None:
        finding.assigned_to = update_data.assigned_to
    if update_data.due_date is not None:
        finding.due_date = update_data.due_date
    if update_data.remediation_notes is not None:
        finding.remediation_notes = update_data.remediation_notes

    # Append to audit history
    now_str = datetime.now(timezone.utc).isoformat()
    history = list(finding.audit_history or [])
    history.append({
        "timestamp": now_str,
        "analyst": "SOC Analyst",
        "previous_status": old_status,
        "new_status": finding.status,
        "notes": update_data.verification_notes or update_data.remediation_notes or "Field update",
        "assigned_to": finding.assigned_to,
    })
    finding.audit_history = history
    finding.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(finding)
    return finding


# ──────────────────────────────────────────────
# 3. Asset Management Integration
# ──────────────────────────────────────────────
@router.get("/assets", response_model=List[schemas.AssetResponse])
def get_assets(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(models.Asset).offset(skip).limit(limit).all()


@router.post("/assets", response_model=schemas.AssetResponse)
def create_asset(asset: schemas.AssetCreate, db: Session = Depends(get_db)):
    existing = db.query(models.Asset).filter(models.Asset.hostname == asset.hostname).first()
    if existing:
        raise HTTPException(status_code=400, detail="Asset with this hostname already exists")
    db_asset = models.Asset(**asset.dict())
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return db_asset


# ──────────────────────────────────────────────
# 4. Assessment History
# ──────────────────────────────────────────────
@router.get("/assessments", response_model=List[schemas.VulnerabilityAssessmentResponse])
def get_assessments(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    return db.query(models.VulnerabilityAssessment).order_by(desc(models.VulnerabilityAssessment.created_at)).offset(skip).limit(limit).all()


@router.get("/assessments/{assessment_id}", response_model=schemas.VulnerabilityAssessmentResponse)
def get_assessment(assessment_id: int, db: Session = Depends(get_db)):
    asm = db.query(models.VulnerabilityAssessment).filter(models.VulnerabilityAssessment.id == assessment_id).first()
    if not asm:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return asm


# ──────────────────────────────────────────────
# 5. Tool 1: Website Security Header Checker
# ──────────────────────────────────────────────
@router.post("/tools/header-check")
def run_header_check(payload: schemas.ToolHeaderCheckRequest, db: Session = Depends(get_db)):
    res = header_checker.check_url(payload.url)
    if not res.get("success"):
        return res

    # Record assessment in database
    missing_count = sum(1 for f in res.get("findings", []) if f["status"] in ("Missing", "Weak"))
    risk_score = round(100 - res.get("score", 100), 1)

    asm = models.VulnerabilityAssessment(
        assessment_id=f"ASM-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{random.randint(100, 999)}",
        title=f"Security Header Audit: {payload.url}",
        tool_name="Website Security Header Checker",
        target=payload.url,
        status="Completed",
        findings_count=missing_count,
        risk_score=risk_score,
        summary=res.get("summary", ""),
        raw_results=res,
        initiated_by="SOC Analyst",
    )
    db.add(asm)
    db.commit()
    db.refresh(asm)
    res["assessment_id"] = asm.id

    return res


# ──────────────────────────────────────────────
# 6. Tool 2: SSL/TLS Certificate Checker
# ──────────────────────────────────────────────
@router.post("/tools/certificate-check")
def run_certificate_check(payload: schemas.ToolCertCheckRequest, db: Session = Depends(get_db)):
    res = cert_checker.check_certificate(payload.host, port=payload.port or 443)
    if not res.get("success"):
        return res

    concerns_count = len(res.get("concerns", []))
    risk_score = 90.0 if res.get("status") == "Expired" else (65.0 if res.get("status") == "Expiring Soon" else 15.0)

    asm = models.VulnerabilityAssessment(
        assessment_id=f"ASM-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{random.randint(100, 999)}",
        title=f"SSL/TLS Certificate Audit: {payload.host}",
        tool_name="SSL/TLS Certificate Checker",
        target=payload.host,
        status="Completed",
        findings_count=concerns_count,
        risk_score=risk_score,
        summary=f"Certificate status is {res.get('status')}. Days remaining: {res.get('days_remaining')}.",
        raw_results=res,
        initiated_by="SOC Analyst",
    )
    db.add(asm)
    db.commit()
    db.refresh(asm)
    res["assessment_id"] = asm.id

    return res


# ──────────────────────────────────────────────
# 7. Tool 3: Dependency Vulnerability Scanner
# ──────────────────────────────────────────────
@router.post("/tools/dependency-check")
def run_dependency_check(payload: schemas.ToolDependencyCheckRequest, db: Session = Depends(get_db)):
    res = dependency_scanner.scan_manifest(payload.manifest_content, filename=payload.filename or "requirements.txt")
    if not res.get("success"):
        return res

    vulns = res.get("vulnerabilities", [])
    crit = res["severity_counts"]["Critical"]
    high = res["severity_counts"]["High"]
    risk_score = min(100.0, crit * 35.0 + high * 20.0 + len(vulns) * 5.0)

    asm = models.VulnerabilityAssessment(
        assessment_id=f"ASM-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{random.randint(100, 999)}",
        title=f"Dependency Vulnerability Scan: {payload.filename}",
        tool_name="Dependency Vulnerability Scanner",
        target=payload.filename or "Manifest",
        status="Completed",
        findings_count=len(vulns),
        risk_score=risk_score,
        summary=f"Scanned {res.get('total_dependencies')} dependencies. Discovered {len(vulns)} vulnerable components.",
        raw_results=res,
        initiated_by="SOC Analyst",
    )
    db.add(asm)
    db.commit()
    db.refresh(asm)

    # Save findings into database
    for v in vulns:
        f = models.VulnerabilityFinding(
            finding_id=f"VULN-{datetime.now(timezone.utc).strftime('%Y')}-{random.randint(1000, 9999)}",
            assessment_id=asm.id,
            asset_id=payload.asset_id,
            cve_id=v.get("cve_id"),
            category="Dependencies",
            title=f"Vulnerable Dependency: {v.get('package')} ({v.get('installed_version')})",
            description=v.get("title"),
            severity=v.get("severity"),
            cvss_score=v.get("cvss_score", 7.0),
            risk_score=risk_score_calc(v.get("cvss_score", 7.0), v.get("severity")),
            confidence="Confirmed",
            evidence=v,
            remediation=v.get("remediation"),
            status="Open",
            assigned_to="Security Engineering",
            audit_history=[{"timestamp": datetime.now(timezone.utc).isoformat(), "analyst": "Dependency Scanner", "action": "Vulnerability Identified"}],
        )
        db.add(f)
    db.commit()
    res["assessment_id"] = asm.id

    return res

def risk_score_calc(cvss: float, severity: str) -> float:
    base = cvss * 10.0
    if severity == "Critical":
        return min(100.0, base * 0.95)
    if severity == "High":
        return min(85.0, base * 0.85)
    return min(65.0, base * 0.75)


# ──────────────────────────────────────────────
# 8. Tool 4: CVE Vulnerability Lookup
# ──────────────────────────────────────────────
@router.get("/cve/{cve_id}")
def get_cve_detail(cve_id: str):
    res = cve_lookup_service.get_cve(cve_id)
    if not res:
        raise HTTPException(status_code=404, detail=f"No CVE record found for '{cve_id}'")
    return res


@router.post("/tools/cve-lookup")
def search_cves(payload: schemas.ToolCVELookupRequest):
    results = cve_lookup_service.search_cves(payload.query)
    return {
        "success": True,
        "query": payload.query,
        "results_count": len(results),
        "results": results,
    }


# ──────────────────────────────────────────────
# 9. Tool 5: Port & Service Exposure Assessment
# ──────────────────────────────────────────────
@router.post("/tools/port-check")
def run_port_exposure_check(payload: schemas.ToolPortCheckRequest, db: Session = Depends(get_db)):
    if payload.scan_text:
        services = port_exposure_service.parse_imported_scan(payload.scan_text)
        total_open = len(services)
        crit = sum(1 for s in services if s["risk_level"] == "Critical")
        high = sum(1 for s in services if s["risk_level"] == "High")
        res = {
            "success": True,
            "asset_name": payload.asset_name,
            "ip_address": payload.ip_address,
            "is_internet_facing": payload.is_internet_facing,
            "total_open_ports": total_open,
            "critical_risks": crit,
            "high_risks": high,
            "posture": "Critical Risk - High Risk Services Exposed" if crit > 0 else "Satisfactory",
            "findings": services,
        }
    else:
        open_ports = payload.open_ports or [80, 443, 22, 6379]
        res = port_exposure_service.evaluate_asset_exposure(
            asset_name=payload.asset_name or "Authorized Asset",
            ip_address=payload.ip_address or "192.168.1.10",
            open_ports=open_ports,
            is_internet_facing=payload.is_internet_facing if payload.is_internet_facing is not None else True,
        )
        res["success"] = True

    return res


# ──────────────────────────────────────────────
# 10. Tool 6: Web Application Security Assessment
# ──────────────────────────────────────────────
@router.post("/tools/webapp-check")
def run_webapp_check(payload: schemas.ToolWebAppCheckRequest, db: Session = Depends(get_db)):
    res = webapp_scanner.assess_webapp(payload.url)
    if not res.get("success"):
        return res

    asm = models.VulnerabilityAssessment(
        assessment_id=f"ASM-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{random.randint(100, 999)}",
        title=f"Passive Web Application Audit: {payload.url}",
        tool_name="Web Application Security Assessment",
        target=payload.url,
        status="Completed",
        findings_count=res.get("total_findings", 0),
        risk_score=float(res.get("overall_risk_score", 0)),
        summary=f"Non-destructive audit identified {res.get('total_findings')} potential configuration and header weaknesses.",
        raw_results=res,
        initiated_by="SOC Analyst",
    )
    db.add(asm)
    db.commit()
    db.refresh(asm)
    res["assessment_id"] = asm.id

    return res


# ──────────────────────────────────────────────
# 11. Tool 7: Security Misconfiguration Checker
# ──────────────────────────────────────────────
@router.post("/tools/config-check")
def run_config_check(payload: schemas.ToolConfigCheckRequest, db: Session = Depends(get_db)):
    res = misconfig_checker.check_configuration(payload.config_content, filename=payload.filename or "settings.py")
    return res


# ──────────────────────────────────────────────
# 12. Tool 8: Vulnerability Risk Prioritization
# ──────────────────────────────────────────────
@router.post("/tools/risk-calculate")
def run_risk_calculation(payload: schemas.ToolRiskCalculateRequest):
    return risk_prioritizer.calculate_prioritization(
        cvss_score=payload.cvss_score,
        asset_criticality=payload.asset_criticality or "Medium",
        network_exposure=payload.network_exposure or "Internet-facing",
        exploit_available=payload.exploit_available or False,
        cisa_kev=payload.cisa_kev or False,
        confidence=payload.confidence or "Confirmed",
    )


# ──────────────────────────────────────────────
# 13. Tool 9: Remediation Management
# ──────────────────────────────────────────────
@router.post("/tools/remediate")
def execute_remediation(payload: schemas.ToolRemediateRequest, db: Session = Depends(get_db)):
    return remediation_service.transition_status(
        finding_id=payload.finding_id,
        new_status=payload.status,
        analyst_name="SOC Lead Analyst",
        notes=payload.notes or "",
        assigned_to=payload.assigned_to,
        due_date=payload.due_date,
        db=db,
    )


# ──────────────────────────────────────────────
# 14. Tool 10: Vulnerability Report Generator
# ──────────────────────────────────────────────
@router.post("/reports/generate")
def generate_vulnerability_report(payload: schemas.ToolReportGenerateRequest, db: Session = Depends(get_db)):
    findings = db.query(models.VulnerabilityFinding).all()
    findings_list = [
        {
            "id": f.id,
            "title": f.title,
            "category": f.category,
            "cve_id": f.cve_id,
            "severity": f.severity,
            "risk_score": f.risk_score,
            "remediation": f.remediation,
        }
        for f in findings
    ]

    return report_generator.generate_report(
        title=payload.title or "Vulnerability & Exposure Audit Report",
        target_name=payload.target_name or "Enterprise Infrastructure",
        assessment_type=payload.assessment_type or "Full Defensive Audit",
        findings=findings_list,
        report_type=payload.report_type or "technical",
    )


# ──────────────────────────────────────────────
# 15. Synthetic Demo Scenario Generator
# ──────────────────────────────────────────────
@router.post("/demo/generate")
def generate_demo_scenario(db: Session = Depends(get_db)):
    """Inject a comprehensive set of demonstrable VEM findings and assessment records."""
    ensure_default_sample_findings(db)
    return {
        "success": True,
        "message": "Demo vulnerability assessment scenarios and sample findings refreshed successfully.",
        "findings_count": db.query(models.VulnerabilityFinding).count(),
        "assessments_count": db.query(models.VulnerabilityAssessment).count(),
    }


# ──────────────────────────────────────────────
# 16. AI Analyst Integration
# ──────────────────────────────────────────────
@router.post("/ai/explain")
def explain_vulnerability_finding(payload: Dict[str, Any], db: Session = Depends(get_db)):
    """Generate grounded AI explanation and remediation playbook for a vulnerability finding."""
    finding_id = payload.get("finding_id")
    finding = None
    if finding_id:
        finding = db.query(models.VulnerabilityFinding).filter(models.VulnerabilityFinding.id == finding_id).first()

    title = finding.title if finding else payload.get("title", "Security Vulnerability")
    cve_id = finding.cve_id if finding else payload.get("cve_id", "N/A")
    severity = finding.severity if finding else payload.get("severity", "High")
    risk_score = finding.risk_score if finding else payload.get("risk_score", 75.0)

    analysis = (
        f"### Aegis AI Analyst Vulnerability Assessment\n\n"
        f"**Threat Entity:** {title} ({cve_id if cve_id else 'Configuration Defect'})\n"
        f"**Risk Priority:** {severity.upper()} (Risk Index: {risk_score}/100)\n\n"
        f"#### Threat Mechanics & Impact\n"
        f"This finding represents an exposed attack surface or vulnerable component. If left unmitigated, "
        f"an attacker possessing network reachability can exploit this weakness to bypass perimeter controls, "
        f"establish initial foothold, or extract protected session data.\n\n"
        f"#### Recommended Remediation Playbook\n"
        f"1. **Isolate Exposure:** Restrict network ingress to affected ports or endpoints via firewall/WAF.\n"
        f"2. **Apply Security Hotfix:** Upgrade package dependencies or deploy vendor-verified patches.\n"
        f"3. **Harden Configuration:** Enforce strict transport encryption (TLS 1.3, HSTS) and suppress banner leakage.\n"
        f"4. **Verification Re-scan:** Re-run the VEM diagnostic tool to validate that the finding is resolved before closing the ticket."
    )

    return {
        "success": True,
        "title": title,
        "cve_id": cve_id,
        "analysis": analysis,
        "suggested_soar_playbook": "patch_vulnerability",
    }
