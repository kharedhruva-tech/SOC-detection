import random
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models import models, schemas
from app.asm import (
    dns_assessment_service,
    cert_monitor,
    service_analyzer,
    change_engine,
    asm_risk_scorer,
)

router = APIRouter()

# ──────────────────────────────────────────────
# Helper: Seed default sample ASM data if empty
# ──────────────────────────────────────────────
def ensure_default_asm_data(db: Session):
    existing = db.query(models.ASMAsset).first()
    if existing:
        return

    now = datetime.now(timezone.utc)

    # 1. Seed Assets
    sample_assets = [
        {
            "asset_id": "ASM-AST-101",
            "name": "Production Customer API Gateway",
            "asset_type": "API",
            "domain_name": "api.enterprise-defense.org",
            "ip_address": "198.51.100.24",
            "environment": "Production",
            "owner": "Cloud Core Team",
            "business_unit": "Digital Platforms",
            "criticality": "Critical",
            "authorization_status": "Authorized",
            "discovery_source": "Approved Inventory Import",
            "exposure_level": "Public Internet",
            "risk_score": 78.5,
            "status": "Active",
            "first_seen": now - timedelta(days=120),
            "last_seen": now,
            "metadata_info": {"cloud_provider": "AWS", "region": "us-east-1", "ingress": "ALB"},
        },
        {
            "asset_id": "ASM-AST-102",
            "name": "Corporate VPN Concentrator",
            "asset_type": "Network Device",
            "domain_name": "vpn.corp-secure.net",
            "ip_address": "198.51.100.8",
            "environment": "Production",
            "owner": "NetSec Operations",
            "business_unit": "Infrastructure",
            "criticality": "Critical",
            "authorization_status": "Authorized",
            "discovery_source": "Manual",
            "exposure_level": "Public Internet",
            "risk_score": 65.0,
            "status": "Active",
            "first_seen": now - timedelta(days=90),
            "last_seen": now,
            "metadata_info": {"vendor": "Palo Alto Networks", "protocol": "GlobalProtect"},
        },
        {
            "asset_id": "ASM-AST-103",
            "name": "Auth & SSO Identity Portal",
            "asset_type": "Web Application",
            "domain_name": "auth.saas-app.io",
            "ip_address": "198.51.100.42",
            "environment": "Production",
            "owner": "IAM Security Team",
            "business_unit": "Corporate IT",
            "criticality": "Critical",
            "authorization_status": "Authorized",
            "discovery_source": "Cloud Sync",
            "exposure_level": "Public Internet",
            "risk_score": 82.0,
            "status": "Active",
            "first_seen": now - timedelta(days=60),
            "last_seen": now,
            "metadata_info": {"framework": "Next.js / OAuth2", "waf_active": True},
        },
        {
            "asset_id": "ASM-AST-104",
            "name": "Kubernetes Ingress Controller",
            "asset_type": "Cloud Asset",
            "domain_name": "k8s-ingress.cloud-prod.com",
            "ip_address": "198.51.100.99",
            "environment": "Production",
            "owner": "SRE Team",
            "business_unit": "Platform Engineering",
            "criticality": "High",
            "authorization_status": "Authorized",
            "discovery_source": "Approved Inventory Import",
            "exposure_level": "DMZ",
            "risk_score": 52.0,
            "status": "Active",
            "first_seen": now - timedelta(days=45),
            "last_seen": now,
            "metadata_info": {"orchestrator": "EKS 1.28", "nodes": 12},
        },
        {
            "asset_id": "ASM-AST-105",
            "name": "Staging Customer Portal",
            "asset_type": "Web Application",
            "domain_name": "portal.staging-env.dev",
            "ip_address": "198.51.100.150",
            "environment": "Staging",
            "owner": "AppSec Dev Team",
            "business_unit": "Product Engineering",
            "criticality": "Medium",
            "authorization_status": "Authorized",
            "discovery_source": "Manual",
            "exposure_level": "Public Internet",
            "risk_score": 71.0,
            "status": "Active",
            "first_seen": now - timedelta(days=30),
            "last_seen": now,
            "metadata_info": {"framework": "React / Django", "ip_allowlist": False},
        },
    ]

    for a in sample_assets:
        db.add(models.ASMAsset(**a))

    # 2. Seed Domains
    sample_domains = [
        {"domain_id": "DOM-001", "root_domain": "enterprise-defense.org", "subdomain": "enterprise-defense.org", "ip_addresses": ["198.51.100.24"], "cname_target": None, "dns_status": "Active", "is_apex": True, "is_active": True, "discovered_via": "Manual", "first_seen": now - timedelta(days=120), "last_seen": now, "flagged_review": False},
        {"domain_id": "DOM-002", "root_domain": "enterprise-defense.org", "subdomain": "api.enterprise-defense.org", "ip_addresses": ["198.51.100.24", "198.51.100.25"], "cname_target": "alb-api.us-east-1.elb.amazonaws.com", "dns_status": "Active", "is_apex": False, "is_active": True, "discovered_via": "Approved Inventory Import", "first_seen": now - timedelta(days=120), "last_seen": now, "flagged_review": False},
        {"domain_id": "DOM-003", "root_domain": "corp-secure.net", "subdomain": "vpn.corp-secure.net", "ip_addresses": ["198.51.100.8"], "cname_target": None, "dns_status": "Active", "is_apex": False, "is_active": True, "discovered_via": "Manual", "first_seen": now - timedelta(days=90), "last_seen": now, "flagged_review": False},
        {"domain_id": "DOM-004", "root_domain": "saas-app.io", "subdomain": "auth.saas-app.io", "ip_addresses": ["198.51.100.42"], "cname_target": "cname.cloudflare.net", "dns_status": "Active", "is_apex": False, "is_active": True, "discovered_via": "Cloud Sync", "first_seen": now - timedelta(days=60), "last_seen": now, "flagged_review": False},
        {"domain_id": "DOM-005", "root_domain": "staging-env.dev", "subdomain": "portal.staging-env.dev", "ip_addresses": ["198.51.100.150"], "cname_target": None, "dns_status": "Active", "is_apex": False, "is_active": True, "discovered_via": "Manual", "first_seen": now - timedelta(days=30), "last_seen": now, "flagged_review": True},
    ]

    for d in sample_domains:
        db.add(models.ASMDomain(**d))

    # 3. Seed Certificates
    sample_certs = [
        {"cert_id": "CRT-001", "domain_name": "api.enterprise-defense.org", "port": 443, "issuer": "Amazon RSA 2048 M02", "subject_cn": "api.enterprise-defense.org", "sans": ["api.enterprise-defense.org", "*.enterprise-defense.org"], "valid_from": (now - timedelta(days=300)).isoformat(), "valid_to": (now + timedelta(days=6)).isoformat(), "days_remaining": 6, "status": "Critical Expiring (7d)", "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", "chain_status": "Trusted", "last_checked": now},
        {"cert_id": "CRT-002", "domain_name": "vpn.corp-secure.net", "port": 443, "issuer": "DigiCert TLS RSA SHA256 2020 CA1", "subject_cn": "vpn.corp-secure.net", "sans": ["vpn.corp-secure.net"], "valid_from": (now - timedelta(days=350)).isoformat(), "valid_to": (now + timedelta(days=14)).isoformat(), "days_remaining": 14, "status": "Expiring Soon (15d)", "tls_version": "TLSv1.2", "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384", "chain_status": "Trusted", "last_checked": now},
        {"cert_id": "CRT-003", "domain_name": "auth.saas-app.io", "port": 443, "issuer": "Let's Encrypt Authority X3", "subject_cn": "auth.saas-app.io", "sans": ["auth.saas-app.io"], "valid_from": (now - timedelta(days=65)).isoformat(), "valid_to": (now + timedelta(days=25)).isoformat(), "days_remaining": 25, "status": "Expiring Soon (30d)", "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256", "chain_status": "Trusted", "last_checked": now},
        {"cert_id": "CRT-004", "domain_name": "k8s-ingress.cloud-prod.com", "port": 443, "issuer": "Google Trust Services LLC", "subject_cn": "k8s-ingress.cloud-prod.com", "sans": ["k8s-ingress.cloud-prod.com"], "valid_from": (now - timedelta(days=10)).isoformat(), "valid_to": (now + timedelta(days=80)).isoformat(), "days_remaining": 80, "status": "Valid", "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", "chain_status": "Trusted", "last_checked": now},
    ]

    for c in sample_certs:
        db.add(models.ASMCertificate(**c))

    # 4. Seed Exposed Services
    sample_services = [
        {"service_id": "SRV-001", "asset_id": "ASM-AST-101", "hostname": "api.enterprise-defense.org", "ip_address": "198.51.100.24", "port": 443, "protocol": "TCP", "service_name": "HTTPS", "version": "nginx/1.24", "is_approved_baseline": True, "exposure_status": "Approved Baseline", "risk_level": "Low", "last_assessed": now},
        {"service_id": "SRV-002", "asset_id": "ASM-AST-101", "hostname": "api.enterprise-defense.org", "ip_address": "198.51.100.24", "port": 80, "protocol": "TCP", "service_name": "HTTP", "version": "nginx/1.24", "is_approved_baseline": True, "exposure_status": "Approved Baseline", "risk_level": "Low", "last_assessed": now},
        {"service_id": "SRV-003", "asset_id": "ASM-AST-101", "hostname": "api.enterprise-defense.org", "ip_address": "198.51.100.24", "port": 6379, "protocol": "TCP", "service_name": "Redis In-Memory DB", "version": "Redis 7.0", "is_approved_baseline": False, "exposure_status": "Unexpected Exposure", "risk_level": "Critical", "last_assessed": now},
        {"service_id": "SRV-004", "asset_id": "ASM-AST-102", "hostname": "vpn.corp-secure.net", "ip_address": "198.51.100.8", "port": 443, "protocol": "TCP", "service_name": "SSL-VPN Gateway", "version": "PAN-OS 10.2", "is_approved_baseline": True, "exposure_status": "Approved Baseline", "risk_level": "Low", "last_assessed": now},
        {"service_id": "SRV-005", "asset_id": "ASM-AST-105", "hostname": "portal.staging-env.dev", "ip_address": "198.51.100.150", "port": 22, "protocol": "TCP", "service_name": "SSH", "version": "OpenSSH 8.9p1", "is_approved_baseline": False, "exposure_status": "Unexpected Exposure", "risk_level": "High", "last_assessed": now},
    ]

    for s in sample_services:
        db.add(models.ASMService(**s))

    # 5. Seed Change Logs
    sample_changes = [
        {"change_id": "CHG-001", "asset_id": "ASM-AST-101", "asset_name": "api.enterprise-defense.org", "change_type": "New Exposed Service Detected", "previous_value": "Port 80, 443 only", "current_value": "Port 6379 (Redis) exposed", "severity": "Critical", "description": "Unexpected open port 6379 observed on public interface outside approved baseline.", "timestamp": now - timedelta(hours=3), "reviewed": False},
        {"change_id": "CHG-002", "asset_id": "ASM-AST-101", "asset_name": "api.enterprise-defense.org", "change_type": "Certificate Expiration Alert", "previous_value": "30 days left", "current_value": "6 days left", "severity": "High", "description": "TLS certificate enters critical expiration window (<= 7 days).", "timestamp": now - timedelta(hours=8), "reviewed": False},
        {"change_id": "CHG-003", "asset_id": "ASM-AST-105", "asset_name": "portal.staging-env.dev", "change_type": "New Asset Registered", "previous_value": None, "current_value": "Staging Customer Portal", "severity": "Info", "description": "New authorized staging environment registered by AppSec Dev Team.", "timestamp": now - timedelta(days=1), "reviewed": True, "reviewed_by": "Alex Mercer (Lead Analyst)"},
        {"change_id": "CHG-004", "asset_id": "ASM-AST-104", "asset_name": "k8s-ingress.cloud-prod.com", "change_type": "Certificate Renewed", "previous_value": "Expiring in 5 days", "current_value": "Valid (80 days left)", "severity": "Low", "description": "Automated cert-manager renewal successfully deployed new certificate.", "timestamp": now - timedelta(days=2), "reviewed": True, "reviewed_by": "cert-manager bot"},
    ]

    for chg in sample_changes:
        db.add(models.ASMChangeLog(**chg))

    db.commit()


# ──────────────────────────────────────────────
# 1. ASM Dashboard Overview & Metrics
# ──────────────────────────────────────────────
@router.get("/dashboard", response_model=schemas.ASMDashboardStats)
def get_asm_dashboard(db: Session = Depends(get_db)):
    ensure_default_asm_data(db)

    assets = db.query(models.ASMAsset).all()
    domains = db.query(models.ASMDomain).all()
    certs = db.query(models.ASMCertificate).all()
    services = db.query(models.ASMService).all()
    changes = db.query(models.ASMChangeLog).all()

    total_assets = len(assets)
    total_domains = len(domains)
    total_certs = len(certs)
    total_services = len(services)

    expiring_certs = [c for c in certs if c.days_remaining <= 30]
    unexpected_services = [s for s in services if not s.is_approved_baseline or s.exposure_status != "Approved Baseline"]
    active_changes = [c for c in changes if not c.reviewed]

    avg_risk = round(sum(a.risk_score for a in assets) / max(1, total_assets), 1)

    # Asset types distribution
    types_dist: Dict[str, int] = {}
    for a in assets:
        types_dist[a.asset_type] = types_dist.get(a.asset_type, 0) + 1

    # Exposure distribution
    expo_dist: Dict[str, int] = {}
    for a in assets:
        expo_dist[a.exposure_level] = expo_dist.get(a.exposure_level, 0) + 1

    # Environment distribution
    env_dist: Dict[str, int] = {}
    for a in assets:
        env_dist[a.environment] = env_dist.get(a.environment, 0) + 1

    critical_perimeter = [a for a in assets if a.criticality in ("Critical", "High") and a.exposure_level == "Public Internet"]
    critical_perimeter.sort(key=lambda x: x.risk_score, reverse=True)

    recent_changes = db.query(models.ASMChangeLog).order_by(desc(models.ASMChangeLog.timestamp)).limit(8).all()

    return schemas.ASMDashboardStats(
        total_assets=total_assets,
        total_domains=total_domains,
        total_certificates=total_certs,
        expiring_certificates_count=len(expiring_certs),
        total_services=total_services,
        unexpected_services_count=len(unexpected_services),
        active_change_events=len(active_changes),
        average_attack_surface_risk=avg_risk,
        asset_types_distribution=types_dist,
        exposure_distribution=expo_dist,
        environment_distribution=env_dist,
        critical_perimeter_assets=critical_perimeter[:5],
        recent_changes=recent_changes,
        expiring_certificates=expiring_certs,
        unexpected_services=unexpected_services,
    )


# ──────────────────────────────────────────────
# 2. Tool 1: Asset Inventory Management
# ──────────────────────────────────────────────
@router.get("/assets", response_model=List[schemas.ASMAssetResponse])
def get_assets(
    asset_type: Optional[str] = None,
    environment: Optional[str] = None,
    criticality: Optional[str] = None,
    exposure: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    ensure_default_asm_data(db)
    query = db.query(models.ASMAsset)

    if asset_type and asset_type != "All":
        query = query.filter(models.ASMAsset.asset_type == asset_type)
    if environment and environment != "All":
        query = query.filter(models.ASMAsset.environment == environment)
    if criticality and criticality != "All":
        query = query.filter(models.ASMAsset.criticality == criticality)
    if exposure and exposure != "All":
        query = query.filter(models.ASMAsset.exposure_level == exposure)
    if search:
        search_fmt = f"%{search}%"
        query = query.filter(
            (models.ASMAsset.name.ilike(search_fmt)) |
            (models.ASMAsset.domain_name.ilike(search_fmt)) |
            (models.ASMAsset.ip_address.ilike(search_fmt)) |
            (models.ASMAsset.owner.ilike(search_fmt)) |
            (models.ASMAsset.asset_id.ilike(search_fmt))
        )

    return query.order_by(desc(models.ASMAsset.risk_score)).offset(skip).limit(limit).all()


@router.post("/assets", response_model=schemas.ASMAssetResponse)
def register_asset(asset_data: schemas.ASMAssetCreate, db: Session = Depends(get_db)):
    asset_id = f"ASM-AST-{random.randint(100, 999)}"
    now = datetime.now(timezone.utc)

    # Compute initial risk score
    risk_info = asm_risk_scorer.calculate_asset_risk(
        criticality=asset_data.criticality or "Medium",
        exposure_level=asset_data.exposure_level or "Public Internet",
        cert_days_remaining=90,
        has_dns_issues=False,
        unexpected_services_count=0,
    )

    db_asset = models.ASMAsset(
        asset_id=asset_id,
        name=asset_data.name,
        asset_type=asset_data.asset_type,
        domain_name=asset_data.domain_name,
        ip_address=asset_data.ip_address,
        environment=asset_data.environment or "Production",
        owner=asset_data.owner or "Security Operations",
        business_unit=asset_data.business_unit or "IT",
        criticality=asset_data.criticality or "Medium",
        authorization_status="Authorized",
        discovery_source=asset_data.discovery_source or "Manual",
        exposure_level=asset_data.exposure_level or "Public Internet",
        risk_score=risk_info["risk_score"],
        status="Active",
        first_seen=now,
        last_seen=now,
        metadata_info={},
    )
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)

    # Record Attack Surface Change event
    change_engine.record_change(
        asset_id=asset_id,
        asset_name=db_asset.name,
        change_type="New Asset Registered",
        previous_value=None,
        current_value=f"{db_asset.asset_type} ({db_asset.exposure_level})",
        severity="Info",
        description=f"New authorized asset '{db_asset.name}' registered in inventory.",
        db=db,
    )

    return db_asset


@router.get("/assets/{asset_id}")
def get_asset_details(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(models.ASMAsset).filter(models.ASMAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Fetch associated domains, services, certs, and changes
    domain_rec = db.query(models.ASMDomain).filter(models.ASMDomain.subdomain == asset.domain_name).first() if asset.domain_name else None
    cert_rec = db.query(models.ASMCertificate).filter(models.ASMCertificate.domain_name == asset.domain_name).first() if asset.domain_name else None
    services = db.query(models.ASMService).filter((models.ASMService.asset_id == asset.asset_id) | (models.ASMService.hostname == asset.domain_name)).all()
    changes = db.query(models.ASMChangeLog).filter(models.ASMChangeLog.asset_id == asset.asset_id).order_by(desc(models.ASMChangeLog.timestamp)).limit(10).all()

    return {
        "asset": asset,
        "domain": domain_rec,
        "certificate": cert_rec,
        "services": services,
        "changes": changes,
    }


@router.patch("/assets/{asset_id}", response_model=schemas.ASMAssetResponse)
def update_asset(asset_id: int, update_data: schemas.ASMAssetUpdate, db: Session = Depends(get_db)):
    asset = db.query(models.ASMAsset).filter(models.ASMAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    old_crit = asset.criticality
    if update_data.name:
        asset.name = update_data.name
    if update_data.criticality:
        asset.criticality = update_data.criticality
    if update_data.owner:
        asset.owner = update_data.owner
    if update_data.status:
        asset.status = update_data.status
    if update_data.authorization_status:
        asset.authorization_status = update_data.authorization_status
    if update_data.exposure_level:
        asset.exposure_level = update_data.exposure_level

    # Recalculate risk score
    risk_info = asm_risk_scorer.calculate_asset_risk(
        criticality=asset.criticality,
        exposure_level=asset.exposure_level,
    )
    asset.risk_score = risk_info["risk_score"]
    asset.last_seen = datetime.now(timezone.utc)
    db.commit()
    db.refresh(asset)

    if update_data.criticality and update_data.criticality != old_crit:
        change_engine.record_change(
            asset_id=asset.asset_id,
            asset_name=asset.name,
            change_type="Criticality Tier Changed",
            previous_value=old_crit,
            current_value=asset.criticality,
            severity="Medium",
            description=f"Criticality updated from {old_crit} to {asset.criticality}.",
            db=db,
        )

    return asset


@router.delete("/assets/{asset_id}")
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(models.ASMAsset).filter(models.ASMAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    change_engine.record_change(
        asset_id=asset.asset_id,
        asset_name=asset.name,
        change_type="Asset Decommissioned",
        previous_value="Active",
        current_value="Decommissioned / Deleted",
        severity="Low",
        description=f"Asset '{asset.name}' decommissioned from active attack surface monitoring.",
        db=db,
    )

    db.delete(asset)
    db.commit()
    return {"status": "success", "message": f"Asset {asset_id} deleted."}


# ──────────────────────────────────────────────
# 3. Tool 2: Domain and Subdomain Inventory
# ──────────────────────────────────────────────
@router.get("/domains", response_model=List[schemas.ASMDomainResponse])
def get_domains(search: Optional[str] = None, db: Session = Depends(get_db)):
    ensure_default_asm_data(db)
    query = db.query(models.ASMDomain)
    if search:
        search_fmt = f"%{search}%"
        query = query.filter(
            (models.ASMDomain.subdomain.ilike(search_fmt)) |
            (models.ASMDomain.root_domain.ilike(search_fmt))
        )
    return query.order_by(models.ASMDomain.root_domain, models.ASMDomain.subdomain).all()


@router.post("/domains", response_model=schemas.ASMDomainResponse)
def add_domain(domain_data: schemas.ASMDomainCreate, db: Session = Depends(get_db)):
    existing = db.query(models.ASMDomain).filter(models.ASMDomain.subdomain == domain_data.subdomain).first()
    if existing:
        raise HTTPException(status_code=400, detail="Domain or subdomain already cataloged")

    now = datetime.now(timezone.utc)
    dom_id = f"DOM-{random.randint(100, 999)}"
    db_dom = models.ASMDomain(
        domain_id=dom_id,
        root_domain=domain_data.root_domain,
        subdomain=domain_data.subdomain,
        ip_addresses=domain_data.ip_addresses or ["198.51.100.20"],
        cname_target=domain_data.cname_target,
        dns_status="Active",
        is_apex=domain_data.subdomain == domain_data.root_domain,
        is_active=True,
        discovered_via="Manual Registration",
        first_seen=now,
        last_seen=now,
        flagged_review=False,
    )
    db.add(db_dom)
    db.commit()
    db.refresh(db_dom)

    change_engine.record_change(
        asset_id=dom_id,
        asset_name=db_dom.subdomain,
        change_type="New Subdomain Added",
        previous_value=None,
        current_value=db_dom.subdomain,
        severity="Info",
        description=f"Verified subdomain '{db_dom.subdomain}' added to authorized catalog.",
        db=db,
    )

    return db_dom


# ──────────────────────────────────────────────
# 4. Tool 3: DNS Security Assessment
# ──────────────────────────────────────────────
@router.post("/dns/check")
def check_domain_dns(payload: schemas.ASMDNSCheckRequest):
    return dns_assessment_service.assess_domain(payload.domain, dkim_selector=payload.dkim_selector or "default")


# ──────────────────────────────────────────────
# 5. Tool 4: SSL/TLS Certificate Monitoring
# ──────────────────────────────────────────────
@router.get("/certificates", response_model=List[schemas.ASMCertificateResponse])
def get_certificates(status: Optional[str] = None, db: Session = Depends(get_db)):
    ensure_default_asm_data(db)
    query = db.query(models.ASMCertificate)
    if status and status != "All":
        query = query.filter(models.ASMCertificate.status.ilike(f"%{status}%"))
    return query.order_by(models.ASMCertificate.days_remaining).all()


@router.post("/certificates/check")
def inspect_and_refresh_certificate(payload: Dict[str, Any], db: Session = Depends(get_db)):
    host = payload.get("host")
    if not host:
        raise HTTPException(status_code=400, detail="Host is required")
    port = payload.get("port", 443)
    res = cert_monitor.inspect_certificate(host, port=port)

    # If cert exists in DB, update it
    cert_rec = db.query(models.ASMCertificate).filter(models.ASMCertificate.domain_name == host).first()
    if cert_rec and res.get("success"):
        old_days = cert_rec.days_remaining
        cert_rec.days_remaining = res.get("days_remaining", 90)
        cert_rec.status = res.get("status", "Valid")
        cert_rec.tls_version = res.get("tls_version", "TLSv1.3")
        cert_rec.cipher_suite = res.get("cipher_suite")
        cert_rec.last_checked = datetime.now(timezone.utc)
        db.commit()

        if cert_rec.days_remaining <= 7 and old_days > 7:
            change_engine.record_change(
                asset_id=cert_rec.cert_id,
                asset_name=host,
                change_type="Certificate Expiration Alert (<=7d)",
                previous_value=f"{old_days} days left",
                current_value=f"{cert_rec.days_remaining} days left",
                severity="Critical",
                description=f"TLS certificate for {host} expires in {cert_rec.days_remaining} days.",
                db=db,
            )

    return res


# ──────────────────────────────────────────────
# 6. Tool 5: Exposed Service Inventory
# ──────────────────────────────────────────────
@router.get("/services", response_model=List[schemas.ASMServiceResponse])
def get_services(unexpected_only: bool = False, db: Session = Depends(get_db)):
    ensure_default_asm_data(db)
    query = db.query(models.ASMService)
    if unexpected_only:
        query = query.filter(models.ASMService.is_approved_baseline == False)
    return query.order_by(desc(models.ASMService.risk_level)).all()


@router.patch("/services/{service_id}", response_model=schemas.ASMServiceResponse)
def update_service_exposure(service_id: int, payload: schemas.ASMServiceUpdate, db: Session = Depends(get_db)):
    srv = db.query(models.ASMService).filter(models.ASMService.id == service_id).first()
    if not srv:
        raise HTTPException(status_code=404, detail="Service not found")

    old_status = srv.exposure_status
    if payload.is_approved_baseline is not None:
        srv.is_approved_baseline = payload.is_approved_baseline
        if payload.is_approved_baseline:
            srv.exposure_status = "Approved Baseline"
            srv.risk_level = "Low"
    if payload.exposure_status:
        srv.exposure_status = payload.exposure_status

    srv.last_assessed = datetime.now(timezone.utc)
    db.commit()
    db.refresh(srv)

    change_engine.record_change(
        asset_id=srv.service_id,
        asset_name=f"{srv.hostname}:{srv.port}",
        change_type="Service Exposure Baseline Updated",
        previous_value=old_status,
        current_value=srv.exposure_status,
        severity="Medium" if srv.exposure_status == "Approved Baseline" else "High",
        description=f"Service on port {srv.port} ({srv.service_name}) marked as '{srv.exposure_status}'.",
        db=db,
    )

    return srv


# ──────────────────────────────────────────────
# 7. Tool 7: Attack Surface Change Detection
# ──────────────────────────────────────────────
@router.get("/changes", response_model=List[schemas.ASMChangeLogResponse])
def get_change_logs(reviewed: Optional[bool] = None, skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    ensure_default_asm_data(db)
    query = db.query(models.ASMChangeLog)
    if reviewed is not None:
        query = query.filter(models.ASMChangeLog.reviewed == reviewed)
    return query.order_by(desc(models.ASMChangeLog.timestamp)).offset(skip).limit(limit).all()


@router.patch("/changes/{change_id}/review")
def review_change_log(change_id: int, reviewer: str = "SOC Analyst", db: Session = Depends(get_db)):
    chg = db.query(models.ASMChangeLog).filter(models.ASMChangeLog.id == change_id).first()
    if not chg:
        raise HTTPException(status_code=404, detail="Change log entry not found")
    chg.reviewed = True
    chg.reviewed_by = reviewer
    db.commit()
    return {"status": "success", "message": f"Change log {change_id} marked as reviewed."}


# ──────────────────────────────────────────────
# 8. Synthetic Demo Telemetry Generator
# ──────────────────────────────────────────────
@router.post("/demo/generate")
def generate_demo_telemetry(db: Session = Depends(get_db)):
    ensure_default_asm_data(db)
    return {
        "success": True,
        "message": "Attack Surface Management demo assets, certificates, services, and changes synchronized successfully.",
        "assets_count": db.query(models.ASMAsset).count(),
        "domains_count": db.query(models.ASMDomain).count(),
        "certificates_count": db.query(models.ASMCertificate).count(),
        "services_count": db.query(models.ASMService).count(),
        "changes_count": db.query(models.ASMChangeLog).count(),
    }


# ──────────────────────────────────────────────
# 9. AI Analyst Threat Integration
# ──────────────────────────────────────────────
@router.post("/ai/explain")
def explain_asm_finding(payload: Dict[str, Any]):
    item_type = payload.get("type", "exposure")
    title = payload.get("title", "Attack Surface Anomaly")
    detail = payload.get("detail", "Unexpected open service or expiring certificate observed on authorized perimeter asset.")

    analysis = (
        f"### Aegis AI Analyst // Attack Surface Exposure Brief\n\n"
        f"**Subject:** {title}\n"
        f"**Category:** Perimeter Attack Surface ({item_type.upper()})\n\n"
        f"#### Threat Posture Assessment\n"
        f"{detail}\n\n"
        f"Unplanned changes to public-facing digital assets create opportunistic attack paths. External adversaries "
        f"continuously monitor Certificate Transparency logs, DNS changes, and exposed ports to identify newly exposed "
        f"admin interfaces or expired TLS credentials.\n\n"
        f"#### Recommended Remediation Playbook\n"
        f"1. **Access Control:** Restrict perimeter exposure using ingress security groups or IP allowlists.\n"
        f"2. **Certificate Life-Cycle:** If certificate expires in <=7 days, initiate emergency Let's Encrypt / ACME renewal.\n"
        f"3. **DNS Hardening:** Enforce strict SPF (`-all`) and DMARC (`p=reject`) to prevent brand spoofing.\n"
        f"4. **Baseline Synchronization:** If exposure is authorized, approve in asset baseline; otherwise decommission."
    )

    return {
        "success": True,
        "title": title,
        "analysis": analysis,
        "suggested_action": "isolate_exposure",
    }
