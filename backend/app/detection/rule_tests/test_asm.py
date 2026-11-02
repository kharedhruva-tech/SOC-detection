import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import models, schemas
from app.asm import (
    dns_assessment_service,
    cert_monitor,
    service_analyzer,
    change_engine,
    asm_risk_scorer,
)
from app.api.routers.asm import (
    get_asm_dashboard,
    get_assets,
    register_asset,
    get_domains,
    get_certificates,
    get_services,
    get_change_logs,
)

@pytest.fixture
def db_session():
    """Create an isolated in-memory SQLite database for ASM test execution."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

# ──────────────────────────────────────────────
# 1. DNS Assessment Tests
# ──────────────────────────────────────────────
def test_asm_dns_assessment():
    res = dns_assessment_service.assess_domain("enterprise-defense.org")
    assert res["success"] is True
    assert "dns_score" in res
    assert "records" in res
    assert "A" in res["records"]
    assert "spf" in res
    assert "dmarc" in res
    assert len(res["checks_performed"]) >= 5

# ──────────────────────────────────────────────
# 2. Certificate Monitoring Tests
# ──────────────────────────────────────────────
def test_asm_cert_monitoring_windows():
    # Test 7-day critical window
    res_7d = cert_monitor.inspect_certificate("demo-expiring-7d.example.com")
    assert res_7d["success"] is True
    assert res_7d["status"] == "Critical Expiring (7d)"
    assert res_7d["urgency_level"] == "Critical"
    assert res_7d["days_remaining"] <= 7

    # Test valid cert
    res_valid = cert_monitor.inspect_certificate("demo.example.com")
    assert res_valid["success"] is True
    assert res_valid["status"] == "Valid"
    assert res_valid["days_remaining"] > 30

# ──────────────────────────────────────────────
# 3. Service Exposure Analyzer Tests
# ──────────────────────────────────────────────
def test_asm_service_exposure_comparison():
    # Port 443 is approved baseline
    res_approved = service_analyzer.evaluate_service_exposure(
        port=443,
        approved_baseline_ports=[80, 443]
    )
    assert res_approved["is_approved_baseline"] is True
    assert res_approved["exposure_status"] == "Approved Baseline"
    assert res_approved["risk_level"] == "Low"

    # Port 6379 (Redis) is unexpected
    res_unexpected = service_analyzer.evaluate_service_exposure(
        port=6379,
        approved_baseline_ports=[80, 443]
    )
    assert res_unexpected["is_approved_baseline"] is False
    assert res_unexpected["exposure_status"] == "Unexpected Exposure"
    assert res_unexpected["risk_level"] == "Critical"

# ──────────────────────────────────────────────
# 4. Attack Surface Change Engine Tests
# ──────────────────────────────────────────────
def test_asm_change_engine_recording(db_session):
    record = change_engine.record_change(
        asset_id="ASM-TEST-01",
        asset_name="Test Ingress",
        change_type="New Exposed Service Detected",
        previous_value="Port 443 only",
        current_value="Port 22 exposed",
        severity="High",
        description="SSH port exposed publicly outside baseline.",
        db=db_session
    )
    assert record["asset_id"] == "ASM-TEST-01"
    assert record["severity"] == "High"

    # Verify query in DB
    logs = db_session.query(models.ASMChangeLog).filter(models.ASMChangeLog.asset_id == "ASM-TEST-01").all()
    assert len(logs) == 1
    assert logs[0].reviewed is False

# ──────────────────────────────────────────────
# 5. Risk Scoring Model Tests
# ──────────────────────────────────────────────
def test_asm_risk_scoring():
    res = asm_risk_scorer.calculate_asset_risk(
        criticality="Critical",
        exposure_level="Public Internet",
        cert_days_remaining=5,  # <=7d
        has_dns_issues=True,
        unexpected_services_count=2
    )
    assert res["risk_score"] >= 75.0
    assert "P1" in res["tier"] or "Critical" in res["posture"]
    assert len(res["factors"]) == 4

# ──────────────────────────────────────────────
# 6. FastAPI Router Endpoints Tests
# ──────────────────────────────────────────────
def test_asm_api_endpoints(db_session):
    # 1. Dashboard
    dash = get_asm_dashboard(db=db_session)
    assert dash.total_assets >= 1
    assert dash.total_domains >= 1
    assert dash.total_certificates >= 1

    # 2. Assets list
    assets = get_assets(db=db_session)
    assert len(assets) >= 1

    # 3. Register asset
    new_asset = register_asset(
        asset_data=schemas.ASMAssetCreate(
            name="New Edge Node",
            asset_type="Server",
            domain_name="edge.corp.net",
            ip_address="198.51.100.99",
            criticality="High",
            exposure_level="Public Internet"
        ),
        db=db_session
    )
    assert new_asset.name == "New Edge Node"

    # 4. Domains list
    domains = get_domains(db=db_session)
    assert len(domains) >= 1

    # 5. Certificates list
    certs = get_certificates(db=db_session)
    assert len(certs) >= 1

    # 6. Services list
    services = get_services(db=db_session)
    assert len(services) >= 1

    # 7. Changes list
    changes = get_change_logs(db=db_session)
    assert len(changes) >= 1

