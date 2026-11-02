import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import models, schemas
from app.vulnerability import (
    validate_target_url,
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
from app.api.routers.vulnerabilities import (
    get_vulnerability_dashboard,
    get_vulnerability_findings,
    update_finding,
    run_header_check,
    run_dependency_check,
    run_risk_calculation,
    execute_remediation,
    generate_vulnerability_report,
)

@pytest.fixture
def db_session():
    """Create an isolated in-memory SQLite database for test execution."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

# ──────────────────────────────────────────────
# Tool 1: Website Security Header Checker Tests
# ──────────────────────────────────────────────
def test_tool_header_checker():
    # Test safe synthetic/localhost target
    res = header_checker.check_url("https://localhost:8000/demo")
    assert res["success"] is True
    assert "grade" in res
    assert "score" in res
    assert len(res["findings"]) > 0
    # Strict-Transport-Security should be evaluated
    hsts = [f for f in res["findings"] if f["header"] == "Strict-Transport-Security"]
    assert len(hsts) == 1

def test_header_checker_invalid_url():
    res = header_checker.check_url("ftp://not-allowed.local")
    assert res["success"] is False
    assert "Scheme" in res["error"] or "not allowed" in res["error"]

# ──────────────────────────────────────────────
# Tool 2: SSL/TLS Certificate Checker Tests
# ──────────────────────────────────────────────
def test_tool_cert_checker_demo():
    res = cert_checker.check_certificate("demo.example.com", port=443)
    assert res["success"] is True
    assert res["status"] in ("Valid", "Expiring Soon", "Expired")
    assert "days_remaining" in res
    assert res["tls_version"] == "TLSv1.3"
    assert len(res["sans"]) >= 1

# ──────────────────────────────────────────────
# Tool 3: Dependency Vulnerability Scanner Tests
# ──────────────────────────────────────────────
def test_tool_dependency_scanner_python():
    sample_requirements = """
    requests==2.28.1
    urllib3==1.26.15
    flask==2.0.1
    numpy==1.24.0
    """
    res = dependency_scanner.scan_manifest(sample_requirements, "requirements.txt")
    assert res["success"] is True
    assert res["total_dependencies"] == 4
    assert res["vulnerabilities_count"] >= 3
    # Check for requests CVE
    req_vuln = [v for v in res["vulnerabilities"] if v["package"] == "requests"]
    assert len(req_vuln) >= 1
    assert req_vuln[0]["cve_id"] == "CVE-2023-32681"

def test_tool_dependency_scanner_npm():
    sample_package_json = """
    {
      "name": "enterprise-web",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "4.17.15",
        "axios": "1.4.0",
        "react": "18.2.0"
      }
    }
    """
    res = dependency_scanner.scan_manifest(sample_package_json, "package.json")
    assert res["success"] is True
    assert res["total_dependencies"] == 3
    lodash_vuln = [v for v in res["vulnerabilities"] if v["package"] == "lodash"]
    assert len(lodash_vuln) >= 1
    assert lodash_vuln[0]["cve_id"] == "CVE-2021-23337"

# ──────────────────────────────────────────────
# Tool 4: CVE Vulnerability Lookup Tests
# ──────────────────────────────────────────────
def test_tool_cve_lookup():
    res = cve_lookup_service.get_cve("CVE-2021-44228")
    assert res is not None
    assert "Log4j" in res["title"] or "Log4j" in res["description"]
    assert res["cvss_score"] == 10.0
    assert res["severity"] == "Critical"
    assert res["cisa_kev"] is True

def test_tool_cve_search():
    results = cve_lookup_service.search_cves("OpenSSL")
    assert len(results) >= 1
    assert any("OpenSSL" in r["title"] or "OpenSSL" in r["description"] for r in results)

# ──────────────────────────────────────────────
# Tool 5: Port & Exposure Assessment Tests
# ──────────────────────────────────────────────
def test_tool_port_exposure_evaluation():
    # Asset with critical exposed ports: 6379 (Redis), 22 (SSH), 443 (HTTPS)
    res = port_exposure_service.evaluate_asset_exposure(
        asset_name="Production Gateway",
        ip_address="203.0.113.10",
        open_ports=[22, 443, 6379],
        is_internet_facing=True
    )
    assert res["total_open_ports"] == 3
    assert res["critical_risks"] >= 1  # Redis on internet
    assert "High Risk" in res["posture"]

def test_tool_port_scan_parsing():
    nmap_sample = """
    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 8.9p1
    80/tcp   open  http    nginx 1.18.0
    3306/tcp open  mysql   MySQL 8.0.32
    """
    services = port_exposure_service.parse_imported_scan(nmap_sample)
    assert len(services) == 3
    mysql = [s for s in services if s["port"] == 3306][0]
    assert mysql["risk_level"] == "High"

# ──────────────────────────────────────────────
# Tool 6: Web Application Security Assessment Tests
# ──────────────────────────────────────────────
def test_tool_webapp_scanner():
    res = webapp_scanner.assess_webapp("https://localhost:8000/demo")
    assert res["success"] is True
    assert "overall_risk_score" in res
    assert isinstance(res["findings"], list)

# ──────────────────────────────────────────────
# Tool 7: Security Misconfiguration Checker Tests
# ──────────────────────────────────────────────
def test_tool_misconfig_checker_and_redaction():
    insecure_settings = """
    DEBUG = True
    ALLOWED_HOSTS = ['*']
    SECRET_KEY = "django-insecure-supersecretkey123456789"
    CORS_ALLOW_ALL_ORIGINS = True
    """
    res = misconfig_checker.check_configuration(insecure_settings, "settings.py")
    assert res["success"] is True
    assert res["severity_counts"]["Critical"] >= 1  # DEBUG = True and secret
    # Ensure raw secret is redacted in output
    assert "supersecretkey123456789" not in res["redacted_preview"]
    assert "REDACTED" in res["redacted_preview"]

# ──────────────────────────────────────────────
# Tool 8: Vulnerability Risk Prioritization Tests
# ──────────────────────────────────────────────
def test_tool_risk_prioritization():
    res = risk_prioritizer.calculate_prioritization(
        cvss_score=9.8,
        asset_criticality="Critical",
        network_exposure="Internet-facing",
        exploit_available=True,
        cisa_kev=True,
        confidence="Confirmed"
    )
    assert res["risk_score"] >= 90.0
    assert "P1" in res["priority"]
    assert len(res["factors"]) == 5

# ──────────────────────────────────────────────
# Tool 9: Remediation Management Tests
# ──────────────────────────────────────────────
def test_tool_remediation_transition(db_session):
    # Create test finding
    finding = models.VulnerabilityFinding(
        finding_id="VULN-TEST-001",
        category="Dependencies",
        title="Test Insecure Dependency",
        severity="High",
        cvss_score=7.5,
        risk_score=70.0,
        confidence="Confirmed",
        status="Open",
        remediation="Upgrade package to 2.0.0"
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)

    # 1. Update to In Progress
    res = remediation_service.transition_status(
        finding_id=finding.id,
        new_status="In Progress",
        analyst_name="DevOps Lead",
        notes="PR created",
        db=db_session
    )
    assert res["success"] is True
    assert res["status"] == "In Progress"

    # 2. Attempt to mark Verified without confirmation notes -> should fail
    res_fail = remediation_service.transition_status(
        finding_id=finding.id,
        new_status="Verified",
        analyst_name="QA Auditor",
        notes="",  # Empty verification notes
        db=db_session
    )
    assert res_fail["success"] is False
    assert "Verification requires confirmation notes" in res_fail["error"]

    # 3. Mark Verified with proper audit notes -> should succeed
    res_ok = remediation_service.transition_status(
        finding_id=finding.id,
        new_status="Verified",
        analyst_name="QA Auditor",
        notes="Re-scan confirmed package upgraded to 2.0.0 cleanly.",
        db=db_session
    )
    assert res_ok["success"] is True
    assert res_ok["status"] == "Verified"

# ──────────────────────────────────────────────
# Tool 10: Vulnerability Report Generator Tests
# ──────────────────────────────────────────────
def test_tool_report_generator():
    findings = [
        {"title": "Log4Shell RCE", "cve_id": "CVE-2021-44228", "severity": "Critical", "risk_score": 98.0, "remediation": "Patch Log4j"},
        {"title": "Missing HSTS", "category": "Security Headers", "severity": "High", "risk_score": 70.0, "remediation": "Add HSTS header"}
    ]
    report = report_generator.generate_report(
        title="Q4 Infrastructure Security Assessment",
        target_name="Production API Cluster",
        assessment_type="Comprehensive VEM Audit",
        findings=findings,
        report_type="technical"
    )
    assert report["success"] is True
    assert report["statistics"]["total"] == 2
    assert report["statistics"]["critical"] == 1
    assert "html_report" in report
    assert "Log4Shell RCE" in report["html_report"]
    assert "Assessment Scope & Legal Limitations" in report["html_report"]

# ──────────────────────────────────────────────
# FastAPI Endpoints Integration Tests
# ──────────────────────────────────────────────
def test_vem_api_dashboard_and_findings(db_session):
    dashboard = get_vulnerability_dashboard(db=db_session)
    assert dashboard.total_vulnerabilities >= 1
    assert dashboard.critical_count >= 1

    findings = get_vulnerability_findings(db=db_session)
    assert len(findings) >= 1

    # Test running header check endpoint
    payload = schemas.ToolHeaderCheckRequest(url="https://localhost:8000/demo")
    chk = run_header_check(payload=payload, db=db_session)
    assert chk["success"] is True

    # Test report generation endpoint
    rep_payload = schemas.ToolReportGenerateRequest(title="Executive Audit")
    rep = generate_vulnerability_report(payload=rep_payload, db=db_session)
    assert rep["success"] is True

