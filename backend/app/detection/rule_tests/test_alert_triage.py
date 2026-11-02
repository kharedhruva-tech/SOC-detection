"""
Automated Test Suite for Advanced Live SIEM Alert Triage.
Tests deduplication, multi-stage correlation, threat intelligence enrichment,
intelligent risk scoring, attack timeline, evidence-grounded AI analysis,
analyst workflows, and SOAR execution.
"""
import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, ensure_schema_compatibility
from app.models.models import SecurityAlert, SecurityEvent, Incident
from app.detection.event_normalizer import StandardizedEvent
from app.detection.rules import DetectionMatch
from app.detection.triage_service import alert_triage_service
from app.detection.threat_intel import threat_intel_service
from app.detection.risk_scorer import risk_scorer


@pytest.fixture(scope="module")
def triage_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSession()
    yield session
    session.close()


def test_threat_intel_classification(triage_db):
    """Verifies that internal, suspicious, unknown, and confirmed malicious indicators are distinguished."""
    # 1. Internal IP -> Clean
    res_clean = threat_intel_service.enrich_indicator("192.168.1.50", "IP", triage_db)
    assert res_clean["reputation"] == "Clean"
    assert res_clean["score"] <= 10

    # 2. Known Malicious IP -> Confirmed Malicious
    res_mal = threat_intel_service.enrich_indicator("185.220.101.4", "IP", triage_db)
    assert res_mal["reputation"] == "Confirmed Malicious"
    assert res_mal["score"] >= 90
    assert "APT" in res_mal["threat_actor"] or "Tor" in res_mal["category"]

    # 3. Known Malware Hash -> Confirmed Malicious
    res_hash = threat_intel_service.enrich_indicator(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "Hash",
        triage_db
    )
    assert res_hash["reputation"] == "Confirmed Malicious"
    assert "WannaCry" in res_hash["category"]

    # 4. Unclassified External IP -> Unknown (not treated as malicious)
    res_unk = threat_intel_service.enrich_indicator("151.101.1.69", "IP", triage_db)
    assert res_unk["reputation"] == "Unknown"
    assert res_unk["score"] <= 30


def test_intelligent_risk_scoring():
    """Verifies 0-100 risk score calculation and contributing factor breakdown."""
    # Critical rule + malicious IP + high asset
    ti_mal = {"reputation": "Confirmed Malicious", "score": 95}
    score, priority, factors, expl = risk_scorer.calculate(
        severity="Critical",
        occurrence_count=3,
        threat_intel=ti_mal,
        asset_criticality="Critical",
        is_correlated=True
    )
    # Severity(35) + Asset(25) + ThreatIntel(25) + Frequency(6) + Correlation(10) = 100 max
    assert score >= 90.0
    assert priority == "P1"
    assert len(factors) == 5
    assert "100" in expl

    # Low severity + Clean internal IP
    ti_clean = {"reputation": "Clean", "score": 5}
    score_low, priority_low, factors_low, _ = risk_scorer.calculate(
        severity="Low",
        occurrence_count=1,
        threat_intel=ti_clean,
        asset_criticality="Low",
        is_correlated=False
    )
    # Severity(5) + Asset(5) + ThreatIntel(0) + Frequency(0) + Correlation(0) = 10
    assert score_low <= 25.0
    assert priority_low == "P4"


def test_alert_ingestion_and_deduplication(triage_db):
    """Verifies alert ingestion and subsequent deduplication with frequency increment."""
    now = datetime.utcnow()
    event_1 = StandardizedEvent(
        event_id="EVT-DEDUP-001",
        event_type="failed_login",
        timestamp=now,
        source_ip="185.220.101.4",
        username="target_admin",
        details={"reason": "bad_password"}
    )
    match_1 = DetectionMatch(
        rule_id="BR-001",
        rule_name="Brute Force Detection",
        severity="High",
        category="Credential Access",
        alert_title="Possible Brute Force Attempt",
        description="Repeated failed authentications observed.",
        entity_key="185.220.101.4:target_admin",
        evidence={"failed_count": 5},
        matched_event_ids=["EVT-DEDUP-001"]
    )

    # 1. Ingest initial alert
    alert = alert_triage_service.ingest_match(triage_db, match_1, event_1)
    assert alert.id is not None
    assert alert.occurrence_count == 1
    assert alert.is_duplicate is False
    assert alert.threat_intel.get("reputation") == "Confirmed Malicious"
    assert alert.risk_score >= 60.0

    initial_id = alert.alert_id

    # 2. Ingest duplicate event within 5-minute window
    event_2 = StandardizedEvent(
        event_id="EVT-DEDUP-002",
        event_type="failed_login",
        timestamp=datetime.utcnow(),
        source_ip="185.220.101.4",
        username="target_admin",
        details={"reason": "bad_password"}
    )
    match_2 = DetectionMatch(
        rule_id="BR-001",
        rule_name="Brute Force Detection",
        severity="High",
        category="Credential Access",
        alert_title="Possible Brute Force Attempt",
        description="Repeated failed authentications observed.",
        entity_key="185.220.101.4:target_admin",
        evidence={"failed_count": 10},
        matched_event_ids=["EVT-DEDUP-002"]
    )

    deduped_alert = alert_triage_service.ingest_match(triage_db, match_2, event_2)

    # Verify same alert record updated, not duplicated
    assert deduped_alert.alert_id == initial_id
    assert deduped_alert.occurrence_count == 2
    assert deduped_alert.is_duplicate is True
    assert "EVT-DEDUP-001" in deduped_alert.matched_event_ids
    assert "EVT-DEDUP-002" in deduped_alert.matched_event_ids
    assert any("Deduplicated" in entry["action"] for entry in deduped_alert.audit_trail)


def test_multi_stage_correlation_and_incident_grouping(triage_db):
    """Verifies that related alerts for the same source entity are correlated into an Incident."""
    now = datetime.utcnow()
    # Ingest privilege escalation alert from the same source IP
    event_pe = StandardizedEvent(
        event_id="EVT-CORR-003",
        event_type="role_assigned",
        timestamp=now,
        source_ip="185.220.101.4",
        username="target_admin",
        details={"assigned_role": "Domain Admins"}
    )
    match_pe = DetectionMatch(
        rule_id="PE-005",
        rule_name="Privilege Escalation Detection",
        severity="Critical",
        category="Privilege Escalation",
        alert_title="Possible Privilege Escalation",
        description="Standard account unexpectedly elevated.",
        entity_key="target_admin",
        evidence={"assigned_role": "Domain Admins"},
        matched_event_ids=["EVT-CORR-003"]
    )

    alert_pe = alert_triage_service.ingest_match(triage_db, match_pe, event_pe)

    # Must be correlated with previous alert
    assert alert_pe.correlation_id is not None
    assert "CORR" in alert_pe.correlation_id
    assert alert_pe.incident_id is not None

    # Check that the incident exists in Incident table
    inc = triage_db.query(Incident).filter(Incident.id == alert_pe.incident_id).first()
    assert inc is not None
    assert "Multi-Stage" in inc.title


def test_analyst_workflow_and_audit_trail(triage_db):
    """Verifies status changes, priority adjustments, analyst assignment, and note logging."""
    alert = triage_db.query(SecurityAlert).first()
    assert alert is not None

    # 1. Update status to Investigating and assign
    updated = alert_triage_service.update_alert_status(
        db=triage_db,
        alert_identifier=alert.alert_id,
        status="Investigating",
        assigned_to="SecOps Commander",
        priority="P1",
        note="Initial triage started: Verified attacker IP in firewall logs.",
        actor="Tier 3 Lead"
    )

    assert updated.status == "Investigating"
    assert updated.assigned_to == "SecOps Commander"
    assert updated.priority == "P1"
    assert len(updated.notes) >= 1
    assert updated.notes[0]["author"] == "Tier 3 Lead"

    # Verify audit trail entries
    actions = [e["action"] for e in updated.audit_trail]
    assert any("Status changed" in a for a in actions)
    assert any("Assigned to" in a for a in actions)
    assert any("Investigation Note Added" in a for a in actions)


def test_attack_timeline_generation(triage_db):
    """Verifies chronological attack timeline assembly."""
    alert = triage_db.query(SecurityAlert).first()
    timeline = alert_triage_service.get_attack_timeline(triage_db, alert.alert_id)

    assert isinstance(timeline, list)
    assert len(timeline) >= 2
    stages = [item["stage"] for item in timeline]
    assert "detection" in stages
    assert "enrichment" in stages


def test_ai_analysis_evidence_grounding(triage_db):
    """Verifies that AI analysis returns factual evidence, impact, steps, and explicit limitations."""
    alert = triage_db.query(SecurityAlert).first()
    ai_res = alert_triage_service.generate_ai_analysis(triage_db, alert.alert_id)

    assert ai_res["alert_id"] == alert.alert_id
    assert "BR-001" in ai_res["alert_summary"] or "PE-005" in ai_res["alert_summary"]
    assert "supporting_evidence" in ai_res
    assert len(ai_res["suggested_investigation_steps"]) >= 3
    assert ai_res["confidence_score"] >= 80.0
    assert "grounded" in ai_res["limitations"].lower()


def test_soar_remediation_execution(triage_db):
    """Verifies SOAR remediation action execution and audit trail logging."""
    alert = triage_db.query(SecurityAlert).first()
    res = alert_triage_service.execute_soar_remediation(
        db=triage_db,
        alert_identifier=alert.alert_id,
        action="block_ip",
        parameters={"ip": alert.source_ip},
        actor="SecOps Commander"
    )

    assert res["status"] == "success"
    assert "Perimeter Firewall" in res["title"]
    assert alert.source_ip in res["message"]

    # Verify that the alert's audit trail has the SOAR execution recorded
    triage_db.refresh(alert)
    actions = [e["action"] for e in alert.audit_trail]
    assert any("SOAR Action Executed" in a for a in actions)

