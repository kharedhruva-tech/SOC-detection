"""
Automated Test Suite for Advanced UEBA Module.
Verifies behavioural baseline establishment, rule-based and statistical anomaly detection,
explainable risk scoring, finding lifecycle management, and demo scenario simulations.
"""
import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import models
from app.detection.engine import detection_engine
from app.detection.rule_registry import rule_registry
from app.detection.event_normalizer import EventNormalizer
from app.detection.ueba.baseline_engine import baseline_engine
from app.detection.ueba.anomaly_detector import anomaly_detector
from app.detection.ueba.risk_scorer import ueba_risk_scorer
from app.detection.ueba.finding_manager import finding_manager
from app.detection.ueba.demo_scenarios import ueba_demo_service
from app.api.routers.ueba import (
    get_ueba_dashboard_stats,
    get_ueba_profiles,
    get_ueba_profile_detail,
    get_ueba_findings,
    get_ueba_finding_detail,
    update_ueba_finding_status,
    get_ueba_risk_scores,
    get_entity_activity_timeline,
    submit_analyst_feedback,
    generate_demo_scenario
)
from app.models.schemas import UEBAFindingStatusUpdate, UEBAFeedbackCreate, UEBADemoGenerateRequest


@pytest.fixture(scope="module")
def db_session():
    """Isolated in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSession()

    # Seed rules & default UEBA profiles
    rule_registry.seed_database(db)
    rule_registry.sync_from_database(db)
    baseline_engine.seed_default_sample_profiles(db)

    yield db

    db.close()


def test_baseline_creation_and_status(db_session):
    """Verifies baseline building, learning transitions, and versioning."""
    # User with 0 events -> Insufficient Data
    res_empty = baseline_engine.build_baseline_for_entity(db_session, "new_user_1", "user")
    assert res_empty["status"] == "Insufficient Data"
    assert res_empty["confidence"] < 0.5

    # Seed 7 events -> Learning status
    for i in range(7):
        evt = models.SecurityEvent(
            event_id=f"EVT-SEED-{i}",
            event_type="login_success",
            category="Authentication",
            username="new_user_1",
            source_ip="10.0.1.50",
            timestamp=datetime(2026, 11, 2, 10, 0, 0) + timedelta(days=i),
            is_demo=False
        )
        db_session.add(evt)
    db_session.commit()

    res_learning = baseline_engine.build_baseline_for_entity(db_session, "new_user_1", "user")
    assert res_learning["status"] == "Learning"
    assert res_learning["events_analyzed"] >= 7

    # Seed 15 more events (total > 20) -> Established status
    for i in range(15):
        evt = models.SecurityEvent(
            event_id=f"EVT-SEED-MORE-{i}",
            event_type="login_success",
            category="Authentication",
            username="new_user_1",
            source_ip="10.0.1.50",
            timestamp=datetime(2026, 11, 2, 10, 30, 0) + timedelta(days=i),
            is_demo=False
        )
        db_session.add(evt)
    db_session.commit()

    res_est = baseline_engine.build_baseline_for_entity(db_session, "new_user_1", "user")
    assert res_est["status"] == "Established"
    assert res_est["confidence"] >= 0.85


def test_unusual_login_time_detection(db_session):
    """Verifies that an off-hours login triggers an Unusual Login Time candidate and finding."""
    # User jsmith baseline is seeded with typical hours 9 to 17 UTC
    event_payload = {
        "event_id": "TEST-UEBA-TIME-01",
        "event_type": "login_success",
        "category": "Authentication",
        "username": "jsmith",
        "source_ip": "10.0.1.45",
        "timestamp": datetime(2026, 11, 2, 3, 22, 0).isoformat(),  # 03:22 AM UTC
        "details": {"workstation": "WKSTN-FIN-04"}
    }
    norm_event = EventNormalizer.normalize(event_payload)
    profile = db_session.query(models.UEBAProfile).filter_by(entity_id="jsmith").first()
    assert profile is not None

    candidates = anomaly_detector.evaluate_event(db_session, norm_event, profile)
    time_anomalies = [c for c in candidates if c.anomaly_type == "Unusual Login Time"]
    assert len(time_anomalies) == 1
    assert time_anomalies[0].evidence["observed_hour_utc"] == 3
    assert time_anomalies[0].severity in ("High", "Medium")


def test_statistical_data_volume_zscore(db_session):
    """Verifies that massive data transfers exceed Z-score threshold and trigger volumetric anomaly."""
    # jsmith baseline: mean = 18.5 MB, std = 4.2 MB
    # Transfer 150 MB -> Z = (150 - 18.5) / 4.2 = 31.3 > 3.0
    event_payload = {
        "event_id": "TEST-UEBA-VOL-01",
        "event_type": "network_connection",
        "category": "Network Security",
        "username": "jsmith",
        "source_ip": "10.0.1.45",
        "dest_ip": "198.51.100.99",
        "details": {"bytes_transferred": 150.0, "data_mb": 150.0}
    }
    norm_event = EventNormalizer.normalize(event_payload)
    profile = db_session.query(models.UEBAProfile).filter_by(entity_id="jsmith").first()

    candidates = anomaly_detector.evaluate_event(db_session, norm_event, profile)
    vol_anomalies = [c for c in candidates if c.anomaly_type == "Abnormal Data Access Volume"]
    assert len(vol_anomalies) == 1
    assert vol_anomalies[0].evidence["z_score"] >= 3.0
    assert vol_anomalies[0].detection_method == "Statistical Z-Score"


def test_dormant_account_reactivation(db_session):
    """Verifies that an account with dormant flag or >30 days inactivity triggers Dormant Account Activity."""
    event_payload = {
        "event_id": "TEST-UEBA-DORM-01",
        "event_type": "login_success",
        "category": "Account Management",
        "username": "sarah_hr",
        "source_ip": "10.0.1.88",
        "details": {"is_dormant": True, "days_inactive": 75}
    }
    norm_event = EventNormalizer.normalize(event_payload)
    profile = db_session.query(models.UEBAProfile).filter_by(entity_id="sarah_hr").first()

    candidates = anomaly_detector.evaluate_event(db_session, norm_event, profile)
    dorm_anomalies = [c for c in candidates if c.anomaly_type == "Dormant Account Activity"]
    assert len(dorm_anomalies) == 1
    assert dorm_anomalies[0].evidence["days_inactive"] >= 30


def test_risk_scoring_calculation():
    """Verifies 0-100 explainable risk scoring math and classifications."""
    # Critical anomaly on Critical asset
    score_crit, level_crit, factors_crit = ueba_risk_scorer.calculate_risk(
        deviation_score=90.0,
        severity="Critical",
        frequency_count=3,
        entity_criticality="Critical",
        confidence=0.95
    )
    assert score_crit >= 75.0
    assert level_crit == "Critical"
    assert len(factors_crit) == 4

    # Low deviation on low asset
    score_low, level_low, factors_low = ueba_risk_scorer.calculate_risk(
        deviation_score=20.0,
        severity="Low",
        frequency_count=1,
        entity_criticality="Low",
        confidence=0.50
    )
    assert score_low < 35.0
    assert level_low in ("Low", "Medium")


def test_finding_manager_persistence_and_deduplication(db_session):
    """Verifies that FindingManager stores UEBAFinding and suppresses duplicate findings within cooldown."""
    event_payload = {
        "event_id": "TEST-UEBA-DEDUP-01",
        "event_type": "login_success",
        "category": "Authentication",
        "username": "jsmith",
        "source_ip": "10.0.1.45",
        "timestamp": datetime(2026, 11, 2, 3, 14, 0).isoformat(),
        "details": {"workstation": "WKSTN-FIN-04"}
    }
    norm_event = EventNormalizer.normalize(event_payload)

    # 1. First event generates finding
    findings_1 = finding_manager.process_event(db_session, norm_event)
    assert len(findings_1) >= 1
    finding_id = findings_1[0].finding_id

    stored = db_session.query(models.UEBAFinding).filter_by(finding_id=finding_id).first()
    assert stored is not None
    assert stored.anomaly_type == "Unusual Login Time"

    # 2. Second event with identical anomaly for same user within cooldown should be deduplicated
    event_payload_2 = dict(event_payload)
    event_payload_2["event_id"] = "TEST-UEBA-DEDUP-02"
    norm_event_2 = EventNormalizer.normalize(event_payload_2)

    findings_2 = finding_manager.process_event(db_session, norm_event_2)
    # Should not create another new finding
    assert len(findings_2) == 0

    # But related_event_ids on original finding should now include the second event
    refreshed = db_session.query(models.UEBAFinding).filter_by(finding_id=finding_id).first()
    assert "TEST-UEBA-DEDUP-02" in refreshed.related_event_ids


def test_finding_status_update_and_feedback(db_session):
    """Verifies analyst status updates and verification feedback submission."""
    finding = db_session.query(models.UEBAFinding).first()
    assert finding is not None
    fid = finding.finding_id

    # 1. Update status to 'Investigating'
    update_req = UEBAFindingStatusUpdate(
        status="Investigating",
        assigned_to="analyst_bob",
        comments="Reviewing workstation authentication tokens."
    )
    up_res = update_ueba_finding_status(fid, update_req, db=db_session)
    assert up_res["new_status"] == "Investigating"
    assert up_res["assigned_to"] == "analyst_bob"

    # 2. Submit analyst feedback
    fb_req = UEBAFeedbackCreate(
        finding_id=fid,
        feedback_type="True Positive",
        comments="Confirmed user did not initiate 03:14 AM session."
    )
    fb_res = submit_analyst_feedback(fb_req, db=db_session)
    assert fb_res["status"] == "success"
    assert fb_res["feedback_type"] == "True Positive"


def test_demo_scenario_generation(db_session):
    """Verifies that all 5 demonstration scenarios generate safe synthetic events and findings."""
    res = ueba_demo_service.run_scenario(db_session, scenario="all")
    assert res["status"] == "success"
    assert len(res["scenarios"]) == 5

    scenario_names = {s["scenario"] for s in res["scenarios"]}
    expected_scenarios = {
        "unusual_login_time",
        "dormant_account",
        "mass_resource_access",
        "auth_velocity",
        "bulk_data_exfiltration"
    }
    assert scenario_names == expected_scenarios


def test_ueba_api_endpoints(db_session):
    """Verifies dashboard overview, profiles, findings, risk scores, and timeline APIs."""
    # 1. Dashboard stats
    dash = get_ueba_dashboard_stats(db=db_session)
    assert dash["total_monitored_users"] >= 2
    assert dash["total_monitored_entities"] >= 2
    assert "Established" in dash["baseline_status_breakdown"]

    # 2. Profiles list
    profiles = get_ueba_profiles(db=db_session)
    assert profiles["total"] >= 2
    assert len(profiles["items"]) >= 2

    # 3. Profile detail
    prof_det = get_ueba_profile_detail("jsmith", db=db_session)
    assert prof_det["entity_id"] == "jsmith"
    assert len(prof_det["baselines"]) >= 1

    # 4. Findings list
    findings = get_ueba_findings(db=db_session)
    assert findings["total"] >= 1

    # 5. Risk scores
    risk_scores = get_ueba_risk_scores(db=db_session)
    assert len(risk_scores) >= 2
    assert all("contributing_factors" in r for r in risk_scores)

    # 6. Entity timeline
    timeline = get_entity_activity_timeline("jsmith", db=db_session)
    assert len(timeline) >= 1

