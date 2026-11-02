"""
Integration and API Endpoint Tests for SIEM Detection Engine.
Tests end-to-end event ingestion, database persistence, rule re-configuration,
demo event generation, and alert status updates.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import models
from app.detection.engine import detection_engine
from app.detection.rule_registry import rule_registry
from app.detection.alert_manager import alert_manager
from app.detection.demo_generator import DemoEventGenerator


@pytest.fixture(scope="module")
def db_session():
    """In-memory SQLite database fixture for isolated testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSession()

    # Seed rules
    rule_registry.seed_database(db)
    rule_registry.sync_from_database(db)

    yield db

    db.close()


def test_seed_database_loads_all_10_rules(db_session):
    rules = db_session.query(models.DetectionRule).all()
    assert len(rules) == 10
    rule_ids = {r.rule_id for r in rules}
    expected_ids = {"BR-001", "PS-002", "LF-003", "UL-004", "PE-005", "FA-006", "MD-007", "PS-008", "DE-009", "AC-010"}
    assert rule_ids == expected_ids


def test_full_detection_workflow_malware(db_session):
    """Submits a malware indicator event and verifies alert generation and DB persistence."""
    event_payload = {
        "event_id": "TEST-MALWARE-01",
        "event_type": "malware_detected",
        "username": "victim_host",
        "source_ip": "10.0.1.99",
        "source": "CrowdStrike",
        "details": {
            "threat_name": "HackTool:Win64/Mimikatz",
            "file_hash": "44d88612fea8a8f36de82e1278abb02f"
        }
    }

    result = detection_engine.process_event(db_session, event_payload)
    assert result["status"] == "success"
    assert "MD-007" in result["matched_rules"]
    assert len(result["alerts_created"]) >= 1

    alert_id = result["alerts_created"][0]["alert_id"]

    # Verify in DB
    db_alert = db_session.query(models.SecurityAlert).filter(models.SecurityAlert.alert_id == alert_id).first()
    assert db_alert is not None
    assert db_alert.rule_id == "MD-007"
    assert db_alert.severity == "Critical"
    assert db_alert.status == "New"
    assert "44d88612fea8a8f36de82e1278abb02f" in db_alert.description or "Mimikatz" in str(db_alert.evidence)

    # Test status update
    updated = alert_manager.update_alert(db_session, alert_id, status="Investigating")
    assert updated.status == "Investigating"


def test_rule_reconfiguration(db_session):
    """Tests updating rule threshold in DB and memory."""
    updated = rule_registry.update_rule(
        db_session,
        rule_id="BR-001",
        enabled=True,
        configuration={"failed_attempts_threshold": 10}
    )
    assert updated.configuration["failed_attempts_threshold"] == 10

    # In-memory rule should reflect change
    mem_rule = rule_registry.get_rule("BR-001")
    assert mem_rule.config["failed_attempts_threshold"] == 10

    # Restore default
    rule_registry.update_rule(db_session, "BR-001", configuration={"failed_attempts_threshold": 5})


def test_demo_scenario_generation_and_reset(db_session):
    """Tests synthetic scenario execution and purge."""
    res = DemoEventGenerator.run_scenario(db_session, "BR-001")
    assert res["events_generated"] == 6

    # Verify demo alerts created
    demo_alerts = db_session.query(models.SecurityAlert).filter(models.SecurityAlert.is_demo == True).all()
    assert len(demo_alerts) >= 1

    # Reset demo data
    reset_res = DemoEventGenerator.reset_demo_data(db_session)
    assert reset_res["deleted_events_count"] >= 1

    remaining_demo = db_session.query(models.SecurityAlert).filter(models.SecurityAlert.is_demo == True).count()
    assert remaining_demo == 0
