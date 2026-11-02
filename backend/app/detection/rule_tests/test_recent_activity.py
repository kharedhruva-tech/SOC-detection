"""
Automated Test Suite for Live Recent Security Activity Module.
Verifies event ingestion, category assignment across all 7 SIEM categories,
detection status tagging, multi-criteria filtering, event detail extraction,
and synthetic demonstration activity generation.
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
from app.api.routers.detection import get_security_events, get_security_event_detail, generate_demo_activity


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


def test_category_assignment_all_7_siem_categories():
    """Verifies that EventNormalizer accurately categorizes heterogeneous events across all 7 supported categories."""
    categories_to_test = [
        ("login_success", {}, "Authentication"),
        ("login_failed", {}, "Authentication"),
        ("network_connection", {}, "Network Security"),
        ("firewall_drop", {}, "Network Security"),
        ("port_scan", {}, "Network Security"),
        ("process_creation", {}, "Endpoint Security"),
        ("registry_value_set", {}, "Endpoint Security"),
        ("file_modify", {}, "File Activity"),
        ("file_creation", {}, "File Activity"),
        ("role_assigned", {}, "Account Management"),
        ("user_created", {}, "Account Management"),
        ("sql_injection_attempt", {}, "Web Application Security"),
        ("xss_attempt", {}, "Web Application Security"),
        ("malware_detected", {}, "Malware Indicators"),
        ("ransomware_activity", {}, "Malware Indicators"),
    ]

    for event_type, details, expected_cat in categories_to_test:
        assigned = EventNormalizer.determine_category(event_type, details)
        assert assigned == expected_cat, f"Expected '{expected_cat}' for '{event_type}', got '{assigned}'"


def test_event_ingestion_and_detection_status(db_session):
    """Verifies event persistence in security_events and accurate detection_status assignment."""
    # 1. Normal event should have detection_status = 'Normal'
    normal_payload = {
        "event_id": "EVT-TEST-NORM-01",
        "event_type": "network_connection",
        "username": "alice",
        "source_ip": "10.0.1.50",
        "dest_ip": "10.0.1.1",
        "source": "Cisco-ASA",
        "severity": "low",
        "details": {"dest_port": 443, "protocol": "TCP"},
        "is_demo": False
    }
    res_norm = detection_engine.process_event(db_session, normal_payload)
    assert res_norm["status"] == "success"
    assert res_norm["detection_status"] == "Normal"

    stored_norm = db_session.query(models.SecurityEvent).filter_by(event_id="EVT-TEST-NORM-01").first()
    assert stored_norm is not None
    assert stored_norm.category == "Network Security"
    assert stored_norm.detection_status == "Normal"

    # 2. Malware event should trigger alert and have detection_status = 'Alert Triggered'
    malware_payload = {
        "event_id": "EVT-TEST-MALW-01",
        "event_type": "malware_detected",
        "username": "bob",
        "source_ip": "10.0.1.60",
        "source": "Defender",
        "severity": "critical",
        "details": {"threat_name": "Trojan:Win32/Emotet", "file_hash": "deadbeef1234567890abcdef"},
        "is_demo": False
    }
    res_malw = detection_engine.process_event(db_session, malware_payload)
    assert res_malw["status"] == "success"
    assert res_malw["detection_status"] == "Alert Triggered"
    assert "MD-007" in res_malw["matched_rules"]

    stored_malw = db_session.query(models.SecurityEvent).filter_by(event_id="EVT-TEST-MALW-01").first()
    assert stored_malw is not None
    assert stored_malw.category == "Malware Indicators"
    assert stored_malw.detection_status == "Alert Triggered"
    assert stored_malw.matched_rule_id == "MD-007"


def test_query_filtering_events_api(db_session):
    """Verifies query filtering across severity, category, detection_status, source_ip, and search."""
    # Seed specific events for filter testing
    events_to_seed = [
        {
            "event_id": "FILT-AUTH-01",
            "event_type": "login_failed",
            "username": "analyst_sam",
            "source_ip": "192.168.10.15",
            "source": "ActiveDirectory",
            "severity": "medium",
            "details": {"failure_reason": "Account locked"}
        },
        {
            "event_id": "FILT-FILE-02",
            "event_type": "file_modify",
            "username": "analyst_sam",
            "source_ip": "192.168.10.15",
            "source": "Sysmon",
            "severity": "low",
            "details": {"file_name": "hosts"}
        },
        {
            "event_id": "FILT-WEB-03",
            "event_type": "sql_injection_attempt",
            "username": "anonymous",
            "source_ip": "203.0.113.44",
            "source": "ModSecurity",
            "severity": "high",
            "details": {"payload": "' OR 1=1 --"}
        }
    ]
    for p in events_to_seed:
        detection_engine.process_event(db_session, p)

    # 1. Filter by category = 'File Activity'
    res_cat = get_security_events(category="File Activity", db=db_session)
    assert any(e["event_id"] == "FILT-FILE-02" for e in res_cat["items"])
    assert all(e["category"] == "File Activity" for e in res_cat["items"])

    # 2. Filter by severity = 'high'
    res_sev = get_security_events(severity="high", db=db_session)
    assert any(e["event_id"] == "FILT-WEB-03" for e in res_sev["items"])
    assert all(e["severity"].lower() == "high" for e in res_sev["items"])

    # 3. Filter by source_ip = '192.168.10.15'
    res_ip = get_security_events(source_ip="192.168.10.15", db=db_session)
    assert len(res_ip["items"]) >= 2
    assert all("192.168.10.15" in e["source_ip"] for e in res_ip["items"])

    # 4. Search keyword 'analyst_sam'
    res_search = get_security_events(search="analyst_sam", db=db_session)
    assert len(res_search["items"]) >= 2
    assert all(e["username"] == "analyst_sam" for e in res_search["items"])


def test_event_detail_and_related_events(db_session):
    """Verifies that get_security_event_detail retrieves full metadata, explanation, and related timeline events."""
    # EVT-TEST-MALW-01 was previously created
    detail = get_security_event_detail("EVT-TEST-MALW-01", db=db_session)
    assert detail["event_id"] == "EVT-TEST-MALW-01"
    assert detail["category"] == "Malware Indicators"
    assert detail["severity"] == "critical"
    assert detail["detection_status"] == "Alert Triggered"
    assert detail["matched_rule_id"] == "MD-007"
    assert detail["matched_rule"]["rule_id"] == "MD-007"
    assert "MD-007" in detail["detection_explanation"]
    assert "Trojan:Win32/Emotet" in detail["raw_event"]

    # Test related events using FILT-AUTH-01 and FILT-FILE-02 (same IP: 192.168.10.15 and user: analyst_sam)
    auth_detail = get_security_event_detail("FILT-AUTH-01", db=db_session)
    assert len(auth_detail["related_events"]) >= 1
    rel_ids = [r["event_id"] for r in auth_detail["related_events"]]
    assert "FILT-FILE-02" in rel_ids


def test_synthetic_activity_generator(db_session):
    """Verifies generate_demo_activity creates and broadcasts synthetic events across all 7 categories."""
    res = generate_demo_activity(db=db_session)
    assert res["status"] == "success"
    assert res["events_count"] == 10

    # Query the generated demo events
    demo_events = get_security_events(is_demo=True, limit=20, db=db_session)
    assert len(demo_events["items"]) >= 10

    categories_found = {e["category"] for e in demo_events["items"]}
    expected_categories = {
        "Authentication",
        "Network Security",
        "Endpoint Security",
        "File Activity",
        "Account Management",
        "Web Application Security",
        "Malware Indicators"
    }
    # All 7 categories should be represented
    for expected in expected_categories:
        assert expected in categories_found, f"Missing category {expected} in demo activity generation"
