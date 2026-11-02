"""
SIEM Detection Engine Core.
Coordinates ingestion, event normalization, database recording, rule evaluation,
and real-time WebSocket event and alert dispatching.
"""
from typing import Dict, Any, List, Union, Optional
from sqlalchemy.orm import Session
from datetime import datetime

from app.models.models import SecurityEvent
from app.detection.event_normalizer import EventNormalizer, StandardizedEvent, EventValidationError
from app.detection.correlation import correlation_tracker
from app.detection.rule_registry import rule_registry
from app.detection.alert_manager import alert_manager
from app.ws_manager import ws_manager


class DetectionEngine:
    """Central processing engine for real-time security events."""

    def __init__(self):
        self._processed_counter = 0

    def process_event(self, db: Session, raw_event: Union[Dict[str, Any], str, StandardizedEvent]) -> Dict[str, Any]:
        """
        Ingests a security event, normalizes it, evaluates enabled rules,
        stores the event in DB, and generates alerts when matches occur.
        Broadcasts NEW_EVENT to connected WebSocket clients for live activity streams.
        """
        # 1. Normalize Event
        event: StandardizedEvent = EventNormalizer.normalize(raw_event)
        category = event.category or EventNormalizer.determine_category(event.event_type, event.details)

        # 2. Evaluate across all enabled rules first to determine detection status
        rules = rule_registry.get_all_rules()
        created_alerts = []
        matched_rules = []

        for rule in rules:
            if not rule.enabled:
                continue

            try:
                match = rule.evaluate(event, correlation_tracker)
                if match:
                    alert = alert_manager.create_alert(db, match, event)
                    created_alerts.append({
                        "alert_id": alert.alert_id,
                        "rule_id": alert.rule_id,
                        "title": alert.title,
                        "severity": alert.severity,
                        "category": alert.category,
                        "risk_score": alert.risk_score
                    })
                    matched_rules.append(rule.rule_id)
            except Exception as e:
                print(f"Error evaluating rule {rule.rule_id}: {e}")

        # 3. Determine detection status & risk score for the event
        if matched_rules:
            detection_status = "Alert Triggered"
            matched_rule_id = matched_rules[0]
            risk_score = created_alerts[0].get("risk_score", 75.0) if created_alerts else 75.0
        else:
            detection_status = "Normal"
            matched_rule_id = None
            risk_score = 15.0 if event.severity in ("high", "medium") else 5.0

        # 4. Persist to security_events table
        db_event = SecurityEvent(
            event_id=event.event_id,
            event_type=event.event_type,
            category=category,
            detection_status=detection_status,
            matched_rule_id=matched_rule_id,
            risk_score=risk_score,
            username=event.username,
            source_ip=event.source_ip,
            dest_ip=event.dest_ip,
            timestamp=event.timestamp,
            source=event.source,
            severity=event.severity,
            details=event.details,
            raw_event=event.raw_event,
            is_demo=event.is_demo,
            created_at=datetime.utcnow()
        )
        db.add(db_event)
        db.commit()
        db.refresh(db_event)

        # 5. Evaluate UEBA behavioural anomalies
        ueba_findings = []
        try:
            from app.detection.ueba.finding_manager import finding_manager
            ueba_findings = finding_manager.process_event(db, event)
            if ueba_findings and detection_status == "Normal":
                db_event.detection_status = "Under Triage"
                db.commit()
        except Exception as e:
            print(f"Notice on UEBA processing: {e}")

        # 6. Periodically prune correlation memory
        self._processed_counter += 1
        if self._processed_counter % 50 == 0:
            correlation_tracker.prune_old_records()

        # 7. Broadcast NEW_EVENT over WebSocket for Live Recent Activity Feed
        try:
            ws_payload = {
                "type": "NEW_EVENT",
                "id": db_event.id,
                "event_id": db_event.event_id,
                "event_type": db_event.event_type,
                "category": db_event.category,
                "severity": db_event.severity,
                "source_ip": db_event.source_ip,
                "username": db_event.username,
                "dest_ip": db_event.dest_ip,
                "source": db_event.source,
                "detection_status": db_event.detection_status,
                "matched_rule_id": db_event.matched_rule_id,
                "risk_score": db_event.risk_score,
                "details": db_event.details or {},
                "timestamp": db_event.timestamp.isoformat(),
                "is_demo": db_event.is_demo
            }
            ws_manager.sync_broadcast(ws_payload)
        except Exception as e:
            print(f"Notice on event broadcast: {e}")

        return {
            "status": "success",
            "event_id": event.event_id,
            "event_type": event.event_type,
            "category": category,
            "detection_status": detection_status,
            "matched_rules_count": len(matched_rules),
            "matched_rules": matched_rules,
            "alerts_created": created_alerts,
            "ueba_findings_count": len(ueba_findings),
            "ueba_findings": [f.finding_id for f in ueba_findings],
            "is_demo": event.is_demo
        }


# Global detection engine instance
detection_engine = DetectionEngine()
