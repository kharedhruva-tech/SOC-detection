"""
Alert Management System.
Generates, persists, deduplicates, and broadcasts security alerts resulting
from SIEM detection rule matches.
Integrates with the Advanced Alert Triage Service.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.models import SecurityAlert, Alert
from app.detection.rules import DetectionMatch
from app.detection.event_normalizer import StandardizedEvent
from app.detection.triage_service import alert_triage_service


class AlertManager:
    """Manages creation, query, triage, and WebSocket dispatch of SecurityAlerts."""

    def create_alert(self, db: Session, match: DetectionMatch, event: StandardizedEvent) -> SecurityAlert:
        """
        Creates and stores a SecurityAlert from a rule match.
        Delegates to AlertTriageService for deduplication, risk scoring, TI enrichment, and correlation.
        """
        return alert_triage_service.ingest_match(db, match, event)

    def get_alerts(self, db: Session, severity: Optional[str] = None,
                   category: Optional[str] = None, status: Optional[str] = None,
                   rule_id: Optional[str] = None, is_demo: Optional[bool] = None,
                   skip: int = 0, limit: int = 100) -> Tuple[List[SecurityAlert], int]:
        """Queries security alerts with multi-criteria filtering and pagination."""
        query = db.query(SecurityAlert)
        if severity:
            query = query.filter(SecurityAlert.severity.ilike(severity))
        if category:
            query = query.filter(SecurityAlert.category.ilike(category))
        if status:
            query = query.filter(SecurityAlert.status.ilike(status))
        if rule_id:
            query = query.filter(SecurityAlert.rule_id == rule_id.upper())
        if is_demo is not None:
            query = query.filter(SecurityAlert.is_demo == is_demo)

        total_count = query.count()
        alerts = query.order_by(desc(SecurityAlert.detection_timestamp)).offset(skip).limit(limit).all()
        return alerts, total_count

    def get_alert_by_id(self, db: Session, alert_identifier: str) -> Optional[SecurityAlert]:
        """Retrieves an alert by string alert_id (e.g. 'ALT-BR-001-XXXX') or integer id."""
        return alert_triage_service.get_alert_by_id(db, alert_identifier)

    def update_alert(self, db: Session, alert_identifier: str,
                     status: Optional[str] = None, assigned_to: Optional[str] = None,
                     priority: Optional[str] = None, note: Optional[str] = None,
                     actor: str = "SOC Analyst") -> Optional[SecurityAlert]:
        """Updates alert triage status, assignee, priority, notes, and records an audit log."""
        return alert_triage_service.update_alert_status(
            db=db,
            alert_identifier=alert_identifier,
            status=status,
            assigned_to=assigned_to,
            priority=priority,
            note=note,
            actor=actor
        )


# Global alert manager singleton
alert_manager = AlertManager()
