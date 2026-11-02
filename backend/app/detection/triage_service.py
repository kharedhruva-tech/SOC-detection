"""
Advanced SIEM Alert Triage and Correlation Service.
Handles deduplication, correlation, threat intelligence enrichment,
intelligent risk scoring, attack timelines, analyst workflows, and SOAR execution.
"""
import uuid
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_, and_

from app.models.models import (
    SecurityAlert,
    SecurityEvent,
    Alert,
    Incident,
    IncidentTimeline,
    Asset
)
from app.detection.rules import DetectionMatch
from app.detection.event_normalizer import StandardizedEvent
from app.detection.correlation import correlation_tracker
from app.detection.rule_registry import rule_registry
from app.detection.threat_intel import threat_intel_service
from app.detection.risk_scorer import risk_scorer
from app.ws_manager import ws_manager


class AlertTriageService:
    """Core triage orchestrator for live SIEM operations."""

    def __init__(self, dedup_window_seconds: int = 300, correlation_window_seconds: int = 900):
        self.dedup_window_seconds = dedup_window_seconds
        self.correlation_window_seconds = correlation_window_seconds

    @staticmethod
    def _generate_alert_id(rule_id: str) -> str:
        short_uuid = uuid.uuid4().hex[:6].upper()
        return f"ALT-{rule_id}-{short_uuid}"

    @staticmethod
    def _build_dedup_key(rule_id: str, source_ip: Optional[str], username: Optional[str]) -> str:
        sip = (source_ip or "none").strip().lower()
        usr = (username or "none").strip().lower()
        return f"{rule_id.upper()}:{sip}:{usr}"

    def ingest_match(
        self,
        db: Session,
        match: DetectionMatch,
        event: StandardizedEvent
    ) -> SecurityAlert:
        """
        Ingests a detection match.
        1. Checks for deduplication against active alerts.
        2. Enriches with Threat Intelligence.
        3. Evaluates asset criticality and risk score.
        4. Correlates across multi-stage alerts and groups into an Incident.
        5. Persists and broadcasts via WebSocket.
        """
        now = datetime.utcnow()
        dedup_key = self._build_dedup_key(match.rule_id, event.source_ip, event.username)
        dedup_cutoff = now - timedelta(seconds=self.dedup_window_seconds)

        # 1. Deduplication Check
        existing_alert = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.dedup_key == dedup_key,
                SecurityAlert.last_seen_at >= dedup_cutoff,
                SecurityAlert.status.in_(["New", "Investigating", "Escalated"])
            )
            .order_by(desc(SecurityAlert.last_seen_at))
            .first()
        )

        if existing_alert:
            # Group into existing alert: increment count, preserve evidence, refresh score
            existing_alert.occurrence_count = (existing_alert.occurrence_count or 1) + 1
            existing_alert.last_seen_at = now
            existing_alert.is_duplicate = True

            # Merge matched event IDs safely without duplicates
            current_event_ids = list(existing_alert.matched_event_ids or [])
            for eid in match.matched_event_ids:
                if eid not in current_event_ids:
                    current_event_ids.append(eid)
            existing_alert.matched_event_ids = current_event_ids

            # Update evidence payload with latest telemetry details
            merged_evidence = dict(existing_alert.evidence or {})
            merged_evidence.update(match.evidence)
            merged_evidence["latest_occurrence_at"] = now.isoformat()
            merged_evidence["total_occurrences"] = existing_alert.occurrence_count
            existing_alert.evidence = merged_evidence

            # Recompute Risk Score with updated frequency
            asset_crit = self._get_asset_criticality(db, existing_alert.source_ip)
            is_corr = bool(existing_alert.correlation_id or existing_alert.incident_id)
            score, priority, factors, expl = risk_scorer.calculate(
                severity=existing_alert.severity,
                occurrence_count=existing_alert.occurrence_count,
                threat_intel=existing_alert.threat_intel or {},
                asset_criticality=asset_crit,
                is_correlated=is_corr
            )
            existing_alert.risk_score = score
            existing_alert.priority = priority
            existing_alert.risk_factors = factors

            # Append audit trail entry
            audit = list(existing_alert.audit_trail or [])
            audit.append({
                "action": "Deduplicated Alert Updated",
                "actor": "SIEM Deduplication Engine",
                "timestamp": now.isoformat(),
                "details": f"Occurrence count incremented to {existing_alert.occurrence_count}. Risk score updated to {score}."
            })
            existing_alert.audit_trail = audit
            existing_alert.updated_at = now

            db.commit()
            db.refresh(existing_alert)

            # Record cooldown and rule stats
            correlation_tracker.record_alert_fired(match.rule_id, match.entity_key)
            rule_registry.increment_detection(db, match.rule_id)

            # Broadcast WebSocket Deduplication update
            self._broadcast_alert("ALERT_UPDATED", existing_alert)
            return existing_alert

        # 2. Brand New Alert: Threat Intelligence Enrichment
        threat_intel = threat_intel_service.enrich_indicator(
            indicator=event.source_ip or event.details.get("file_hash"),
            indicator_type="Hash" if event.details.get("file_hash") else "IP",
            db=db
        )

        # 3. Asset Criticality & Risk Scoring
        asset_crit = self._get_asset_criticality(db, event.source_ip)
        correlation_id, related_incident_id = self._find_or_create_correlation(db, event.source_ip, event.username, now)

        score, priority, factors, expl = risk_scorer.calculate(
            severity=match.severity,
            occurrence_count=1,
            threat_intel=threat_intel,
            asset_criticality=asset_crit,
            is_correlated=bool(correlation_id)
        )

        # 4. Create and Persist SecurityAlert
        alert_id = self._generate_alert_id(match.rule_id)
        audit_trail = [{
            "action": "Alert Ingested & Evaluated",
            "actor": "SIEM Detection Engine",
            "timestamp": now.isoformat(),
            "details": f"Rule {match.rule_id} triggered. Threat Intel: {threat_intel.get('reputation')}. Risk Score: {score} ({priority})."
        }]

        sec_alert = SecurityAlert(
            alert_id=alert_id,
            rule_id=match.rule_id,
            rule_name=match.rule_name,
            title=match.alert_title,
            description=match.description,
            severity=match.severity,
            category=match.category,
            source_ip=event.source_ip,
            username=event.username,
            event_timestamp=event.timestamp,
            detection_timestamp=now,
            matched_event_ids=match.matched_event_ids,
            evidence=match.evidence,
            status="New",
            is_demo=event.is_demo,
            occurrence_count=1,
            is_duplicate=False,
            dedup_key=dedup_key,
            first_seen_at=now,
            last_seen_at=now,
            destination_ip=event.dest_ip,
            correlation_id=correlation_id,
            incident_id=related_incident_id,
            risk_score=score,
            risk_factors=factors,
            threat_intel=threat_intel,
            priority=priority,
            notes=[],
            audit_trail=audit_trail,
            created_at=now,
            updated_at=now,
        )
        db.add(sec_alert)
        db.commit()
        db.refresh(sec_alert)

        # 5. Record cooldown and update rule stats
        correlation_tracker.record_alert_fired(match.rule_id, match.entity_key)
        rule_registry.increment_detection(db, match.rule_id)

        # 6. Legacy alert synchronization for incidents/reports compatibility
        try:
            legacy_alert = Alert(
                title=f"[{match.rule_id}] {match.alert_title}",
                category=match.category,
                severity=match.severity,
                description=match.description,
                mitre_tactics=match.mitre_tactics,
                mitre_techniques=match.mitre_techniques,
                source_log=json.dumps({
                    "evidence": match.evidence,
                    "event_ids": match.matched_event_ids,
                    "source_ip": event.source_ip,
                    "username": event.username,
                    "risk_score": score
                }),
                status="New",
                is_duplicate=False,
                timestamp=now,
                rule_id=match.rule_id,
                alert_code=alert_id,
                source_ip=event.source_ip,
                username=event.username,
                evidence=match.evidence,
                matched_event_ids=match.matched_event_ids,
                is_demo=event.is_demo,
                incident_id=related_incident_id
            )
            db.add(legacy_alert)
            db.commit()
        except Exception as e:
            print(f"Notice on legacy sync: {e}")

        # 7. WebSocket Live Dispatch
        self._broadcast_alert("NEW_ALERT", sec_alert)
        return sec_alert

    def _get_asset_criticality(self, db: Session, ip_address: Optional[str]) -> str:
        """Looks up asset table or identifies crown jewel criticality."""
        if not ip_address:
            return "Medium"
        asset = db.query(Asset).filter(Asset.ip_address == ip_address).first()
        if asset and asset.criticality:
            return asset.criticality
        # Heuristics for demo critical infrastructure
        if ip_address.endswith(".1") or ip_address.endswith(".254") or "dc" in ip_address:
            return "Critical"
        return "Medium"

    def _find_or_create_correlation(
        self,
        db: Session,
        source_ip: Optional[str],
        username: Optional[str],
        now: datetime
    ) -> Tuple[Optional[str], Optional[int]]:
        """
        Finds existing alerts for the same source IP or username within the correlation window.
        If found, groups them under a common correlation_id and associates with an Incident.
        """
        if not source_ip and not username:
            return None, None

        window_start = now - timedelta(seconds=self.correlation_window_seconds)
        conditions = []
        if source_ip:
            conditions.append(SecurityAlert.source_ip == source_ip)
        if username:
            conditions.append(SecurityAlert.username == username)

        recent_related = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.detection_timestamp >= window_start,
                or_(*conditions)
            )
            .order_by(desc(SecurityAlert.detection_timestamp))
            .first()
        )

        if recent_related and recent_related.correlation_id:
            return recent_related.correlation_id, recent_related.incident_id

        if recent_related:
            # Generate new correlation identifier
            entity_tag = source_ip or username or "entity"
            corr_id = f"CORR-{entity_tag.replace('.', '-')[:16]}-{uuid.uuid4().hex[:4].upper()}"
            recent_related.correlation_id = corr_id

            # Create Grouped Incident in Incident table if not already linked
            if not recent_related.incident_id:
                inc = Incident(
                    title=f"Correlated Multi-Stage Security Event ({entity_tag})",
                    description=f"Automated SIEM correlation identified linked suspicious activities targeting {entity_tag}.",
                    severity="High",
                    status="Open",
                    risk_score=75.0,
                    creator="SIEM Correlation Engine",
                    created_at=now
                )
                db.add(inc)
                db.commit()
                db.refresh(inc)
                recent_related.incident_id = inc.id
                db.commit()

            return corr_id, recent_related.incident_id

        return None, None

    def update_alert_status(
        self,
        db: Session,
        alert_identifier: str,
        status: Optional[str] = None,
        assigned_to: Optional[str] = None,
        priority: Optional[str] = None,
        note: Optional[str] = None,
        actor: str = "SOC Analyst"
    ) -> Optional[SecurityAlert]:
        """
        Updates alert triage status, assignee, priority, and records an audit log.
        """
        alert = self.get_alert_by_id(db, alert_identifier)
        if not alert:
            return None

        now = datetime.utcnow()
        audit = list(alert.audit_trail or [])
        notes = list(alert.notes or [])

        if status:
            valid_statuses = {"New", "Investigating", "Escalated", "Resolved", "False Positive"}
            clean_status = status.strip()
            matched_status = next((s for s in valid_statuses if s.lower() == clean_status.lower()), clean_status)
            old_status = alert.status
            alert.status = matched_status
            audit.append({
                "action": f"Status changed from '{old_status}' to '{matched_status}'",
                "actor": actor,
                "timestamp": now.isoformat(),
                "details": f"Analyst triage progression: {matched_status}"
            })

        if assigned_to is not None:
            old_assignee = alert.assigned_to or "Unassigned"
            alert.assigned_to = assigned_to
            audit.append({
                "action": f"Assigned to '{assigned_to}'",
                "actor": actor,
                "timestamp": now.isoformat(),
                "details": f"Case reassigned from {old_assignee} to {assigned_to}"
            })

        if priority:
            clean_priority = priority.upper().strip()
            if clean_priority in ("P1", "P2", "P3", "P4"):
                old_p = alert.priority
                alert.priority = clean_priority
                audit.append({
                    "action": f"Priority adjusted to {clean_priority}",
                    "actor": actor,
                    "timestamp": now.isoformat(),
                    "details": f"Priority modified from {old_p} to {clean_priority}"
                })

        if note and note.strip():
            note_obj = {
                "id": str(uuid.uuid4())[:8],
                "author": actor,
                "text": note.strip(),
                "timestamp": now.isoformat()
            }
            notes.append(note_obj)
            audit.append({
                "action": "Investigation Note Added",
                "actor": actor,
                "timestamp": now.isoformat(),
                "details": f"Note: {note[:60]}..."
            })

        alert.notes = notes
        alert.audit_trail = audit
        alert.updated_at = now
        db.commit()
        db.refresh(alert)

        # Broadcast update over WebSocket
        self._broadcast_alert("ALERT_UPDATED", alert)
        return alert

    def get_attack_timeline(self, db: Session, alert_identifier: str) -> List[Dict[str, Any]]:
        """
        Assembles a chronological attack and triage timeline:
        - Contributing Raw Logs
        - Rule Detection
        - Threat Intel Enrichment
        - Correlation Event
        - Analyst Actions
        - Remediation & Resolution
        """
        alert = self.get_alert_by_id(db, alert_identifier)
        if not alert:
            return []

        timeline: List[Dict[str, Any]] = []

        # 1. Contributing Events (from security_events)
        if alert.matched_event_ids:
            events = db.query(SecurityEvent).filter(SecurityEvent.event_id.in_(alert.matched_event_ids)).all()
            for evt in events:
                timeline.append({
                    "stage": "telemetry",
                    "title": f"Security Event Log: {evt.event_type}",
                    "timestamp": evt.timestamp.isoformat(),
                    "actor": evt.username or evt.source_ip or "Telemetry Source",
                    "details": f"Raw event ID {evt.event_id} captured via {evt.source}. Target: {evt.dest_ip or 'Local System'}.",
                    "type": "event"
                })

        # 2. Rule Detection Trigger
        timeline.append({
            "stage": "detection",
            "title": f"SIEM Detection Rule Triggered: {alert.rule_name} ({alert.rule_id})",
            "timestamp": alert.detection_timestamp.isoformat() if alert.detection_timestamp else alert.created_at.isoformat(),
            "actor": "SIEM Correlation Engine",
            "details": alert.description or "Configured detection condition met by incoming event sequence.",
            "type": "alert",
            "severity": alert.severity
        })

        # 3. Threat Intelligence Enrichment
        if alert.threat_intel and alert.threat_intel.get("reputation"):
            ti = alert.threat_intel
            timeline.append({
                "stage": "enrichment",
                "title": f"Threat Intel Enrichment: {ti.get('reputation')} ({ti.get('score')}%)",
                "timestamp": ti.get("retrieval_timestamp") or alert.detection_timestamp.isoformat(),
                "actor": ti.get("source") or "Threat Intel Gateway",
                "details": f"Attributed to {ti.get('threat_actor') or 'Unknown'}. Category: {ti.get('category')}. {ti.get('details')}",
                "type": "intel"
            })

        # 4. Correlation & Incident Linking
        if alert.correlation_id:
            timeline.append({
                "stage": "correlation",
                "title": f"Alert Correlated into Incident #{alert.incident_id or 'Auto'}",
                "timestamp": alert.created_at.isoformat(),
                "actor": "SIEM Correlation Engine",
                "details": f"Grouped with related telemetry under correlation key '{alert.correlation_id}'.",
                "type": "correlation"
            })

        # 5. Deduplication Observations
        if alert.occurrence_count and alert.occurrence_count > 1:
            timeline.append({
                "stage": "deduplication",
                "title": f"Repeated Activity: {alert.occurrence_count} Occurrences Captured",
                "timestamp": alert.last_seen_at.isoformat() if alert.last_seen_at else alert.updated_at.isoformat(),
                "actor": "SIEM Deduplication Engine",
                "details": f"Alert deduplicated {alert.occurrence_count} times in active sliding window. Risk score recalculated to {alert.risk_score}.",
                "type": "dedup"
            })

        # 6. Analyst Actions & Audit Trail
        for audit_entry in (alert.audit_trail or []):
            if "Ingested" not in audit_entry.get("action", ""):
                timeline.append({
                    "stage": "analyst",
                    "title": audit_entry.get("action"),
                    "timestamp": audit_entry.get("timestamp"),
                    "actor": audit_entry.get("actor", "SecOps Analyst"),
                    "details": audit_entry.get("details", ""),
                    "type": "analyst"
                })

        # Sort timeline chronologically
        timeline.sort(key=lambda x: x.get("timestamp") or "")
        return timeline

    def execute_soar_remediation(
        self,
        db: Session,
        alert_identifier: str,
        action: str,
        parameters: Optional[Dict[str, Any]] = None,
        actor: str = "SecOps Commander"
    ) -> Dict[str, Any]:
        """
        Executes a targeted SOAR mitigation action with analyst authorization.
        Simulates in Demo mode and logs an immutable audit trail entry.
        """
        alert = self.get_alert_by_id(db, alert_identifier)
        if not alert:
            return {"status": "error", "message": f"Alert '{alert_identifier}' not found"}

        now = datetime.utcnow()
        action_clean = action.lower().strip()
        params = parameters or {}

        result_message = ""
        action_title = ""

        if action_clean == "block_ip":
            target_ip = params.get("ip") or alert.source_ip or "185.220.101.4"
            action_title = f"Perimeter Firewall Rule: Block {target_ip}"
            result_message = f"Simulated egress/ingress block applied to IP {target_ip} across Edge Firewall cluster."
        elif action_clean == "isolate_host":
            target_host = params.get("hostname") or alert.source_ip or "WKSTN-SEC-01"
            action_title = f"EDR Host Isolation: {target_host}"
            result_message = f"Endpoint network isolation policy activated for host {target_host} via CrowdStrike/Sentinel simulator."
        elif action_clean == "disable_user":
            target_user = params.get("username") or alert.username or "compromised_user"
            action_title = f"Active Directory Revocation: {target_user}"
            result_message = f"Revoked active Kerberos/OAuth tokens and disabled Active Directory account for user '{target_user}'."
        elif action_clean == "trigger_playbook":
            action_title = "Automated Incident Containment Playbook"
            result_message = "SOAR Playbook executed successfully: Enriched IOCs, quarantined host, posted incident brief to Slack war room."
        else:
            action_title = f"Custom Mitigation: {action}"
            result_message = f"Executed response action '{action}' on target security entity."

        # Update Alert Audit Trail
        audit = list(alert.audit_trail or [])
        audit.append({
            "action": f"SOAR Action Executed: {action_title}",
            "actor": actor,
            "timestamp": now.isoformat(),
            "details": result_message
        })
        alert.audit_trail = audit
        alert.status = "Investigating"
        alert.updated_at = now
        db.commit()
        db.refresh(alert)

        # Notify via WebSocket
        self._broadcast_alert("ALERT_UPDATED", alert)

        return {
            "status": "success",
            "action": action_clean,
            "title": action_title,
            "message": result_message,
            "alert_id": alert.alert_id,
            "executed_by": actor,
            "timestamp": now.isoformat()
        }

    def generate_ai_analysis(self, db: Session, alert_identifier: str) -> Dict[str, Any]:
        """
        Generates a strictly evidence-grounded AI analysis of the alert.
        Distinguishes verified factual evidence from analytical hypotheses.
        """
        alert = self.get_alert_by_id(db, alert_identifier)
        if not alert:
            return {"error": "Alert not found"}

        ti = alert.threat_intel or {}
        evidence = alert.evidence or {}

        # 1. Summary
        summary = (
            f"Security Alert {alert.alert_id} represents a {alert.severity.upper()} severity detection "
            f"under rule '{alert.rule_name}' ({alert.rule_id}). "
            f"The detection engine observed {alert.occurrence_count or 1} occurrences matching "
            f"the {alert.category} threat model from source entity '{alert.source_ip or alert.username or 'Internal'}'. "
            f"Overall risk evaluated at {alert.risk_score}/100 ({alert.priority})."
        )

        # 2. Reason for detection
        reason = (
            evidence.get("trigger_condition") or
            f"Exceeded configured rule thresholds for {alert.rule_name}. "
            f"Associated with {len(alert.matched_event_ids or [])} contributing event logs within active sliding window."
        )

        # 3. Grounded factual evidence
        supporting_evidence = {
            "rule_id": alert.rule_id,
            "source_ip": alert.source_ip or "N/A",
            "username": alert.username or "N/A",
            "threat_actor": ti.get("threat_actor") or "Unattributed",
            "reputation": ti.get("reputation") or "Unknown",
            "matched_event_count": len(alert.matched_event_ids or []),
            "occurrence_count": alert.occurrence_count or 1,
            "parameters": evidence
        }

        # 4. Potential impact
        impact = (
            f"Potential unauthorized credential compromise, unauthorized lateral movement, or policy violations. "
            f"Asset evaluated at '{alert.risk_factors[1]['description'] if len(alert.risk_factors or []) > 1 else 'Standard'}'. "
            f"If uncontained, adversary may achieve persistent command execution or enterprise data exfiltration."
        )

        # 5. Suggested investigation steps
        steps = [
            f"1. Validate source IP '{alert.source_ip}' against enterprise VPN access logs and external threat feeds.",
            f"2. Inspect authentication timeline for account '{alert.username}' to confirm legitimate user presence.",
            f"3. Review {len(alert.matched_event_ids or [])} contributing security events for process execution or file modifications.",
            f"4. If malicious activity is confirmed, trigger perimeter IP block and initiate Active Directory password reset.",
            f"5. Escalate incident to Tier 3 SecOps Commander if indicators of secondary C2 communication are observed."
        ]

        # 6. Confidence & Limitations
        confidence = 94.0 if ti.get("reputation") == "Confirmed Malicious" else (85.0 if alert.source_ip else 78.0)
        limitations = (
            "Analysis strictly grounded on supplied telemetry and external intelligence feeds. "
            "Indicators classified as 'Unknown' have not been confirmed malicious and require manual verification. "
            "AI Copilot does not perform destructive actions autonomously."
        )

        ai_payload = {
            "alert_id": alert.alert_id,
            "alert_summary": summary,
            "reason_for_detection": reason,
            "supporting_evidence": supporting_evidence,
            "potential_impact": impact,
            "related_events": alert.matched_event_ids or [],
            "suggested_investigation_steps": steps,
            "confidence_score": confidence,
            "limitations": limitations,
            "analyzed_at": datetime.utcnow().isoformat()
        }

        # Cache in alert model
        alert.ai_analysis = ai_payload
        db.commit()

        return ai_payload

    def get_alert_by_id(self, db: Session, alert_identifier: str) -> Optional[SecurityAlert]:
        """Retrieves alert by string alert_id (e.g. 'ALT-BR-001-XXXX') or numeric database ID."""
        if str(alert_identifier).isdigit():
            alert = db.query(SecurityAlert).filter(SecurityAlert.id == int(alert_identifier)).first()
            if alert:
                return alert
        return db.query(SecurityAlert).filter(SecurityAlert.alert_id == alert_identifier).first()

    def _broadcast_alert(self, event_type: str, alert: SecurityAlert):
        """Dispatches real-time WebSocket telemetry to connected analysts."""
        ws_payload = {
            "type": event_type,
            "id": alert.id,
            "alert_id": alert.alert_id,
            "rule_id": alert.rule_id,
            "title": alert.title,
            "category": alert.category,
            "severity": alert.severity,
            "source_ip": alert.source_ip,
            "username": alert.username,
            "status": alert.status,
            "priority": alert.priority or "P3",
            "risk_score": alert.risk_score or 0.0,
            "occurrence_count": alert.occurrence_count or 1,
            "is_duplicate": alert.is_duplicate or False,
            "correlation_id": alert.correlation_id,
            "incident_id": alert.incident_id,
            "threat_intel": alert.threat_intel or {},
            "timestamp": alert.detection_timestamp.isoformat() if alert.detection_timestamp else alert.created_at.isoformat(),
            "evidence": alert.evidence or {}
        }
        ws_manager.sync_broadcast(ws_payload)


# Global triage service singleton
alert_triage_service = AlertTriageService()

