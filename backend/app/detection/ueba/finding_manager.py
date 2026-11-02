"""
UEBA Finding Manager.
Coordinates anomaly evaluation, finding generation, deduplication,
profile risk updates, WebSocket broadcasting, and SIEM alert synchronization.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import uuid
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.models import UEBAProfile, UEBAFinding, UEBAFeedback, SecurityAlert, SecurityEvent
from app.detection.event_normalizer import StandardizedEvent
from app.detection.ueba.baseline_engine import baseline_engine
from app.detection.ueba.anomaly_detector import anomaly_detector, AnomalyCandidate
from app.detection.ueba.risk_scorer import ueba_risk_scorer
from app.ws_manager import ws_manager


class FindingManager:
    """Handles lifecycle of UEBA findings and SIEM pipeline integration."""

    DEDUPLICATION_WINDOW_MINUTES = 60

    def process_event(self, db: Session, event: StandardizedEvent) -> List[UEBAFinding]:
        """
        Main pipeline hook: normalizes entity, compares with baseline, detects anomalies,
        calculates risk scores, persists findings, and broadcasts live alerts.
        """
        entity_id = event.username or event.source_ip
        if not entity_id or entity_id.lower() in ("unknown", "anonymous", "generic", "system"):
            # If username unavailable, fallback to source IP if valid
            if event.source_ip and event.source_ip not in ("127.0.0.1", "localhost"):
                entity_id = event.source_ip
                entity_type = "ip"
            else:
                return []
        else:
            entity_type = "user" if event.username else "endpoint"

        # 1. Retrieve or initialize entity profile
        profile = baseline_engine.get_or_create_profile(db, entity_id, entity_type)

        # 2. Evaluate event for anomalies
        candidates = anomaly_detector.evaluate_event(db, event, profile)
        if not candidates:
            return []

        created_findings = []
        now = datetime.utcnow()

        for cand in candidates:
            # 3. Check for existing open finding within cooldown window to prevent alert fatigue
            recent_duplicate = (
                db.query(UEBAFinding)
                .filter(
                    UEBAFinding.entity_id == cand.entity_id,
                    UEBAFinding.anomaly_type == cand.anomaly_type,
                    UEBAFinding.status.in_(["New", "Investigating"]),
                    UEBAFinding.created_at >= now - timedelta(minutes=self.DEDUPLICATION_WINDOW_MINUTES)
                )
                .first()
            )

            if recent_duplicate:
                # Append event ID to existing finding without creating duplicate
                if event.event_id not in (recent_duplicate.related_event_ids or []):
                    rel = list(recent_duplicate.related_event_ids or [])
                    rel.append(event.event_id)
                    recent_duplicate.related_event_ids = rel
                    recent_duplicate.updated_at = now
                    db.commit()
                continue

            # 4. Calculate explainable risk score
            crit = profile.metadata_info.get("criticality", "Medium") if profile.metadata_info else "Medium"
            risk_score, risk_level, factors = ueba_risk_scorer.calculate_risk(
                deviation_score=cand.raw_deviation_score,
                severity=cand.severity,
                frequency_count=profile.anomalies_count + 1,
                entity_criticality=crit,
                confidence=cand.confidence
            )

            finding_code = f"UEBA-{uuid.uuid4().hex[:8].upper()}"

            evidence_dict = dict(cand.evidence)
            evidence_dict["risk_factors"] = factors
            evidence_dict["calculated_risk_score"] = risk_score

            finding = UEBAFinding(
                finding_id=finding_code,
                entity_id=cand.entity_id,
                entity_type=cand.entity_type,
                anomaly_type=cand.anomaly_type,
                detection_method=cand.detection_method,
                risk_score=risk_score,
                confidence=cand.confidence,
                severity=cand.severity,
                title=cand.title,
                description=cand.description,
                evidence=evidence_dict,
                related_event_ids=cand.related_event_ids,
                recommended_steps=cand.recommended_steps,
                status="New",
                is_demo=bool(event.is_demo),
                created_at=now,
                updated_at=now
            )
            db.add(finding)

            # Update Profile metrics
            profile.anomalies_count += 1
            profile.risk_score = max(profile.risk_score, risk_score)
            profile.risk_level = risk_level
            profile.last_updated_at = now

            created_findings.append(finding)

            # 5. Broadcast NEW_UEBA_FINDING over WebSocket for live dashboard updates
            try:
                ws_payload = {
                    "type": "NEW_UEBA_FINDING",
                    "finding_id": finding.finding_id,
                    "entity_id": finding.entity_id,
                    "entity_type": finding.entity_type,
                    "anomaly_type": finding.anomaly_type,
                    "detection_method": finding.detection_method,
                    "risk_score": finding.risk_score,
                    "severity": finding.severity,
                    "title": finding.title,
                    "description": finding.description,
                    "timestamp": finding.created_at.isoformat(),
                    "is_demo": finding.is_demo
                }
                ws_manager.sync_broadcast(ws_payload)
            except Exception as e:
                print(f"Notice on UEBA finding broadcast: {e}")

            # 6. Optional SIEM Integration: forward High & Critical UEBA findings into SecurityAlert table
            if finding.severity in ("High", "Critical"):
                try:
                    siem_alert_id = f"ALT-UEBA-{uuid.uuid4().hex[:6].upper()}"
                    siem_alert = SecurityAlert(
                        alert_id=siem_alert_id,
                        rule_id="UEBA-ANOMALY",
                        rule_name=f"UEBA: {finding.anomaly_type}",
                        title=f"[UEBA Anomaly] {finding.title}",
                        description=finding.description,
                        severity=finding.severity,
                        category="Behavioral Anomaly",
                        source_ip=event.source_ip,
                        username=finding.entity_id if finding.entity_type == "user" else None,
                        event_timestamp=event.timestamp or now,
                        detection_timestamp=now,
                        matched_event_ids=finding.related_event_ids,
                        evidence=evidence_dict,
                        status="New",
                        is_demo=finding.is_demo,
                        risk_score=finding.risk_score,
                        risk_factors=factors,
                        priority="P1" if finding.severity == "Critical" else "P2",
                        created_at=now,
                        updated_at=now
                    )
                    db.add(siem_alert)
                except Exception as e:
                    print(f"Notice on SIEM alert synchronization: {e}")

        db.commit()
        for f in created_findings:
            db.refresh(f)

        return created_findings

    def update_finding_status(
        self,
        db: Session,
        finding_id: str,
        status: str,
        assigned_to: Optional[str] = None,
        comments: Optional[str] = None
    ) -> Optional[UEBAFinding]:
        """Updates finding investigation status."""
        finding = db.query(UEBAFinding).filter(UEBAFinding.finding_id == finding_id).first()
        if not finding:
            return None

        finding.status = status
        if assigned_to:
            finding.assigned_to = assigned_to
        finding.updated_at = datetime.utcnow()

        if comments:
            evidence = dict(finding.evidence or {})
            notes = evidence.get("analyst_notes", [])
            notes.append({
                "status": status,
                "comments": comments,
                "timestamp": datetime.utcnow().isoformat()
            })
            evidence["analyst_notes"] = notes
            finding.evidence = evidence

        db.commit()
        db.refresh(finding)
        return finding

    def add_feedback(
        self,
        db: Session,
        finding_id: str,
        analyst_id: str,
        feedback_type: str,
        comments: Optional[str] = None
    ) -> UEBAFeedback:
        """Stores analyst verification feedback."""
        fb = UEBAFeedback(
            finding_id=finding_id,
            analyst_id=analyst_id,
            feedback_type=feedback_type,
            comments=comments,
            created_at=datetime.utcnow()
        )
        db.add(fb)

        # If False Positive feedback, auto-update finding status
        if feedback_type == "False Positive":
            self.update_finding_status(db, finding_id, status="False Positive", comments=comments)

        db.commit()
        db.refresh(fb)
        return fb


finding_manager = FindingManager()
