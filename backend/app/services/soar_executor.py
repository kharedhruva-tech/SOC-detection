import json
import time
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.models.models import Incident, Alert, Playbook, PlaybookRun, IncidentTimeline
from datetime import datetime


class SOARExecutor:
    def __init__(self):
        pass

    def execute_playbook(self, db: Session, playbook_id: int, incident_id: int, triggered_by: str = "System") -> PlaybookRun:
        playbook = db.query(Playbook).filter(Playbook.id == playbook_id).first()
        incident = db.query(Incident).filter(Incident.id == incident_id).first()

        if not playbook or not incident:
            raise ValueError("Playbook or Incident not found")

        # Build initial log as a text string (model uses log: Text, not logs: JSON)
        log_lines = [f"[{datetime.utcnow().isoformat()}] Started playbook '{playbook.name}'"]

        # Create PlaybookRun record
        run = PlaybookRun(
            playbook_id=playbook.id,
            incident_id=incident.id,
            status="Running",
            triggered_by=triggered_by,
            log="\n".join(log_lines),
        )
        db.add(run)
        db.commit()
        db.refresh(run)

        # Add to incident timeline — use correct field names: event_type, message, actor
        timeline_entry = IncidentTimeline(
            incident_id=incident.id,
            event_type="playbook_started",
            message=f"Playbook '{playbook.name}' execution started by {triggered_by}.",
            actor=triggered_by,
        )
        db.add(timeline_entry)
        db.commit()

        # Build steps from playbook nodes (Playbook has nodes/edges, not steps)
        nodes: List[Dict[str, Any]] = playbook.nodes if isinstance(playbook.nodes, list) else []

        for node in nodes:
            action = node.get("data", {}).get("action") or node.get("action", "unknown")
            target = node.get("data", {}).get("target") or node.get("target", "N/A")

            log_lines.append(f"[{datetime.utcnow().isoformat()}] Executing step: {action} on {target}")

            # Simulate action effects
            if action == "isolate_host":
                log_lines.append(f"[{datetime.utcnow().isoformat()}] Host {target} successfully isolated from network.")
            elif action == "block_ip":
                log_lines.append(f"[{datetime.utcnow().isoformat()}] IP {target} blocked on perimeter firewall.")
            elif action == "disable_user":
                log_lines.append(f"[{datetime.utcnow().isoformat()}] User {target} disabled in Active Directory.")
            elif action == "send_email":
                log_lines.append(f"[{datetime.utcnow().isoformat()}] Notification email sent to {target}.")

            run.log = "\n".join(log_lines)
            db.commit()
            time.sleep(0.2)  # Simulate delay

        # Mark run as completed
        run.status = "Completed"
        run.completed_at = datetime.utcnow()
        log_lines.append(f"[{datetime.utcnow().isoformat()}] Playbook execution completed successfully.")
        run.log = "\n".join(log_lines)

        timeline_entry_done = IncidentTimeline(
            incident_id=incident.id,
            event_type="playbook_completed",
            message=f"Playbook '{playbook.name}' execution completed.",
            actor="SOAR Engine",
        )
        db.add(timeline_entry_done)

        # Update incident status
        if incident.status in ("Open", "New"):
            incident.status = "Investigating"

        db.commit()
        return run


soar_executor = SOARExecutor()
