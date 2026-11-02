from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

class ASMChangeEngine:
    @staticmethod
    def record_change(
        asset_id: str,
        asset_name: str,
        change_type: str,
        previous_value: Optional[str] = None,
        current_value: Optional[str] = None,
        severity: str = "Info",
        description: str = "",
        db: Optional[Session] = None,
    ) -> Dict[str, Any]:
        """
        Record an attack surface change event with audit tracking.
        """
        now = datetime.now(timezone.utc)
        change_record = {
            "change_id": f"CHG-{now.strftime('%Y%m%d%H%M%S')}",
            "asset_id": asset_id,
            "asset_name": asset_name,
            "change_type": change_type,
            "previous_value": str(previous_value) if previous_value is not None else None,
            "current_value": str(current_value) if current_value is not None else None,
            "severity": severity,
            "description": description or f"{change_type} detected on asset {asset_name}.",
            "timestamp": now.isoformat(),
            "reviewed": False,
            "reviewed_by": None,
        }

        if db:
            from app.models.models import ASMChangeLog
            db_log = ASMChangeLog(
                change_id=change_record["change_id"],
                asset_id=asset_id,
                asset_name=asset_name,
                change_type=change_type,
                previous_value=change_record["previous_value"],
                current_value=change_record["current_value"],
                severity=severity,
                description=change_record["description"],
                timestamp=now,
                reviewed=False,
            )
            db.add(db_log)
            db.commit()
            db.refresh(db_log)
            change_record["id"] = db_log.id

        return change_record

change_engine = ASMChangeEngine()
