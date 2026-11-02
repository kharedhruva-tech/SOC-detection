"""
UEBA Behaviour Baseline Engine.
Builds, updates, and versions behavioural baselines for monitored users and entities
using historical security event telemetry.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import math
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_

from app.models.models import SecurityEvent, UEBAProfile, UEBABaseline, User, Asset


class BaselineEngine:
    """Manages baseline learning, updating, and persistence for users and entities."""

    MIN_SAMPLES_FOR_LEARNING = 5
    MIN_SAMPLES_FOR_ESTABLISHED = 15

    def get_or_create_profile(
        self,
        db: Session,
        entity_id: str,
        entity_type: str = "user",
        metadata_info: Optional[Dict[str, Any]] = None
    ) -> UEBAProfile:
        """Retrieves existing profile or initializes a new one in Learning status."""
        profile = db.query(UEBAProfile).filter(UEBAProfile.entity_id == entity_id).first()
        if not profile:
            profile = UEBAProfile(
                entity_id=entity_id,
                entity_type=entity_type,
                display_name=entity_id.replace("_", " ").title(),
                baseline_status="Learning",
                risk_score=15.0,
                risk_level="Low",
                learning_started_at=datetime.utcnow(),
                last_updated_at=datetime.utcnow(),
                baseline_version=1,
                metadata_info=metadata_info or {},
                anomalies_count=0
            )
            db.add(profile)
            db.commit()
            db.refresh(profile)
        return profile

    def build_baseline_for_entity(
        self,
        db: Session,
        entity_id: str,
        entity_type: str = "user",
        include_demo: bool = False
    ) -> Dict[str, Any]:
        """
        Computes multi-dimensional behavioural baselines from historical events.
        Updates or creates UEBABaseline records across login_hours, login_locations,
        login_frequency, data_volume, and resource_access.
        """
        profile = self.get_or_create_profile(db, entity_id, entity_type)

        # Query historical events for this entity
        query = db.query(SecurityEvent)
        if entity_type == "user":
            query = query.filter(SecurityEvent.username == entity_id)
        elif entity_type in ("endpoint", "server", "ip"):
            query = query.filter(or_(SecurityEvent.source_ip == entity_id, SecurityEvent.dest_ip == entity_id))
        else:
            query = query.filter(or_(SecurityEvent.username == entity_id, SecurityEvent.source_ip == entity_id))

        if not include_demo:
            query = query.filter(SecurityEvent.is_demo == False)

        events: List[SecurityEvent] = query.order_by(SecurityEvent.timestamp.asc()).all()
        event_count = len(events)

        # Determine learning status
        if event_count < self.MIN_SAMPLES_FOR_LEARNING:
            status = "Insufficient Data"
            confidence = 0.25
        elif event_count < self.MIN_SAMPLES_FOR_ESTABLISHED:
            status = "Learning"
            confidence = 0.65
        else:
            status = "Established"
            confidence = 0.90

        profile.baseline_status = status
        profile.baseline_version += 1
        profile.last_updated_at = datetime.utcnow()

        # 1. Login Hours Baseline
        login_events = [e for e in events if "login" in (e.event_type or "").lower() or "auth" in (e.category or "").lower()]
        hours_distribution: Dict[int, int] = {h: 0 for h in range(24)}
        for e in login_events:
            if e.timestamp:
                hours_distribution[e.timestamp.hour] += 1

        # Identify typical hours (hours with >= 10% of max activity or at least 1 login if few events)
        max_hour_hits = max(hours_distribution.values()) if hours_distribution else 0
        threshold = max(1, int(max_hour_hits * 0.15))
        typical_hours = [h for h, count in hours_distribution.items() if count >= threshold]
        if not typical_hours:
            typical_hours = [8, 9, 10, 11, 12, 13, 14, 15, 16, 17]  # Standard enterprise default

        login_hours_data = {
            "typical_hours": sorted(typical_hours),
            "start_hour": min(typical_hours) if typical_hours else 8,
            "end_hour": max(typical_hours) if typical_hours else 18,
            "distribution": hours_distribution,
            "weekend_logins_count": sum(1 for e in login_events if e.timestamp and e.timestamp.weekday() >= 5),
            "sample_count": len(login_events)
        }
        self._save_category_baseline(db, profile.id, "login_hours", login_hours_data, len(login_events), confidence)

        # 2. Login Locations / IP Baseline
        ips: Dict[str, int] = {}
        for e in events:
            ip = e.source_ip
            if ip and ip not in ("unknown", "127.0.0.1", "localhost"):
                ips[ip] = ips.get(ip, 0) + 1

        known_ips = list(ips.keys())
        login_loc_data = {
            "common_ips": known_ips,
            "primary_ip": max(ips, key=ips.get) if ips else "10.0.1.50",
            "ip_frequencies": ips,
            "sample_count": len(events)
        }
        self._save_category_baseline(db, profile.id, "login_locations", login_loc_data, len(events), confidence)

        # 3. Data Transfer Volume Baseline (Mean & Standard Deviation for Z-scores)
        volumes = []
        for e in events:
            if e.details and isinstance(e.details, dict):
                vol = e.details.get("bytes_transferred") or e.details.get("data_mb") or e.details.get("file_size_mb")
                if vol is not None:
                    try:
                        volumes.append(float(vol))
                    except (ValueError, TypeError):
                        pass

        if len(volumes) >= 2:
            mean_vol = sum(volumes) / len(volumes)
            variance = sum((x - mean_vol) ** 2 for x in volumes) / (len(volumes) - 1)
            std_vol = math.sqrt(variance)
        elif len(volumes) == 1:
            mean_vol = volumes[0]
            std_vol = volumes[0] * 0.25
        else:
            mean_vol = 15.0  # Default 15 MB
            std_vol = 5.0

        std_vol = max(std_vol, 1.0)  # Avoid division by zero in Z-score calculation
        data_volume_data = {
            "mean_volume_mb": round(mean_vol, 2),
            "std_volume_mb": round(std_vol, 2),
            "sample_size": len(volumes),
            "max_volume_mb": round(max(volumes), 2) if volumes else round(mean_vol * 1.5, 2)
        }
        self._save_category_baseline(db, profile.id, "data_volume", data_volume_data, len(volumes), confidence)

        # 4. Resource Access & Endpoint Baseline
        resources: Dict[str, int] = {}
        for e in events:
            if e.details and isinstance(e.details, dict):
                res = e.details.get("resource") or e.details.get("file_name") or e.details.get("share_name") or e.details.get("url")
                if res:
                    resources[str(res)] = resources.get(str(res), 0) + 1

        resource_data = {
            "frequently_accessed": sorted(resources.keys(), key=lambda r: resources[r], reverse=True)[:15],
            "distinct_resources_count": len(resources),
            "avg_daily_distinct": max(1, len(resources) // max(1, len(events) // 5))
        }
        self._save_category_baseline(db, profile.id, "resource_access", resource_data, len(resources), confidence)

        db.commit()
        db.refresh(profile)

        return {
            "entity_id": profile.entity_id,
            "status": profile.baseline_status,
            "confidence": confidence,
            "version": profile.baseline_version,
            "events_analyzed": event_count
        }

    def _save_category_baseline(
        self,
        db: Session,
        profile_id: int,
        category: str,
        data: Dict[str, Any],
        sample_count: int,
        confidence: float
    ) -> UEBABaseline:
        """Helper to upsert a category baseline record."""
        baseline = (
            db.query(UEBABaseline)
            .filter(UEBABaseline.profile_id == profile_id, UEBABaseline.behaviour_category == category)
            .first()
        )
        if not baseline:
            baseline = UEBABaseline(
                profile_id=profile_id,
                behaviour_category=category,
                baseline_data=data,
                sample_count=sample_count,
                confidence=confidence,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.add(baseline)
        else:
            baseline.baseline_data = data
            baseline.sample_count = sample_count
            baseline.confidence = confidence
            baseline.updated_at = datetime.utcnow()
        return baseline

    def rebuild_all_baselines(self, db: Session, include_demo: bool = False) -> Dict[str, Any]:
        """Rebuilds baselines for all registered users and entities."""
        # 1. Discover all users
        user_entities = db.query(SecurityEvent.username).distinct().filter(SecurityEvent.username.isnot(None)).all()
        usernames = {u[0] for u in user_entities if u[0]}

        # Also pull from users table
        db_users = db.query(User.username).all()
        for u in db_users:
            if u[0]:
                usernames.add(u[0])

        updated = []
        for uname in usernames:
            res = self.build_baseline_for_entity(db, uname, "user", include_demo=include_demo)
            updated.append(res)

        return {
            "status": "success",
            "rebuilt_count": len(updated),
            "entities": updated,
            "timestamp": datetime.utcnow().isoformat()
        }

    def reset_baseline(self, db: Session, entity_id: str) -> bool:
        """Resets an entity's baseline upon administrative request."""
        profile = db.query(UEBAProfile).filter(UEBAProfile.entity_id == entity_id).first()
        if not profile:
            return False

        db.query(UEBABaseline).filter(UEBABaseline.profile_id == profile.id).delete()
        profile.baseline_status = "Learning"
        profile.baseline_version += 1
        profile.risk_score = 15.0
        profile.risk_level = "Low"
        profile.last_updated_at = datetime.utcnow()
        db.commit()
        return True

    def seed_default_sample_profiles(self, db: Session):
        """Ensures realistic baseline data is present for demonstration entities."""
        default_entities = [
            {
                "entity_id": "jsmith",
                "entity_type": "user",
                "display_name": "John Smith (Finance Lead)",
                "metadata": {"department": "Finance", "role": "Senior Financial Analyst", "workstation": "WKSTN-FIN-04"},
                "typical_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
                "primary_ip": "10.0.1.45",
                "mean_data_mb": 18.5,
                "std_data_mb": 4.2
            },
            {
                "entity_id": "bwayne",
                "entity_type": "user",
                "display_name": "Bruce Wayne (Executive)",
                "metadata": {"department": "Executive", "role": "Chief Executive", "workstation": "EXEC-LAPTOP-01"},
                "typical_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
                "primary_ip": "10.0.1.10",
                "mean_data_mb": 35.0,
                "std_data_mb": 8.0
            },
            {
                "entity_id": "admin_svc",
                "entity_type": "service_account",
                "display_name": "Backup & Sync Service",
                "metadata": {"department": "IT Operations", "role": "Automated Service Account", "server": "SRV-BACKUP-01"},
                "typical_hours": list(range(24)),
                "primary_ip": "10.0.2.100",
                "mean_data_mb": 500.0,
                "std_data_mb": 50.0
            },
            {
                "entity_id": "sarah_hr",
                "entity_type": "user",
                "display_name": "Sarah Connor (HR Director)",
                "metadata": {"department": "Human Resources", "role": "HR Director", "workstation": "HR-WKSTN-02"},
                "typical_hours": [9, 10, 11, 12, 13, 14, 15, 16],
                "primary_ip": "10.0.1.88",
                "mean_data_mb": 12.0,
                "std_data_mb": 3.0
            }
        ]

        for ent in default_entities:
            existing = db.query(UEBAProfile).filter(UEBAProfile.entity_id == ent["entity_id"]).first()
            if not existing:
                prof = UEBAProfile(
                    entity_id=ent["entity_id"],
                    entity_type=ent["entity_type"],
                    display_name=ent["display_name"],
                    baseline_status="Established",
                    risk_score=20.0,
                    risk_level="Low",
                    learning_started_at=datetime.utcnow() - timedelta(days=45),
                    last_updated_at=datetime.utcnow(),
                    baseline_version=2,
                    metadata_info=ent["metadata"],
                    anomalies_count=0
                )
                db.add(prof)
                db.commit()
                db.refresh(prof)

                # Seed category baselines
                hours_dist = {h: (40 if h in ent["typical_hours"] else 1) for h in range(24)}
                self._save_category_baseline(db, prof.id, "login_hours", {
                    "typical_hours": ent["typical_hours"],
                    "start_hour": min(ent["typical_hours"]),
                    "end_hour": max(ent["typical_hours"]),
                    "distribution": hours_dist,
                    "sample_count": 85
                }, 85, 0.92)

                self._save_category_baseline(db, prof.id, "login_locations", {
                    "common_ips": [ent["primary_ip"], "10.0.1.254"],
                    "primary_ip": ent["primary_ip"],
                    "sample_count": 85
                }, 85, 0.90)

                self._save_category_baseline(db, prof.id, "data_volume", {
                    "mean_volume_mb": ent["mean_data_mb"],
                    "std_volume_mb": ent["std_data_mb"],
                    "sample_size": 85,
                    "max_volume_mb": ent["mean_data_mb"] * 2.5
                }, 85, 0.95)

                self._save_category_baseline(db, prof.id, "resource_access", {
                    "frequently_accessed": ["\\\\Share\\General", "\\\\Share\\Department", "Internal-Portal"],
                    "distinct_resources_count": 12,
                    "avg_daily_distinct": 3
                }, 85, 0.88)

        db.commit()


baseline_engine = BaselineEngine()
