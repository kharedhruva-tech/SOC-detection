"""
UEBA Anomaly Detection Engine.
Applies rule-based, statistical (Z-score), and behavioural deviation techniques
against established user and entity baselines.
"""
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import math
from sqlalchemy.orm import Session

from app.models.models import SecurityEvent, UEBAProfile, UEBABaseline
from app.detection.event_normalizer import StandardizedEvent


class AnomalyCandidate:
    """Represents an anomaly evaluation result before finding creation."""

    def __init__(
        self,
        entity_id: str,
        entity_type: str,
        anomaly_type: str,
        detection_method: str,
        severity: str,
        title: str,
        description: str,
        evidence: Dict[str, Any],
        raw_deviation_score: float,
        confidence: float,
        related_event_ids: List[str],
        recommended_steps: List[str]
    ):
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.anomaly_type = anomaly_type
        self.detection_method = detection_method
        self.severity = severity
        self.title = title
        self.description = description
        self.evidence = evidence
        self.raw_deviation_score = raw_deviation_score
        self.confidence = confidence
        self.related_event_ids = related_event_ids
        self.recommended_steps = recommended_steps


class AnomalyDetector:
    """Evaluates incoming security events against established baselines."""

    def __init__(self):
        self.z_score_threshold = 3.0  # Standard statistical anomaly threshold (99.7% confidence)
        self.dormant_days_threshold = 30  # Days of inactivity before dormant reactivation triggers

    def evaluate_event(
        self,
        db: Session,
        event: StandardizedEvent,
        profile: UEBAProfile
    ) -> List[AnomalyCandidate]:
        """
        Runs comprehensive behavioural and statistical checks against the entity profile.
        Returns a list of detected anomaly candidates.
        """
        candidates: List[AnomalyCandidate] = []
        if not profile:
            return candidates

        # Fetch category baselines for fast lookup
        baselines_by_cat = {b.behaviour_category: b for b in profile.baselines}

        # 1. Unusual Login Time Check
        time_cand = self._check_unusual_login_time(event, profile, baselines_by_cat.get("login_hours"))
        if time_cand:
            candidates.append(time_cand)

        # 2. Unusual Login Location / IP Check
        loc_cand = self._check_unusual_location(event, profile, baselines_by_cat.get("login_locations"))
        if loc_cand:
            candidates.append(loc_cand)

        # 3. Abnormal Data Transfer Volume (Statistical Z-Score)
        vol_cand = self._check_data_volume_zscore(event, profile, baselines_by_cat.get("data_volume"))
        if vol_cand:
            candidates.append(vol_cand)

        # 4. Dormant Account Activity Check
        dorm_cand = self._check_dormant_account(db, event, profile)
        if dorm_cand:
            candidates.append(dorm_cand)

        # 5. Unusual Resource Access Count
        res_cand = self._check_resource_access(event, profile, baselines_by_cat.get("resource_access"))
        if res_cand:
            candidates.append(res_cand)

        # 6. Unexpected Privilege or Role Change
        priv_cand = self._check_privilege_anomaly(event, profile)
        if priv_cand:
            candidates.append(priv_cand)

        return candidates

    def _check_unusual_login_time(
        self,
        event: StandardizedEvent,
        profile: UEBAProfile,
        baseline: Optional[UEBABaseline]
    ) -> Optional[AnomalyCandidate]:
        """Detects logins occurring significantly outside typical hours."""
        if "login" not in (event.event_type or "").lower() and "auth" not in (event.category or "").lower():
            return None

        event_time = event.timestamp or datetime.utcnow()
        event_hour = event_time.hour

        # If baseline exists and has typical hours
        typical_hours = [9, 10, 11, 12, 13, 14, 15, 16, 17]
        confidence = 0.75
        if baseline and baseline.baseline_data and "typical_hours" in baseline.baseline_data:
            typical_hours = baseline.baseline_data["typical_hours"]
            confidence = baseline.confidence or 0.85

        if event_hour not in typical_hours:
            # Calculate distance in hours from the nearest typical hour
            distances = [min(abs(event_hour - th), 24 - abs(event_hour - th)) for th in typical_hours]
            min_dist = min(distances) if distances else 4

            if min_dist >= 2:  # At least 2 hours deviation from established schedule
                # Calculate deviation score (2 to 12 hours -> 50 to 95)
                deviation = min(95.0, 50.0 + (min_dist * 5.0))
                severity = "High" if min_dist >= 4 else "Medium"

                return AnomalyCandidate(
                    entity_id=profile.entity_id,
                    entity_type=profile.entity_type,
                    anomaly_type="Unusual Login Time",
                    detection_method="Behavioral Deviation",
                    severity=severity,
                    title=f"Unusual Access Time for @{profile.entity_id}",
                    description=(
                        f"Authentication observed at {event_hour:02d}:00 UTC, which deviates by {min_dist} hours "
                        f"from the established activity pattern ({min(typical_hours):02d}:00–{max(typical_hours):02d}:00 UTC)."
                    ),
                    evidence={
                        "observed_hour_utc": event_hour,
                        "typical_hours": typical_hours,
                        "hour_deviation_distance": min_dist,
                        "baseline_status": profile.baseline_status,
                        "baseline_sample_count": baseline.sample_count if baseline else 0
                    },
                    raw_deviation_score=deviation,
                    confidence=confidence,
                    related_event_ids=[event.event_id],
                    recommended_steps=[
                        f"1. Contact @{profile.entity_id} via secondary communication to verify off-hours login.",
                        "2. Inspect source workstation hostname and IP origin.",
                        "3. Check for subsequent sensitive resource access or lateral movement attempts."
                    ]
                )
        return None

    def _check_unusual_location(
        self,
        event: StandardizedEvent,
        profile: UEBAProfile,
        baseline: Optional[UEBABaseline]
    ) -> Optional[AnomalyCandidate]:
        """Detects login from an unknown source IP outside historical subnets."""
        if "login" not in (event.event_type or "").lower() or not event.source_ip:
            return None

        ip = event.source_ip
        if ip in ("127.0.0.1", "localhost", "unknown"):
            return None

        common_ips = []
        confidence = 0.70
        if baseline and baseline.baseline_data:
            common_ips = baseline.baseline_data.get("common_ips", [])
            confidence = baseline.confidence or 0.80

        # If baseline is established and IP is unknown
        if common_ips and ip not in common_ips:
            # Check if same /24 subnet as any common IP
            ip_parts = ip.split(".")
            subnet_match = False
            if len(ip_parts) == 4:
                prefix = ".".join(ip_parts[:3])
                for c_ip in common_ips:
                    if c_ip.startswith(prefix):
                        subnet_match = True
                        break

            if not subnet_match:
                # External / foreign IP anomaly
                return AnomalyCandidate(
                    entity_id=profile.entity_id,
                    entity_type=profile.entity_type,
                    anomaly_type="Unusual Login Location",
                    detection_method="Rule-Based Baseline",
                    severity="High",
                    title=f"Unrecognized Source IP Origin for @{profile.entity_id}",
                    description=(
                        f"User logged in from uncatalogued IP address {ip}, outside all previously observed "
                        f"network segments ({', '.join(common_ips[:3])})."
                    ),
                    evidence={
                        "observed_ip": ip,
                        "known_ips": common_ips,
                        "subnet_matched": False,
                        "baseline_status": profile.baseline_status
                    },
                    raw_deviation_score=75.0,
                    confidence=confidence,
                    related_event_ids=[event.event_id],
                    recommended_steps=[
                        f"1. Cross-reference source IP {ip} against corporate VPN and perimeter proxy gateways.",
                        "2. Check Geo-IP intelligence for anomalous international or hosting provider origin.",
                        "3. Verify if MFA challenge completed successfully on this session."
                    ]
                )
        return None

    def _check_data_volume_zscore(
        self,
        event: StandardizedEvent,
        profile: UEBAProfile,
        baseline: Optional[UEBABaseline]
    ) -> Optional[AnomalyCandidate]:
        """Calculates statistical Z-score for data transfer volume deviations."""
        details = event.details or {}
        vol = details.get("bytes_transferred") or details.get("data_mb") or details.get("file_size_mb")
        if vol is None:
            return None

        try:
            observed_mb = float(vol)
        except (ValueError, TypeError):
            return None

        mean_mb = 20.0
        std_mb = 5.0
        confidence = 0.80

        if baseline and baseline.baseline_data:
            mean_mb = baseline.baseline_data.get("mean_volume_mb", 20.0)
            std_mb = baseline.baseline_data.get("std_volume_mb", 5.0)
            confidence = baseline.confidence or 0.85

        std_mb = max(std_mb, 1.0)
        z_score = (observed_mb - mean_mb) / std_mb

        if z_score >= self.z_score_threshold:
            # Significant volumetric anomaly (Z >= 3.0)
            severity = "Critical" if z_score >= 5.0 else "High"
            deviation = min(98.0, 60.0 + (z_score * 7.0))

            return AnomalyCandidate(
                entity_id=profile.entity_id,
                entity_type=profile.entity_type,
                anomaly_type="Abnormal Data Access Volume",
                detection_method="Statistical Z-Score",
                severity=severity,
                title=f"Volumetric Data Anomaly for @{profile.entity_id} (Z-Score: {z_score:.2f})",
                description=(
                    f"Observed outbound transfer of {observed_mb:.1f} MB exceeds historical baseline "
                    f"(Mean: {mean_mb:.1f} MB, StdDev: {std_mb:.1f} MB) with a Z-score of {z_score:.2f}."
                ),
                evidence={
                    "observed_volume_mb": round(observed_mb, 2),
                    "baseline_mean_mb": round(mean_mb, 2),
                    "baseline_std_mb": round(std_mb, 2),
                    "z_score": round(z_score, 2),
                    "z_threshold": self.z_score_threshold,
                    "target_destination": event.dest_ip or "External"
                },
                raw_deviation_score=deviation,
                confidence=confidence,
                related_event_ids=[event.event_id],
                recommended_steps=[
                    "1. Identify files transferred and classify confidential/regulated data exposure.",
                    "2. Verify destination IP/domain against DLP exfiltration indicators.",
                    "3. Initiate immediate temporary data-transfer hold if unauthorized exfiltration suspected."
                ]
            )
        return None

    def _check_dormant_account(
        self,
        db: Session,
        event: StandardizedEvent,
        profile: UEBAProfile
    ) -> Optional[AnomalyCandidate]:
        """Detects activity on an account inactive for > dormant_days_threshold."""
        details = event.details or {}
        is_explicit_dormant = bool(details.get("is_dormant") or details.get("dormant"))

        # Look up previous event timestamp in database
        previous_event = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.username == profile.entity_id,
                SecurityEvent.event_id != event.event_id
            )
            .order_by(SecurityEvent.timestamp.desc())
            .first()
        )

        days_inactive = 0
        if previous_event and previous_event.timestamp and event.timestamp:
            gap = event.timestamp - previous_event.timestamp
            days_inactive = gap.days

        if is_explicit_dormant or days_inactive >= self.dormant_days_threshold:
            dormant_days = days_inactive if days_inactive >= self.dormant_days_threshold else 92
            return AnomalyCandidate(
                entity_id=profile.entity_id,
                entity_type=profile.entity_type,
                anomaly_type="Dormant Account Activity",
                detection_method="Rule-Based Baseline",
                severity="High",
                title=f"Reactivation of Dormant Account @{profile.entity_id}",
                description=(
                    f"Account @{profile.entity_id} generated activity after {dormant_days} days of inactivity. "
                    "Sudden reactivation of dormant accounts is a common indicator of credential compromise."
                ),
                evidence={
                    "days_inactive": dormant_days,
                    "inactivity_threshold_days": self.dormant_days_threshold,
                    "last_active_before": previous_event.timestamp.isoformat() if previous_event and previous_event.timestamp else "N/A"
                },
                raw_deviation_score=85.0,
                confidence=0.88,
                related_event_ids=[event.event_id],
                recommended_steps=[
                    "1. Confirm if employee/contractor returned from leave or active assignment.",
                    "2. Verify if password was recently reset without user authorization.",
                    "3. Review identity provider authentication logs for brute-force or credential stuffing prior to login."
                ]
            )
        return None

    def _check_resource_access(
        self,
        event: StandardizedEvent,
        profile: UEBAProfile,
        baseline: Optional[UEBABaseline]
    ) -> Optional[AnomalyCandidate]:
        """Detects unusual spike in resources/files accessed in a single transaction."""
        details = event.details or {}
        resource_count = details.get("resource_count") or details.get("file_count") or details.get("shares_accessed_count")
        if not resource_count:
            return None

        try:
            count = int(resource_count)
        except (ValueError, TypeError):
            return None

        normal_max = 5
        if baseline and baseline.baseline_data:
            normal_max = max(normal_max, baseline.baseline_data.get("avg_daily_distinct", 3) * 3)

        if count >= normal_max * 3:
            return AnomalyCandidate(
                entity_id=profile.entity_id,
                entity_type=profile.entity_type,
                anomaly_type="Unusual Resource Access",
                detection_method="Behavioral Deviation",
                severity="High",
                title=f"Mass Resource Access Spike by @{profile.entity_id}",
                description=(
                    f"User accessed {count} distinct resources/shares simultaneously, exceeding typical baseline "
                    f"threshold ({normal_max} resources). Indicates potential bulk reconnaissance or data harvesting."
                ),
                evidence={
                    "accessed_resources_count": count,
                    "baseline_normal_max": normal_max,
                    "accessed_resources_sample": details.get("resources_list", [])[:5]
                },
                raw_deviation_score=80.0,
                confidence=0.85,
                related_event_ids=[event.event_id],
                recommended_steps=[
                    "1. Audit access logs for sensitive enterprise folders and databases.",
                    "2. Check if automated scripts/crawlers were executed by the user session.",
                    "3. Restrict temporary share access pending analyst confirmation."
                ]
            )
        return None

    def _check_privilege_anomaly(
        self,
        event: StandardizedEvent,
        profile: UEBAProfile
    ) -> Optional[AnomalyCandidate]:
        """Detects unexpected privilege changes or elevation commands."""
        ev_type = (event.event_type or "").lower()
        if "role" in ev_type or "privilege" in ev_type or "admin" in ev_type:
            details = event.details or {}
            role = details.get("new_role") or details.get("role") or details.get("command")
            if role and any(k in str(role).lower() for k in ("admin", "root", "domain admin", "superuser")):
                return AnomalyCandidate(
                    entity_id=profile.entity_id,
                    entity_type=profile.entity_type,
                    anomaly_type="Unexpected Privilege Change",
                    detection_method="Rule-Based Baseline",
                    severity="Critical",
                    title=f"Administrative Privilege Grant on @{profile.entity_id}",
                    description=(
                        f"Elevated role/privilege '{role}' assigned or invoked on @{profile.entity_id}, "
                        "deviating from standard non-administrative profile."
                    ),
                    evidence={
                        "assigned_privilege": str(role),
                        "assigned_by": details.get("assigned_by", "Unknown"),
                        "event_type": event.event_type
                    },
                    raw_deviation_score=90.0,
                    confidence=0.95,
                    related_event_ids=[event.event_id],
                    recommended_steps=[
                        "1. Verify change management ticket authorizing the privilege elevation.",
                        "2. Inspect issuing administrator account for signs of compromise.",
                        "3. Revoke privilege immediately if not backed by authorized change approval."
                    ]
                )
        return None


anomaly_detector = AnomalyDetector()
