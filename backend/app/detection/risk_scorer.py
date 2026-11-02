"""
Intelligent Risk Scoring Engine.
Computes configurable 0–100 risk scores with transparent contributing factors,
combining rule severity, asset criticality, threat intelligence, event frequency,
and multi-stage correlation.
"""
from typing import Dict, Any, List, Tuple


class RiskScorer:
    """Calculates granular risk scores (0-100) and priority ratings (P1-P4)."""

    SEVERITY_WEIGHTS = {
        "critical": 35.0,
        "high": 25.0,
        "medium": 15.0,
        "low": 5.0,
        "informational": 2.0
    }

    ASSET_WEIGHTS = {
        "critical": 25.0,
        "high": 18.0,
        "medium": 10.0,
        "low": 5.0
    }

    THREAT_INTEL_WEIGHTS = {
        "confirmed malicious": 25.0,
        "malicious": 25.0,
        "suspicious": 15.0,
        "unknown": 5.0,
        "clean": 0.0
    }

    @classmethod
    def calculate(
        cls,
        severity: str,
        occurrence_count: int = 1,
        threat_intel: Dict[str, Any] = None,
        asset_criticality: str = "Medium",
        is_correlated: bool = False
    ) -> Tuple[float, str, List[Dict[str, Any]], str]:
        """
        Calculates risk score, priority band (P1-P4), contributing factor items, and explanation.
        """
        factors: List[Dict[str, Any]] = []

        # 1. Detection Severity Factor
        sev_clean = (severity or "Medium").strip().lower()
        sev_pts = cls.SEVERITY_WEIGHTS.get(sev_clean, 15.0)
        factors.append({
            "factor": "Detection Rule Severity",
            "points": sev_pts,
            "max": 35.0,
            "description": f"Rule triggered with {severity.upper()} baseline classification."
        })

        # 2. Asset Criticality Factor
        asset_clean = (asset_criticality or "Medium").strip().lower()
        asset_pts = cls.ASSET_WEIGHTS.get(asset_clean, 10.0)
        factors.append({
            "factor": "Asset Criticality",
            "points": asset_pts,
            "max": 25.0,
            "description": f"Target environment or identity evaluated as {asset_criticality.upper()} criticality."
        })

        # 3. Threat Intelligence Factor
        ti_reputation = "Unknown"
        if threat_intel and "reputation" in threat_intel:
            ti_reputation = threat_intel["reputation"]
        ti_clean = ti_reputation.strip().lower()
        ti_pts = cls.THREAT_INTEL_WEIGHTS.get(ti_clean, 5.0)
        factors.append({
            "factor": "Threat Intelligence Context",
            "points": ti_pts,
            "max": 25.0,
            "description": f"Associated indicator reputation evaluated as '{ti_reputation}' from external feeds."
        })

        # 4. Event Frequency / Deduplication Factor
        freq_pts = min(15.0, max(0.0, float(occurrence_count - 1) * 3.0))
        factors.append({
            "factor": "Event Frequency & Velocity",
            "points": freq_pts,
            "max": 15.0,
            "description": f"Observed {occurrence_count} deduplicated occurrences in active time window."
        })

        # 5. Correlated Evidence Factor
        corr_pts = 10.0 if is_correlated else 0.0
        factors.append({
            "factor": "Multi-Stage Correlation",
            "points": corr_pts,
            "max": 10.0,
            "description": "Correlated across related detection rules or concurrent attack stages." if is_correlated else "Single isolated detection stage."
        })

        total_score = min(100.0, round(sum(f["points"] for f in factors), 1))

        # Assign Priority
        if total_score >= 80.0:
            priority = "P1"
        elif total_score >= 60.0:
            priority = "P2"
        elif total_score >= 40.0:
            priority = "P3"
        else:
            priority = "P4"

        explanation = (
            f"Evaluated overall risk at {total_score}/100 ({priority}). Primary drivers: "
            f"{severity.upper()} severity (+{sev_pts} pts), {asset_criticality.capitalize()} asset criticality (+{asset_pts} pts), "
            f"and '{ti_reputation}' threat intelligence context (+{ti_pts} pts)."
        )

        return total_score, priority, factors, explanation


# Global risk scorer singleton
risk_scorer = RiskScorer()

