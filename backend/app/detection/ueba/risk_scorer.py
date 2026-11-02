"""
UEBA Explainable Risk Scoring Engine.
Computes multi-factor risk scores (0–100) combining behavioural deviation,
event severity, activity frequency, and entity criticality with transparent factor breakdowns.
"""
from typing import Dict, Any, List, Tuple


class UEBARiskScorer:
    """Calculates explainable 0–100 risk scores with transparent contributing factor breakdowns."""

    def __init__(self):
        # Configurable weights summing to 1.0
        self.WEIGHT_DEVIATION = 0.35
        self.WEIGHT_SEVERITY = 0.30
        self.WEIGHT_FREQUENCY = 0.15
        self.WEIGHT_CRITICALITY = 0.20

    def calculate_risk(
        self,
        deviation_score: float,
        severity: str,
        frequency_count: int = 1,
        entity_criticality: str = "Medium",
        confidence: float = 0.8
    ) -> Tuple[float, str, List[Dict[str, Any]]]:
        """
        Calculates normalized risk score (0-100), classification, and factor breakdown.
        """
        # 1. Severity sub-score (0 to 100)
        sev_map = {
            "critical": 95.0,
            "high": 75.0,
            "medium": 45.0,
            "low": 20.0
        }
        sev_score = sev_map.get((severity or "").lower(), 40.0)

        # 2. Deviation sub-score (0 to 100, clamped)
        dev_score = max(0.0, min(100.0, float(deviation_score or 50.0)))

        # 3. Frequency sub-score (more occurrences increase risk, clamped at 100)
        freq_score = min(100.0, 20.0 + (max(1, frequency_count) * 15.0))

        # 4. Criticality sub-score
        crit_map = {
            "critical": 100.0,
            "high": 75.0,
            "medium": 50.0,
            "low": 25.0
        }
        crit_score = crit_map.get((entity_criticality or "").lower(), 50.0)

        # Weighted calculation
        raw_score = (
            (dev_score * self.WEIGHT_DEVIATION) +
            (sev_score * self.WEIGHT_SEVERITY) +
            (freq_score * self.WEIGHT_FREQUENCY) +
            (crit_score * self.WEIGHT_CRITICALITY)
        )

        # Scale slightly by confidence (insufficient baseline confidence prevents false criticals)
        effective_score = raw_score * (0.6 + (0.4 * min(1.0, max(0.1, confidence))))
        final_score = round(max(0.0, min(100.0, effective_score)), 1)

        # Classification
        if final_score >= 75.0:
            level = "Critical"
        elif final_score >= 50.0:
            level = "High"
        elif final_score >= 30.0:
            level = "Medium"
        else:
            level = "Low"

        # Transparent Contributing Factors
        factors = [
            {
                "factor": "Behavioural Baseline Deviation",
                "contribution": round(dev_score * self.WEIGHT_DEVIATION, 1),
                "weight": f"{int(self.WEIGHT_DEVIATION * 100)}%",
                "details": f"Measured deviation of {dev_score:.1f}/100 from historical baseline"
            },
            {
                "factor": "Event Severity",
                "contribution": round(sev_score * self.WEIGHT_SEVERITY, 1),
                "weight": f"{int(self.WEIGHT_SEVERITY * 100)}%",
                "details": f"Classified at {severity.capitalize()} baseline severity"
            },
            {
                "factor": "Activity Velocity & Frequency",
                "contribution": round(freq_score * self.WEIGHT_FREQUENCY, 1),
                "weight": f"{int(self.WEIGHT_FREQUENCY * 100)}%",
                "details": f"{frequency_count} repeated instance(s) observed in sliding evaluation window"
            },
            {
                "factor": "Asset / Entity Criticality",
                "contribution": round(crit_score * self.WEIGHT_CRITICALITY, 1),
                "weight": f"{int(self.WEIGHT_CRITICALITY * 100)}%",
                "details": f"Entity criticality tier: {entity_criticality.capitalize()}"
            }
        ]

        return final_score, level, factors


ueba_risk_scorer = UEBARiskScorer()

