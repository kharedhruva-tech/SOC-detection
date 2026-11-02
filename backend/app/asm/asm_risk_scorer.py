from typing import Dict, Any, List

CRITICALITY_MAP = {
    "Critical": 100.0,
    "High": 75.0,
    "Medium": 45.0,
    "Low": 20.0,
}

EXPOSURE_MAP = {
    "Public Internet": 100.0,
    "DMZ": 70.0,
    "Internal VPC": 35.0,
    "Air-gapped": 10.0,
}

class ASMRiskScorer:
    @staticmethod
    def calculate_asset_risk(
        criticality: str = "Medium",
        exposure_level: str = "Public Internet",
        cert_days_remaining: int = 90,
        has_dns_issues: bool = False,
        unexpected_services_count: int = 0,
    ) -> Dict[str, Any]:
        """
        Calculate an explainable 0–100 Attack Surface Risk Score for an asset.
        """
        crit_val = CRITICALITY_MAP.get(criticality, 45.0)
        expo_val = EXPOSURE_MAP.get(exposure_level, 70.0)

        # Cert/DNS hygiene score component (0 to 100 penalty)
        hygiene_penalty = 0.0
        if cert_days_remaining < 0:
            hygiene_penalty += 85.0
        elif cert_days_remaining <= 7:
            hygiene_penalty += 65.0
        elif cert_days_remaining <= 30:
            hygiene_penalty += 35.0

        if has_dns_issues:
            hygiene_penalty += 25.0
        hygiene_val = min(100.0, hygiene_penalty)

        # Service penalty
        service_val = min(100.0, unexpected_services_count * 35.0)

        # Weighted calculation
        # 30% Criticality + 25% Exposure + 25% Cert/DNS Hygiene + 20% Unexpected Services
        raw_score = (
            (crit_val * 0.30) +
            (expo_val * 0.25) +
            (hygiene_val * 0.25) +
            (service_val * 0.20)
        )

        final_score = round(min(100.0, max(0.0, raw_score)), 1)

        if final_score >= 80.0:
            posture = "Critical Attack Surface Exposure"
            tier = "P1 - Critical Priority"
        elif final_score >= 60.0:
            posture = "Elevated Perimeter Risk"
            tier = "P2 - High Priority"
        elif final_score >= 40.0:
            posture = "Moderate Exposure Profile"
            tier = "P3 - Medium Priority"
        else:
            posture = "Hardened Perimeter Posture"
            tier = "P4 - Low Risk"

        factors = [
            {"factor": "Asset Business Criticality", "contribution": f"{round(crit_val * 0.30, 1)} pts", "detail": f"Tier: {criticality}"},
            {"factor": "Perimeter Exposure Level", "contribution": f"{round(expo_val * 0.25, 1)} pts", "detail": f"Location: {exposure_level}"},
            {"factor": "Certificate & DNS Hygiene", "contribution": f"{round(hygiene_val * 0.25, 1)} pts", "detail": f"Cert Days Left: {cert_days_remaining}, DNS Concerns: {has_dns_issues}"},
            {"factor": "Unexpected Service Exposures", "contribution": f"{round(service_val * 0.20, 1)} pts", "detail": f"Unapproved Open Services: {unexpected_services_count}"},
        ]

        return {
            "risk_score": final_score,
            "posture": posture,
            "tier": tier,
            "factors": factors,
        }

asm_risk_scorer = ASMRiskScorer()
