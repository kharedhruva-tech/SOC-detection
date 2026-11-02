from typing import Dict, Any, List, Optional

APPROVED_STANDARD_PORTS = {80, 443}

HIGH_RISK_PORTS = {
    21: {"service": "FTP", "risk": "Critical", "reason": "Cleartext FTP protocol exposes credentials."},
    22: {"service": "SSH", "risk": "Medium", "reason": "Administrative remote shell exposed to public internet."},
    23: {"service": "Telnet", "risk": "Critical", "reason": "Legacy cleartext protocol transmits all data in plaintext."},
    445: {"service": "SMB", "risk": "Critical", "reason": "Server Message Block exposed; prime vector for ransomware lateral movement."},
    1433: {"service": "MSSQL", "risk": "High", "reason": "Database port exposed on perimeter."},
    3306: {"service": "MySQL", "risk": "High", "reason": "Relational database port publicly accessible."},
    3389: {"service": "RDP", "risk": "High", "reason": "Remote Desktop Protocol exposed; brute force target."},
    5432: {"service": "PostgreSQL", "risk": "High", "reason": "PostgreSQL port exposed on perimeter."},
    6379: {"service": "Redis", "risk": "Critical", "reason": "In-memory database without auth allows remote code execution."},
    8080: {"service": "HTTP-Alt", "risk": "Low", "reason": "Secondary web interface; verify authentication."},
    9200: {"service": "Elasticsearch", "risk": "High", "reason": "Search index exposed; high data exfiltration risk."},
    27017: {"service": "MongoDB", "risk": "Critical", "reason": "NoSQL database exposed without access controls."},
}

class ServiceExposureAnalyzer:
    @staticmethod
    def evaluate_service_exposure(
        port: int,
        protocol: str = "TCP",
        service_name: Optional[str] = None,
        approved_baseline_ports: Optional[List[int]] = None,
        is_internet_facing: bool = True,
    ) -> Dict[str, Any]:
        """
        Compare exposed service against asset's approved baseline.
        Flag unexpected services and classify exposure risk.
        """
        baseline = set(approved_baseline_ports or [80, 443])
        is_approved = port in baseline

        meta = HIGH_RISK_PORTS.get(port, {
            "service": service_name or f"Port-{port}",
            "risk": "Medium" if is_internet_facing else "Low",
            "reason": "Non-standard network port observed."
        })

        if is_approved:
            status = "Approved Baseline"
            risk_level = "Low"
            recommendation = "Service is part of the approved asset baseline."
        else:
            status = "Unexpected Exposure"
            risk_level = meta["risk"]
            if not is_internet_facing and risk_level == "Critical":
                risk_level = "High"
            recommendation = f"Audit port {port} ({meta['service']}). If not required publicly, close port or restrict via security group ACL."

        return {
            "port": port,
            "protocol": protocol.upper(),
            "service": meta["service"] if meta["service"] != f"Port-{port}" else (service_name or meta["service"]),
            "is_approved_baseline": is_approved,
            "exposure_status": status,
            "risk_level": risk_level,
            "reason": meta["reason"],
            "recommendation": recommendation,
        }

service_analyzer = ServiceExposureAnalyzer()

