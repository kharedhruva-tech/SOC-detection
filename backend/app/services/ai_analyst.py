import json
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.models.models import Incident, Alert, IncidentTimeline, IncidentComment
from app.database import SessionLocal
from datetime import datetime
import random

class AIAnalystEngine:
    def __init__(self):
        # In a real scenario, this would initialize a connection to an LLM (e.g. OpenAI, Vertex AI)
        self.model_name = "CyberCopilot-v2.0"
        
    def summarize_incident(self, db: Session, incident_id: int) -> str:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return "Incident not found."
            
        alerts = db.query(Alert).filter(Alert.incident_id == incident.id).all()
        
        # Simple heuristic generation for prototype
        summary = f"**AI Summary for Incident #{incident.id}: {incident.title}**\n\n"
        
        if "Brute Force" in incident.title:
            summary += f"This incident involves multiple failed login attempts indicative of a brute force attack. We observed {len(alerts)} related alerts. "
        elif "Impossible Travel" in incident.title:
            summary += f"This incident was triggered due to logins from geographically distant locations in an impossibly short timeframe. "
        elif "Ransomware" in incident.title:
            summary += f"CRITICAL: High volume of file modifications detected matching ransomware behavior patterns. Immediate isolation recommended. "
        else:
            summary += f"General security incident containing {len(alerts)} correlated alerts. "
            
        summary += "\n\n**Recommended Actions:**\n"
        summary += "- Review affected assets for compromise.\n"
        summary += "- Consider executing the appropriate isolation playbook.\n"
        summary += "- Verify the source IP reputation.\n"
        
        # Add summary as a comment to the incident
        # Use correct model field: comment_text (not content), no is_ai_generated column
        comment = IncidentComment(
            incident_id=incident.id,
            author="AI Analyst",
            comment_text=summary,
        )
        db.add(comment)
        db.commit()
        
        return summary
        
    def analyze_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Provides real-time analysis of a specific alert."""
        analysis = {
            "severity_score": random.randint(40, 99),
            "false_positive_probability": round(random.uniform(0.01, 0.45), 2),
            "mitre_tactics": ["Initial Access", "Execution"],
            "explanation": "The AI model identified anomalous patterns in the request payload that deviate significantly from baseline behavior."
        }
        
        if "login" in str(alert_data).lower():
            analysis["mitre_tactics"] = ["Credential Access"]
            analysis["explanation"] = "Multiple authentication failures followed by a success indicates potential credential stuffing or brute force."
            
        return analysis
        
    def generate_root_cause_analysis(self, db: Session, incident_id: int) -> str:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return "Incident not found."
            
        rca = f"### AI Root Cause Analysis (Incident #{incident.id})\n\n"
        rca += "**Initial Vector:**\n"
        rca += "The attack likely originated from an external IP scanning for vulnerable exposed services.\n\n"
        
        rca += "**Execution:**\n"
        rca += "Malicious payloads were executed utilizing living-off-the-land binaries (LOLBins).\n\n"
        
        rca += "**Impact:**\n"
        rca += f"Potential unauthorized access to {incident.severity} severity assets. No data exfiltration confirmed yet.\n"
        
        return rca

ai_analyst = AIAnalystEngine()
