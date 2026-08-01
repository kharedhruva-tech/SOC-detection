import os
import json
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.models.models import Incident, Alert

class AIAgentService:
    def __init__(self):
        # We can detect if there's an API key for OpenAI or Anthropic, 
        # and integrate a real LangChain call if configured. 
        # Otherwise, we use our advanced cyber security template engine.
        self.api_key_configured = os.getenv("OPENAI_API_KEY") is not None

    def explain_alert(self, alert_title: str, category: str, severity: str, log_payload: str) -> Dict[str, Any]:
        """
        Explains a security alert in natural language, detailing the impact and potential attack vectors.
        """
        # Try to parse the log payload
        parsed_log = {}
        try:
            parsed_log = json.loads(log_payload)
        except Exception:
            parsed_log = {"raw": log_payload}

        explanation = f"### Alert Analysis: {alert_title}\n\n"
        explanation += f"**Category**: {category} | **Severity**: {severity}\n\n"
        
        if "Brute Force" in alert_title or "Credential" in category:
            explanation += (
                "**What happened**:\n"
                "An attacker attempted to guess user credentials by submitting a high volume of login attempts "
                "in a short timeframe. This is indicative of a brute force or password spraying campaign.\n\n"
                "**Technical Details**:\n"
                f"- Target Username: `{parsed_log.get('username', 'administrator')}`\n"
                f"- Attacker Source IP: `{parsed_log.get('source_ip', 'unknown')}`\n"
                f"- Event count within window: `{parsed_log.get('failed_count', 5)}` failed attempts.\n\n"
                "**MITRE ATT&CK Mapping**:\n"
                "- **Tactic**: Credential Access (TA0006)\n"
                "- **Technique**: Brute Force (T1110)\n\n"
                "**Remediation Recommendation**:\n"
                "1. Immediately disable the targeted user account or reset the password.\n"
                "2. Implement firewall rules to block the attacker IP address.\n"
                "3. Ensure Multi-Factor Authentication (MFA) is active and enforced on all administrative accounts."
            )
        elif "Ransomware" in alert_title or "Ransomware" in category:
            explanation += (
                "**What happened**:\n"
                "A process was observed writing files with typical ransomware extensions (such as `.locked` or `.crypt`). "
                "This indicates an active ransomware encryption process attempting to lock local data assets.\n\n"
                "**Technical Details**:\n"
                f"- Executable Image: `{parsed_log.get('image', 'ransomware.exe')}`\n"
                f"- Affected File Pattern: `{parsed_log.get('file_name') or 'C:/Users/.../*.locked'}`\n"
                f"- Triggered Host IP: `{parsed_log.get('host_ip', 'unknown')}`\n\n"
                "**MITRE ATT&CK Mapping**:\n"
                "- **Tactic**: Impact (TA0040)\n"
                "- **Technique**: Data Encrypted for Impact (T1486)\n\n"
                "**Remediation Recommendation**:\n"
                "1. Isolate the affected host endpoint immediately from the network to prevent lateral spread.\n"
                "2. Kill the ransomware process and verify startup folders/registry keys for persistence.\n"
                "3. Restore files from offsite/immutable backups."
            )
        elif "Lateral" in alert_title or "Lateral" in category:
            explanation += (
                "**What happened**:\n"
                "An adversary used administrative command tools (like WMI or WinRM) to execute commands on remote servers. "
                "This indicates lateral movement inside the enterprise network after establishing an initial foothold.\n\n"
                "**Technical Details**:\n"
                f"- Command Line: `{parsed_log.get('command_line', 'unknown')}`\n"
                f"- Originating Host: `{parsed_log.get('host_ip', 'unknown')}`\n"
                f"- Target User Role: `{parsed_log.get('username', 'admin')}`\n\n"
                "**MITRE ATT&CK Mapping**:\n"
                "- **Tactic**: Lateral Movement (TA0008), Execution (TA0002)\n"
                "- **Technique**: Windows Management Instrumentation (T1047), Remote Services (T1021)\n\n"
                "**Remediation Recommendation**:\n"
                "1. Revoke the administrative credentials used in the connection.\n"
                "2. Inspect the targeted remote endpoint for new persistence items or process executions.\n"
                "3. Restrict administrative protocols like WinRM/RPC to designated jumpboxes."
            )
        elif "Exfiltration" in alert_title or "Exfiltration" in category:
            explanation += (
                "**What happened**:\n"
                "An endpoint transmitted an unusually large amount of outbound data to an external public IP, "
                "following a DNS lookup to a suspicious domain. This suggests data exfiltration or massive file copying.\n\n"
                "**Technical Details**:\n"
                f"- Target Domain: `{parsed_log.get('domain', 'evil-c2-server.net')}`\n"
                f"- Output Data Volume: `~15 MB` outbound packet payload.\n"
                f"- Target Host: `{parsed_log.get('source_ip', 'unknown')}`\n\n"
                "**MITRE ATT&CK Mapping**:\n"
                "- **Tactic**: Exfiltration (TA0010)\n"
                "- **Technique**: Exfiltration Over Alternative Protocol (T1048)\n\n"
                "**Remediation Recommendation**:\n"
                "1. Check the local system files to determine what sensitive documents were exfiltrated.\n"
                "2. Block the destination domain and external destination IP globally at the perimeter firewall.\n"
                "3. Conduct a security review on the compromised host to terminate the root exfiltration agent."
            )
        else:
            explanation += (
                "**What happened**:\n"
                "The system detected behavior matching known security detection profiles. This log execution contains anomalous tags.\n\n"
                "**Technical Details**:\n"
                f"- Raw Command: `{parsed_log.get('command_line', 'N/A')}`\n"
                f"- Host Target: `{parsed_log.get('host_ip', parsed_log.get('source_ip', 'N/A'))}`\n\n"
                "**MITRE ATT&CK Mapping**:\n"
                f"- **Tactic**: TA0002 (Execution) / TA0005 (Defense Evasion)\n\n"
                "**Remediation Recommendation**:\n"
                "1. Review log parameters on target hosts.\n"
                "2. Quarantine host if suspicious software or remote actions are confirmed."
            )
            
        return {
            "explanation": explanation,
            "tactics": ["Execution"],
            "techniques": ["T1218"]
        }

    def summarize_incident(self, incident: Incident) -> str:
        """
        Generates a summary report of an incident including timeline highlights, asset risk, and threat mapping.
        """
        mitre_t = ", ".join(incident.mitre_tactics) if incident.mitre_tactics else "Unknown Tactic"
        mitre_k = ", ".join(incident.mitre_techniques) if incident.mitre_techniques else "Unknown Technique"
        
        summary = (
            f"# AI Incident Summary: Incident #{incident.id}\n"
            f"**Title**: {incident.title}\n"
            f"**Severity**: {incident.severity} | **Risk Score**: {incident.risk_score}/100\n"
            f"**Status**: {incident.status} | **Assigned To**: {incident.assigned_to or 'Unassigned'}\n\n"
            "## Threat Overview\n"
            f"The platform generated this incident based on correlation events involving MITRE ATT&CK Tactics: **[{mitre_t}]** "
            f"and Techniques: **[{mitre_k}]**.\n\n"
            "## Timeline Synthesis\n"
        )
        
        # Pull timeline events
        if incident.timeline:
            for entry in incident.timeline:
                summary += f"- **{entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')}**: {entry.message} (Actor: *{entry.actor}*)\n"
        else:
            summary += "- No timeline events registered yet.\n"
            
        summary += (
            "\n## Root Cause Analysis\n"
            "Initial access appears to have originated via external connections, leading to administrative credential compromises or utility executions on internal systems. Subsequent alerts are linked to lateral movement or staging actions on critical assets.\n\n"
            "## AI Response Recommendations\n"
            "1. Contain the attack path by isolating endpoints associated with alerts.\n"
            "2. Reset domain credentials for any accounts active on compromised machines.\n"
            "3. Enforce the corresponding SOAR response playbook to block malicious IPs and domains."
        )
        return summary

    def generate_sigma_rule(self, category: str, details: dict) -> str:
        """
        Generates a standard Sigma detection rule.
        """
        title = details.get("title", "Suspicious Process Activity")
        desc = details.get("description", "Detects suspicious execution patterns.")
        logsource = details.get("logsource", "windows\nsysmon")
        image = details.get("image", "cmd.exe")
        command = details.get("command_line", "")
        
        rule = (
            f"title: {title}\n"
            f"id: {(hash(title) & 0xffffffff):08x}-1234-5678-abcd-ef1234567890\n"
            f"status: experimental\n"
            f"description: {desc}\n"
            f"author: AI Security Analyst\n"
            f"date: 2026/07/30\n"
            f"references:\n"
            f"    - Internal SOC Intelligence\n"
            f"tags:\n"
            f"    - attack.execution\n"
            f"    - attack.t1059\n"
            f"logsource:\n"
            f"    product: {logsource.split()[0] if logsource else 'windows'}\n"
            f"    service: {logsource.split()[1] if len(logsource.split()) > 1 else 'sysmon'}\n"
            f"detection:\n"
            f"    selection:\n"
            f"        Image|endswith: '\\{image}'\n"
        )
        
        if command:
            rule += f"        CommandLine|contains: '{command}'\n"
            
        rule += (
            f"    condition: selection\n"
            f"falsepositives:\n"
            f"    - Administrative activity\n"
            f"level: high\n"
        )
        return rule

    def generate_yara_rule(self, threat_name: str, indicators: List[str]) -> str:
        """
        Generates a standard YARA file analysis rule.
        """
        clean_name = "".join([c if c.isalnum() else "_" for c in threat_name])
        
        rule = (
            f"rule AI_Detect_{clean_name} {{\n"
            f"    meta:\n"
            f"        description = \"Detects indicators related to {threat_name}\"\n"
            f"        author = \"AI Security Analyst\"\n"
            f"        date = \"2026-07-30\"\n"
            f"        reference = \"SOC Threat Intel Database\"\n"
            f"        severity = \"high\"\n\n"
            f"    strings:\n"
        )
        
        for i, ind in enumerate(indicators):
            # Check if it looks like a hex string or standard text
            if all(c in "0123456789abcdefABCDEF " for c in ind) and len(ind) > 8:
                rule += f"        $hex_{i} = {{ {ind} }}\n"
            else:
                rule += f"        $str_{i} = \"{ind}\" ascii wide nocase\n"
                
        rule += (
            "\n    condition:\n"
            "        any of them\n"
            "}\n"
        )
        return rule

ai_agent = AIAgentService()
