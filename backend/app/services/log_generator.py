import json
import time
import random
import threading
from datetime import datetime
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.services.siem_engine import SIEMEngine

class LogGenerator:
    def __init__(self):
        self.running = False
        self.thread = None
        self.siem = SIEMEngine()
        self.hosts = ["10.0.1.5", "10.0.1.20", "10.0.2.50", "10.0.2.100", "192.168.1.10", "172.16.0.5"]
        self.users = ["admin", "jsmith", "bwayne", "ckent", "dprince", "puser", "service_acct"]
        self.ip_addresses = ["1.1.1.1", "8.8.8.8", "203.0.113.5", "198.51.100.12", "185.20.10.5", "45.33.22.11"]
        self.attack_ips = ["185.12.33.44", "194.22.33.11", "103.44.55.66"]
    
    def start(self):
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._run_loop, daemon=True)
            self.thread.start()
            print("Log generator started")
            
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
            print("Log generator stopped")
            
    def _run_loop(self):
        while self.running:
            # Generate normal logs
            self.generate_normal_logs()
            
            # Occasionally generate attack logs
            if random.random() < 0.1:
                self.generate_attack_sequence()
                
            time.sleep(random.uniform(1.0, 3.0))
            
    def _create_log(self, log_type: str, source_ip: str, dest_ip: str, user: str, details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "log_type": log_type,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "user": user,
            "details": details
        }
            
    def generate_normal_logs(self):
        db = SessionLocal()
        try:
            # Generate 1-5 random normal logs
            for _ in range(random.randint(1, 5)):
                log_type = random.choice(["Windows Event", "Firewall", "Web Access"])
                
                if log_type == "Windows Event":
                    log = self._create_log(
                        "Windows Event",
                        random.choice(self.hosts),
                        "Local",
                        random.choice(self.users),
                        {"event_id": 4624, "message": "Successful Logon", "process": "svchost.exe"}
                    )
                elif log_type == "Firewall":
                    log = self._create_log(
                        "Firewall",
                        random.choice(self.hosts),
                        random.choice(self.ip_addresses),
                        "System",
                        {"action": "allow", "port": 443, "protocol": "TCP"}
                    )
                else: # Web Access
                    log = self._create_log(
                        "Web Access",
                        random.choice(self.ip_addresses),
                        "10.0.1.5", # Web Server
                        "Anonymous",
                        {"method": "GET", "url": "/index.html", "status": 200, "user_agent": "Mozilla/5.0"}
                    )
                    
                self.siem.process_log(db, log)
        finally:
            db.close()
            
    def generate_attack_sequence(self):
        db = SessionLocal()
        try:
            attack_type = random.choice(["brute_force", "impossible_travel", "ransomware", "lateral_movement", "exfiltration"])
            target_host = random.choice(self.hosts)
            attacker_ip = random.choice(self.attack_ips)
            target_user = random.choice(self.users)
            
            if attack_type == "brute_force":
                for _ in range(7): # Trigger brute force rule (>5)
                    log = self._create_log("Windows Event", attacker_ip, target_host, target_user, {"event_id": 4625, "message": "Failed Logon"})
                    self.siem.process_log(db, log)
                    
            elif attack_type == "impossible_travel":
                log1 = self._create_log("VPN Login", "203.0.113.5", "10.0.0.1", target_user, {"location": "New York, USA", "status": "Success"})
                self.siem.process_log(db, log1)
                log2 = self._create_log("VPN Login", "185.12.33.44", "10.0.0.1", target_user, {"location": "Moscow, Russia", "status": "Success"})
                self.siem.process_log(db, log2)
                
            elif attack_type == "ransomware":
                for _ in range(25): # High threshold of file modifications
                    log = self._create_log("EDR Event", target_host, "Local", target_user, {"action": "file_write", "file": f"C:\\Users\\{target_user}\\Documents\\file_{random.randint(1,100)}.txt.enc", "process": "unknown.exe"})
                    self.siem.process_log(db, log)
                    
            elif attack_type == "lateral_movement":
                log1 = self._create_log("Windows Event", target_host, "Local", target_user, {"event_id": 4624, "message": "Logon"})
                self.siem.process_log(db, log1)
                log2 = self._create_log("EDR Event", target_host, "Local", "System", {"action": "process_creation", "process": "psexec.exe", "command_line": f"psexec \\\\10.0.2.100 cmd.exe"})
                self.siem.process_log(db, log2)
                
            elif attack_type == "exfiltration":
                for _ in range(5):
                    log = self._create_log("Firewall", target_host, attacker_ip, target_user, {"action": "allow", "port": 443, "bytes_out": 10485760}) # 10MB per log
                    self.siem.process_log(db, log)
                    
        finally:
            db.close()

# Global instance to be started in main.py
log_generator = LogGenerator()
