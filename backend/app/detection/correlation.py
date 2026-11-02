"""
Sliding-Window Correlation Engine and Alert Cooldown Manager.
Tracks entity state across configurable time windows (IPs, users, ports, exfil volumes)
and handles duplicate suppression / cooldown windows.
"""
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Any, Optional


class CorrelationTracker:
    """Thread-safe correlation tracker for sliding window state and alert cooldowns."""

    def __init__(self):
        self._lock = threading.Lock()
        
        # State tracking structures:
        # (ip, user) -> [(timestamp, event_id)]
        self.failed_logins_by_ip_user: Dict[Tuple[str, str], List[Tuple[datetime, str]]] = {}
        
        # ip -> { username -> [(timestamp, event_id)] }
        self.failed_logins_by_ip: Dict[str, Dict[str, List[Tuple[datetime, str]]]] = {}
        
        # username -> [(timestamp, event_id)]
        self.failed_logins_by_user: Dict[str, List[Tuple[datetime, str]]] = {}
        
        # ip -> { dest_port -> [(timestamp, event_id)] }
        self.ports_accessed_by_ip: Dict[str, Dict[int, List[Tuple[datetime, str]]]] = {}
        
        # ip -> [(timestamp, bytes_sent, event_id)]
        self.bytes_transferred_by_ip: Dict[str, List[Tuple[datetime, int, str]]] = {}
        
        # Cooldown map: (rule_id, entity_key) -> last_alert_time
        self.cooldown_tracker: Dict[Tuple[str, str], datetime] = {}

    def prune_old_records(self, max_age_seconds: int = 600):
        """Cleans up internal buffers for timestamps older than max_age_seconds."""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=max_age_seconds)

        with self._lock:
            # Prune failed logins (ip, user)
            for k in list(self.failed_logins_by_ip_user.keys()):
                self.failed_logins_by_ip_user[k] = [
                    (t, eid) for t, eid in self.failed_logins_by_ip_user[k] if t >= cutoff
                ]
                if not self.failed_logins_by_ip_user[k]:
                    del self.failed_logins_by_ip_user[k]

            # Prune failed logins by ip
            for ip in list(self.failed_logins_by_ip.keys()):
                user_dict = self.failed_logins_by_ip[ip]
                for user in list(user_dict.keys()):
                    user_dict[user] = [(t, eid) for t, eid in user_dict[user] if t >= cutoff]
                    if not user_dict[user]:
                        del user_dict[user]
                if not user_dict:
                    del self.failed_logins_by_ip[ip]

            # Prune failed logins by user
            for u in list(self.failed_logins_by_user.keys()):
                self.failed_logins_by_user[u] = [
                    (t, eid) for t, eid in self.failed_logins_by_user[u] if t >= cutoff
                ]
                if not self.failed_logins_by_user[u]:
                    del self.failed_logins_by_user[u]

            # Prune ports accessed by ip
            for ip in list(self.ports_accessed_by_ip.keys()):
                port_dict = self.ports_accessed_by_ip[ip]
                for p in list(port_dict.keys()):
                    port_dict[p] = [(t, eid) for t, eid in port_dict[p] if t >= cutoff]
                    if not port_dict[p]:
                        del port_dict[p]
                if not port_dict:
                    del self.ports_accessed_by_ip[ip]

            # Prune bytes transferred
            for ip in list(self.bytes_transferred_by_ip.keys()):
                self.bytes_transferred_by_ip[ip] = [
                    (t, b, eid) for t, b, eid in self.bytes_transferred_by_ip[ip] if t >= cutoff
                ]
                if not self.bytes_transferred_by_ip[ip]:
                    del self.bytes_transferred_by_ip[ip]

    # --- Recording and Querying Methods ---

    def record_failed_login(self, ip: Optional[str], username: Optional[str], timestamp: datetime, event_id: str):
        """Records a failed authentication attempt."""
        safe_ip = (ip or "unknown").strip()
        safe_user = (username or "unknown").strip().lower()

        with self._lock:
            # 1. (ip, user)
            key = (safe_ip, safe_user)
            if key not in self.failed_logins_by_ip_user:
                self.failed_logins_by_ip_user[key] = []
            self.failed_logins_by_ip_user[key].append((timestamp, event_id))

            # 2. by ip -> user
            if safe_ip not in self.failed_logins_by_ip:
                self.failed_logins_by_ip[safe_ip] = {}
            if safe_user not in self.failed_logins_by_ip[safe_ip]:
                self.failed_logins_by_ip[safe_ip][safe_user] = []
            self.failed_logins_by_ip[safe_ip][safe_user].append((timestamp, event_id))

            # 3. by user
            if safe_user not in self.failed_logins_by_user:
                self.failed_logins_by_user[safe_user] = []
            self.failed_logins_by_user[safe_user].append((timestamp, event_id))

    def get_failed_logins_for_ip_user(self, ip: str, username: str, window_seconds: int, reference_time: Optional[datetime] = None) -> List[Tuple[datetime, str]]:
        """Returns list of (timestamp, event_id) for specific ip & user within the window."""
        safe_ip = (ip or "unknown").strip()
        safe_user = (username or "unknown").strip().lower()
        now = reference_time or datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)

        with self._lock:
            records = self.failed_logins_by_ip_user.get((safe_ip, safe_user), [])
            return [(t, eid) for t, eid in records if cutoff <= t <= now]

    def get_distinct_failed_users_for_ip(self, ip: str, window_seconds: int, reference_time: Optional[datetime] = None) -> Dict[str, List[str]]:
        """Returns {username: [event_ids]} for failed logins from IP within the window."""
        safe_ip = (ip or "unknown").strip()
        now = reference_time or datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)

        result: Dict[str, List[str]] = {}
        with self._lock:
            user_map = self.failed_logins_by_ip.get(safe_ip, {})
            for user, records in user_map.items():
                eids = [eid for t, eid in records if cutoff <= t <= now]
                if eids:
                    result[user] = eids
        return result

    def get_failed_logins_for_user(self, username: str, window_seconds: int, reference_time: Optional[datetime] = None) -> List[Tuple[datetime, str]]:
        """Returns list of (timestamp, event_id) for specific user within the window."""
        safe_user = (username or "unknown").strip().lower()
        now = reference_time or datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)

        with self._lock:
            records = self.failed_logins_by_user.get(safe_user, [])
            return [(t, eid) for t, eid in records if cutoff <= t <= now]

    def record_network_connection(self, source_ip: Optional[str], dest_port: Optional[int], timestamp: datetime, event_id: str):
        """Records an outbound network connection attempt to a destination port."""
        if not source_ip or dest_port is None:
            return
        safe_ip = source_ip.strip()

        with self._lock:
            if safe_ip not in self.ports_accessed_by_ip:
                self.ports_accessed_by_ip[safe_ip] = {}
            if dest_port not in self.ports_accessed_by_ip[safe_ip]:
                self.ports_accessed_by_ip[safe_ip][dest_port] = []
            self.ports_accessed_by_ip[safe_ip][dest_port].append((timestamp, event_id))

    def get_distinct_ports_for_ip(self, source_ip: str, window_seconds: int, reference_time: Optional[datetime] = None) -> Dict[int, List[str]]:
        """Returns {dest_port: [event_ids]} scanned/accessed by source IP within window."""
        safe_ip = (source_ip or "unknown").strip()
        now = reference_time or datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)

        result: Dict[int, List[str]] = {}
        with self._lock:
            port_map = self.ports_accessed_by_ip.get(safe_ip, {})
            for port, records in port_map.items():
                eids = [eid for t, eid in records if cutoff <= t <= now]
                if eids:
                    result[port] = eids
        return result

    def record_data_transfer(self, source_ip: Optional[str], bytes_sent: int, timestamp: datetime, event_id: str):
        """Records an outbound data volume transfer."""
        if not source_ip or bytes_sent <= 0:
            return
        safe_ip = source_ip.strip()

        with self._lock:
            if safe_ip not in self.bytes_transferred_by_ip:
                self.bytes_transferred_by_ip[safe_ip] = []
            self.bytes_transferred_by_ip[safe_ip].append((timestamp, bytes_sent, event_id))

    def get_total_transfer_for_ip(self, source_ip: str, window_seconds: int, reference_time: Optional[datetime] = None) -> Tuple[int, List[str]]:
        """Returns (total_bytes, [event_ids]) for source IP within window."""
        safe_ip = (source_ip or "unknown").strip()
        now = reference_time or datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)

        total_bytes = 0
        event_ids: List[str] = []
        with self._lock:
            records = self.bytes_transferred_by_ip.get(safe_ip, [])
            for t, b, eid in records:
                if cutoff <= t <= now:
                    total_bytes += b
                    event_ids.append(eid)
        return total_bytes, event_ids

    # --- Duplicate Control & Cooldown Management ---

    def is_in_cooldown(self, rule_id: str, entity_key: str, cooldown_seconds: int) -> bool:
        """Checks if a matching alert was raised recently for the same entity and rule."""
        if cooldown_seconds <= 0:
            return False
        now = datetime.utcnow()
        key = (rule_id, entity_key)

        with self._lock:
            last_alert = self.cooldown_tracker.get(key)
            if last_alert and (now - last_alert).total_seconds() < cooldown_seconds:
                return True
        return False

    def record_alert_fired(self, rule_id: str, entity_key: str):
        """Records that an alert fired for cooldown calculation."""
        key = (rule_id, entity_key)
        with self._lock:
            self.cooldown_tracker[key] = datetime.utcnow()

    def reset(self):
        """Resets all correlation memory (used by demo reset and tests)."""
        with self._lock:
            self.failed_logins_by_ip_user.clear()
            self.failed_logins_by_ip.clear()
            self.failed_logins_by_user.clear()
            self.ports_accessed_by_ip.clear()
            self.bytes_transferred_by_ip.clear()
            self.cooldown_tracker.clear()


# Global tracker singleton
correlation_tracker = CorrelationTracker()

