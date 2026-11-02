"""
SIEM Rule Registry.
Manages rule lifecycle, database synchronization, in-memory instances,
and dynamic reconfiguration.
"""
from typing import Dict, List, Optional, Any, Type
from sqlalchemy.orm import Session
from datetime import datetime

from app.models.models import DetectionRule
from app.detection.rule_config import DEFAULT_RULES_CONFIG
from app.detection.rules import (
    BaseDetectionRule,
    BruteForceRule,
    PasswordSprayingRule,
    MultipleFailedLoginRule,
    UnusualLoginTimeRule,
    PrivilegeEscalationRule,
    SuspiciousFileActivityRule,
    MalwareIndicatorRule,
    PortScanRule,
    DataExfiltrationRule,
    UnexpectedAccountCreationRule,
)

RULE_CLASS_MAP: Dict[str, Type[BaseDetectionRule]] = {
    "BR-001": BruteForceRule,
    "PS-002": PasswordSprayingRule,
    "LF-003": MultipleFailedLoginRule,
    "UL-004": UnusualLoginTimeRule,
    "PE-005": PrivilegeEscalationRule,
    "FA-006": SuspiciousFileActivityRule,
    "MD-007": MalwareIndicatorRule,
    "PS-008": PortScanRule,
    "DE-009": DataExfiltrationRule,
    "AC-010": UnexpectedAccountCreationRule,
}


class RuleRegistry:
    """Central registry holding active detection rule instances."""

    def __init__(self):
        self._rules: Dict[str, BaseDetectionRule] = {}
        self._load_defaults()

    def _load_defaults(self):
        """Initializes all 10 rule classes with their default configurations."""
        for cfg in DEFAULT_RULES_CONFIG:
            rule_id = cfg["rule_id"]
            rule_cls = RULE_CLASS_MAP.get(rule_id)
            if rule_cls:
                instance = rule_cls(
                    rule_id=rule_id,
                    name=cfg["name"],
                    category=cfg["category"],
                    severity=cfg["severity"],
                    description=cfg["description"],
                    mitre_tactics=cfg.get("mitre_tactics", []),
                    mitre_techniques=cfg.get("mitre_techniques", []),
                    enabled=cfg.get("enabled", True),
                    configuration=dict(cfg.get("configuration", {})),
                )
                self._rules[rule_id] = instance

    def get_all_rules(self) -> List[BaseDetectionRule]:
        """Returns all registered detection rule objects."""
        return list(self._rules.values())

    def get_rule(self, rule_id: str) -> Optional[BaseDetectionRule]:
        """Retrieves a rule instance by its ID."""
        return self._rules.get(rule_id.upper())

    def seed_database(self, db: Session):
        """Seeds default detection rules into database if not present."""
        for cfg in DEFAULT_RULES_CONFIG:
            existing = db.query(DetectionRule).filter(DetectionRule.rule_id == cfg["rule_id"]).first()
            if not existing:
                new_rule = DetectionRule(
                    rule_id=cfg["rule_id"],
                    name=cfg["name"],
                    description=cfg["description"],
                    category=cfg["category"],
                    severity=cfg["severity"],
                    enabled=cfg.get("enabled", True),
                    configuration=cfg.get("configuration", {}),
                    mitre_tactics=cfg.get("mitre_tactics", []),
                    mitre_techniques=cfg.get("mitre_techniques", []),
                    total_detections=0,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                db.add(new_rule)
        db.commit()

    def sync_from_database(self, db: Session):
        """Updates in-memory rule instances with custom configurations stored in DB."""
        db_rules = db.query(DetectionRule).all()
        for dbr in db_rules:
            if dbr.rule_id in self._rules:
                rule = self._rules[dbr.rule_id]
                rule.enabled = dbr.enabled
                rule.severity = dbr.severity
                if dbr.configuration:
                    rule.config = dict(dbr.configuration)

    def update_rule(self, db: Session, rule_id: str, enabled: Optional[bool] = None,
                    configuration: Optional[Dict[str, Any]] = None,
                    severity: Optional[str] = None) -> Optional[DetectionRule]:
        """Updates a rule's enabled status, severity, and configuration in DB and memory."""
        clean_id = rule_id.upper()
        db_rule = db.query(DetectionRule).filter(DetectionRule.rule_id == clean_id).first()
        if not db_rule:
            return None

        if enabled is not None:
            db_rule.enabled = enabled
        if severity is not None:
            db_rule.severity = severity
        if configuration is not None:
            # Merge with existing config
            current_config = dict(db_rule.configuration or {})
            current_config.update(configuration)
            db_rule.configuration = current_config

        db_rule.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(db_rule)

        # Update in-memory instance
        if clean_id in self._rules:
            mem_rule = self._rules[clean_id]
            if enabled is not None:
                mem_rule.enabled = enabled
            if severity is not None:
                mem_rule.severity = severity
            if configuration is not None:
                mem_rule.config.update(configuration)

        return db_rule

    def increment_detection(self, db: Session, rule_id: str):
        """Increments detection counter and updates last_triggered_at timestamp."""
        clean_id = rule_id.upper()
        db_rule = db.query(DetectionRule).filter(DetectionRule.rule_id == clean_id).first()
        if db_rule:
            db_rule.total_detections = (db_rule.total_detections or 0) + 1
            db_rule.last_triggered_at = datetime.utcnow()
            db.commit()


# Singleton rule registry
rule_registry = RuleRegistry()

