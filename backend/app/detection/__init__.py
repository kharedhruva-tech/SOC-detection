"""
SIEM Detection Engine Package.
"""
from app.detection.event_normalizer import EventNormalizer, StandardizedEvent, EventValidationError
from app.detection.rule_config import DEFAULT_RULES_CONFIG, CATEGORIES, SEVERITIES
from app.detection.correlation import correlation_tracker
from app.detection.rules import BaseDetectionRule, DetectionMatch
from app.detection.rule_registry import rule_registry
from app.detection.alert_manager import alert_manager
from app.detection.engine import detection_engine
from app.detection.demo_generator import DemoEventGenerator

__all__ = [
    "EventNormalizer",
    "StandardizedEvent",
    "EventValidationError",
    "DEFAULT_RULES_CONFIG",
    "CATEGORIES",
    "SEVERITIES",
    "correlation_tracker",
    "BaseDetectionRule",
    "DetectionMatch",
    "rule_registry",
    "alert_manager",
    "detection_engine",
    "DemoEventGenerator",
]

