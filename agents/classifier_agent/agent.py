"""
Classifier Agent - Classifies alerts into attack types using a lightweight PyTorch MLP.

Consumes alerts.raw, classifies attack type, maps MITRE ATT&CK techniques,
and publishes to alerts.classified.
"""
from __future__ import annotations
import json
import logging
from typing import Any
from agents.base_agent import BaseAgent, Alert

logger = logging.getLogger(__name__)

ATTACK_CLASSES = [
    "phishing", "credential_theft", "http_exploitation",
    "ransomware", "lateral_movement", "insider_threat", "reconnaissance",
]

MITRE_MAPPING = {
    "phishing": {"tactic": "Initial Access", "technique": "T1566"},
    "credential_theft": {"tactic": "Credential Access", "technique": "T1110"},
    "http_exploitation": {"tactic": "Initial Access", "technique": "T1190"},
    "ransomware": {"tactic": "Impact", "technique": "T1486"},
    "lateral_movement": {"tactic": "Lateral Movement", "technique": "T1021"},
    "insider_threat": {"tactic": "Collection", "technique": "T1005"},
    "reconnaissance": {"tactic": "Reconnaissance", "technique": "T1046"},
}

# Alert type to attack class mapping for rule-based fallback
RULE_MAPPING = {
    "phishing_email": "phishing",
    "credential_stuffing": "credential_theft",
    "brute_force_attempt": "credential_theft",
    "sql_injection": "http_exploitation",
    "path_traversal": "http_exploitation",
    "ransomware_activity": "ransomware",
    "ransomware_encryption": "ransomware",
    "suspicious_process": "lateral_movement",
    "privilege_escalation": "lateral_movement",
    "port_scan": "reconnaissance",
    "bulk_data_download": "insider_threat",
    "unauthorized_sensitive_access": "insider_threat",
    "high_volume_transfer": "insider_threat",
    "unusual_login_time": "credential_theft",
}


class ClassifierAgent(BaseAgent):
    def __init__(self, **kwargs):
        super().__init__(agent_name="classifier_agent", **kwargs)
        self._model = None
        self._model_loaded = False

    def get_subscribed_topics(self) -> list[str]:
        return ["alerts.raw"]

    def initialize(self) -> None:
        super().initialize()
        self._load_model()

    def _load_model(self) -> None:
        """Load or train the MLP classifier."""
        try:
            from agents.classifier_agent.model import AttackClassifierMLP
            self._model = AttackClassifierMLP()
            self._model.train_on_synthetic_data()
            self._model_loaded = True
            logger.info("Classifier MLP model loaded")
        except Exception as e:
            logger.warning("Could not load ML model, using rule-based: %s", e)
            self._model_loaded = False

    def analyze(self, event: dict[str, Any]) -> list[Alert]:
        """Classify an incoming raw alert and publish to alerts.classified."""
        alert_type = event.get("alert_type", "unknown")
        confidence = event.get("confidence", 0.5)

        # Classify using ML model or rule-based fallback
        if self._model_loaded and self._model:
            features = self._extract_features(event)
            predicted_class, ml_confidence = self._model.predict(features)
            attack_class = ATTACK_CLASSES[predicted_class] if predicted_class < len(ATTACK_CLASSES) else "unknown"
            final_confidence = (confidence + ml_confidence) / 2
        else:
            attack_class = RULE_MAPPING.get(alert_type, "unknown")
            final_confidence = confidence

        mitre = MITRE_MAPPING.get(attack_class, {"tactic": "Unknown", "technique": "Unknown"})

        # Create classified alert
        classified = dict(event)
        classified["attack_class"] = attack_class
        classified["classification_confidence"] = round(final_confidence, 3)
        classified["mitre_tactic"] = mitre["tactic"]
        classified["mitre_technique"] = mitre["technique"]
        classified["classified_by"] = "ml" if self._model_loaded else "rules"

        # Publish to alerts.classified
        if self._producer:
            self._producer.produce("alerts.classified", classified, key=event.get("alert_id", ""))

        return []  # Classifier doesn't generate new alerts

    def _extract_features(self, event: dict[str, Any]) -> list[float]:
        """Extract numerical features from alert for MLP input."""
        severity_map = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
        features = [
            severity_map.get(event.get("severity", "medium"), 0.5),
            event.get("confidence", 0.5),
            len(event.get("evidence", [])) / 10.0,
            len(event.get("recommended_actions", [])) / 10.0,
            1.0 if event.get("source_ip") else 0.0,
            1.0 if event.get("user_id") else 0.0,
            1.0 if event.get("target_ip") else 0.0,
            hash(event.get("alert_type", "")) % 100 / 100.0,  # Alert type encoding
        ]
        return features

    def propose_strategy(self, alert: Alert) -> None:
        return None  # Classifier doesn't propose strategies
