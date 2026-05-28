from __future__ import annotations

import json
from datetime import datetime
from typing import Any


CLASSIFICATIONS = ("NORMAL", "SUSPICIOUS", "DEGRADED", "HIGH_RISK", "CRITICAL")


class OperationalIntelligenceFoundation:
    """Evidence-based operational intelligence.

    This foundation intentionally avoids ML claims. It only classifies events from
    fields Centinela already produces: risk, detection, policy and correlation.
    """

    def normalize_event(self, event: dict[str, Any]) -> dict[str, Any]:
        detection = event.get("detection") if isinstance(event.get("detection"), dict) else {}
        risk = event.get("risk") if isinstance(event.get("risk"), dict) else {}
        policy = event.get("policy") if isinstance(event.get("policy"), dict) else {}
        correlation = event.get("correlation") if isinstance(event.get("correlation"), dict) else {}
        metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}

        threat_detected = bool(detection.get("threat_detected"))
        risk_score = self._number(risk.get("score"))
        risk_level = str(risk.get("level") or "UNKNOWN").upper()
        policy_action = str(policy.get("action") or "UNKNOWN").upper()
        threat_types = detection.get("threat_types") if isinstance(detection.get("threat_types"), list) else []
        correlation_signals = correlation.get("signal_count", 0)

        severity = self._normalize_severity(
            detection.get("severity") or risk_level,
            risk_score,
            policy_action,
            threat_detected,
        )
        category = self._category(event, threat_types, policy_action, threat_detected)
        confidence = self._confidence(event, threat_detected, risk_score, policy_action, correlation_signals)
        classification = self.classify(
            severity=severity,
            risk_score=risk_score,
            policy_action=policy_action,
            threat_detected=threat_detected,
            confidence=confidence,
            correlation_signals=correlation_signals,
        )
        signal_state = self.signal_state(event, confidence, classification)

        return {
            "event_id": event.get("id") or "unknown",
            "source": event.get("source") or metadata.get("source") or "centinela.pipeline",
            "timestamp": event.get("timestamp") or datetime.utcnow().isoformat(),
            "severity": severity,
            "category": category,
            "confidence": confidence,
            "origin": {
                "agent": event.get("agent") or "unknown",
                "user": event.get("user") or event.get("user_id") or "unknown",
                "model": event.get("model") or "unknown",
                "session_id": event.get("session_id") or "unknown",
            },
            "operational_impact": self._operational_impact(classification, policy_action, correlation_signals),
            "security_impact": self._security_impact(threat_detected, threat_types, risk_score),
            "risk_evidence": {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "threat_detected": threat_detected,
                "threat_types": threat_types,
                "policy_action": policy_action,
                "correlation_signal_count": correlation_signals,
            },
            "classification": classification,
            "signal_state": signal_state,
            "evidence_basis": self._evidence_basis(
                event,
                risk_score,
                threat_detected,
                policy_action,
                correlation_signals,
            ),
        }

    def classify(
        self,
        *,
        severity: str,
        risk_score: float,
        policy_action: str,
        threat_detected: bool,
        confidence: str,
        correlation_signals: int,
    ) -> str:
        if confidence == "INSUFFICIENT":
            return "DEGRADED"
        if severity == "CRITICAL" or policy_action == "BLOCK" or risk_score >= 90:
            return "CRITICAL"
        if severity == "HIGH" or policy_action == "RESTRICT" or risk_score >= 70:
            return "HIGH_RISK"
        if threat_detected or correlation_signals > 0 or risk_score >= 40:
            return "SUSPICIOUS"
        return "NORMAL"

    def signal_state(self, event: dict[str, Any], confidence: str, classification: str) -> str:
        if not event.get("id") and not event.get("content"):
            return "empty_event"
        if confidence == "INSUFFICIENT":
            return "low_confidence"
        if classification == "NORMAL":
            return "noise"
        return "signal"

    def build_snapshot(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        normalized = [self.normalize_event(event) for event in events]
        deduped, duplicate_count = self._dedupe(normalized)
        counts = {name: 0 for name in CLASSIFICATIONS}
        signal_counts = {"signal": 0, "noise": 0, "low_confidence": 0, "empty_event": 0, "duplicate": duplicate_count}

        for event in normalized:
            counts[event["classification"]] = counts.get(event["classification"], 0) + 1
            signal_counts[event["signal_state"]] = signal_counts.get(event["signal_state"], 0) + 1

        return {
            "status": "OPERATIONAL_INTELLIGENCE_BASELINE",
            "data_state": "VERIFIED_FROM_STORED_EVENTS" if events else "INSUFFICIENT_DATA",
            "realtime_claim": False,
            "ml_claim": False,
            "evidence_count": len(events),
            "normalized_event_count": len(normalized),
            "deduplicated_signal_count": len(deduped),
            "classification_counts": counts,
            "signal_noise": signal_counts,
            "events": deduped[:50],
            "limitations": [
                "Snapshot is derived from stored runtime events only.",
                "No machine learning is claimed in Phase 3.1.",
                "UNKNOWN and INSUFFICIENT_DATA states must not be presented as stable intelligence.",
            ],
            "generated_at": datetime.utcnow().isoformat(),
        }

    def event_from_database_row(self, row: Any) -> dict[str, Any]:
        raw = self._parse_json(getattr(row, "raw", None))
        if isinstance(raw, dict):
            return raw
        return {
            "id": getattr(row, "id", None),
            "timestamp": getattr(row, "timestamp", None).isoformat() if getattr(row, "timestamp", None) else None,
            "agent": getattr(row, "agent", None),
            "user": getattr(row, "user_id", None),
            "model": getattr(row, "model", None),
            "content": getattr(row, "content", None),
            "risk": {
                "score": getattr(row, "risk_score", 0) or 0,
                "level": getattr(row, "risk_level", None) or "UNKNOWN",
            },
            "detection": {
                "threat_detected": bool(getattr(row, "threat_detected", False)),
                "threat_types": self._parse_threat_types(getattr(row, "threat_types", "")),
            },
            "policy": {"action": getattr(row, "policy_action", None) or "UNKNOWN"},
        }

    def _dedupe(self, events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
        seen: set[tuple[Any, ...]] = set()
        deduped: list[dict[str, Any]] = []
        duplicates = 0
        for event in events:
            key = (
                event.get("event_id"),
                event.get("category"),
                event.get("origin", {}).get("agent"),
                event.get("classification"),
            )
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)
            deduped.append(event)
        return deduped, duplicates

    def _confidence(
        self,
        event: dict[str, Any],
        threat_detected: bool,
        risk_score: float,
        policy_action: str,
        correlation_signals: int,
    ) -> str:
        evidence_points = 0
        if event.get("id"):
            evidence_points += 1
        if event.get("timestamp"):
            evidence_points += 1
        if event.get("agent") and event.get("agent") != "unknown":
            evidence_points += 1
        if risk_score > 0:
            evidence_points += 1
        if threat_detected:
            evidence_points += 1
        if policy_action not in ("UNKNOWN", ""):
            evidence_points += 1
        if correlation_signals > 0:
            evidence_points += 1
        if evidence_points <= 1:
            return "INSUFFICIENT"
        if evidence_points <= 3:
            return "LOW"
        if evidence_points <= 5:
            return "MEDIUM"
        return "HIGH"

    def _normalize_severity(self, severity: Any, risk_score: float, policy_action: str, threat_detected: bool) -> str:
        value = str(severity or "").upper()
        if value in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            return value
        if policy_action == "BLOCK" or risk_score >= 90:
            return "CRITICAL"
        if policy_action == "RESTRICT" or risk_score >= 70:
            return "HIGH"
        if threat_detected or risk_score >= 40:
            return "MEDIUM"
        return "LOW"

    def _category(self, event: dict[str, Any], threat_types: list[Any], policy_action: str, threat_detected: bool) -> str:
        if threat_types:
            return str(threat_types[0]).upper()
        event_type = str(event.get("type") or "").upper()
        if event_type and event_type != "UNKNOWN":
            return event_type
        if policy_action in {"BLOCK", "RESTRICT"} or threat_detected:
            return "SECURITY_EVENT"
        return "OPERATIONAL_EVENT"

    def _operational_impact(self, classification: str, policy_action: str, correlation_signals: int) -> str:
        if classification == "CRITICAL":
            return "Immediate containment or operator review required."
        if classification == "HIGH_RISK":
            return "Restricted operation; monitor and validate before escalation."
        if classification == "SUSPICIOUS":
            return "Watchlist signal; keep context for correlation."
        if classification == "DEGRADED":
            return "Evidence insufficient; do not treat as stable intelligence."
        if correlation_signals > 0:
            return "Correlation present; monitor for pattern growth."
        return "No operational action required from current evidence."

    def _security_impact(self, threat_detected: bool, threat_types: list[Any], risk_score: float) -> str:
        if threat_detected and threat_types:
            return f"Detected security signal: {', '.join(str(t) for t in threat_types[:3])}."
        if risk_score >= 70:
            return "High risk score from existing risk engine."
        if risk_score > 0:
            return "Risk evidence exists but does not meet high-risk threshold."
        return "No security impact detected from available evidence."

    def _evidence_basis(
        self,
        event: dict[str, Any],
        risk_score: float,
        threat_detected: bool,
        policy_action: str,
        correlation_signals: int,
    ) -> list[str]:
        basis: list[str] = []
        if event.get("id"):
            basis.append("event_id_present")
        if event.get("timestamp"):
            basis.append("timestamp_present")
        if event.get("agent") and event.get("agent") != "unknown":
            basis.append("agent_present")
        if risk_score > 0:
            basis.append("risk_score_from_risk_engine")
        if threat_detected:
            basis.append("threat_detection_positive")
        if policy_action not in ("UNKNOWN", ""):
            basis.append("policy_action_present")
        if correlation_signals > 0:
            basis.append("correlation_signals_present")
        if not basis:
            basis.append("insufficient_evidence")
        return basis

    def _number(self, value: Any) -> float:
        try:
            return float(value or 0)
        except (TypeError, ValueError):
            return 0.0

    def _parse_json(self, value: Any) -> Any:
        if not value:
            return None
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return None

    def _parse_threat_types(self, value: Any) -> list[str]:
        parsed = self._parse_json(value)
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
        if isinstance(value, str) and value:
            return [item.strip() for item in value.split(",") if item.strip()]
        return []
