from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any


class HistoricalMemoryCorrelation:
    """Minimal historical memory and temporal correlation.

    The engine groups persisted normalized events. It does not infer hidden
    intent and does not fabricate history when evidence is absent.
    """

    def build_temporal_snapshot(self, normalized_events: list[dict[str, Any]], retention_days: int = 30) -> dict[str, Any]:
        events = sorted(
            [event for event in normalized_events if isinstance(event, dict)],
            key=lambda event: self._parse_time(event.get("timestamp")),
            reverse=True,
        )
        repeated = self._repeated_events(events)
        recurring_anomalies = self._recurring_anomalies(events)
        recurring_degradation = self._recurring_degradation(events)
        recurring_auth = self._recurring_auth_failures(events)
        recurring_incidents = self._recurring_operational_incidents(events)
        confidence_counts = Counter(group["confidence"] for group in repeated + recurring_anomalies + recurring_degradation + recurring_auth + recurring_incidents)

        return {
            "status": "HISTORICAL_MEMORY_BASELINE",
            "data_state": "PERSISTED_NORMALIZED_EVENTS" if events else "INSUFFICIENT_DATA",
            "retention": {
                "policy": "basic_count_and_age_retention",
                "days": retention_days,
                "max_query_events": 200,
            },
            "evidence_count": len(events),
            "recent_events": events[:20],
            "repeated_events": repeated,
            "recurring_anomalies": recurring_anomalies,
            "recurring_degradation": recurring_degradation,
            "recurring_auth_failures": recurring_auth,
            "recurring_operational_incidents": recurring_incidents,
            "degradation_history_baseline": self._degradation_history(events),
            "correlation_confidence": {
                "UNKNOWN": confidence_counts.get("UNKNOWN", 0),
                "LOW": confidence_counts.get("LOW", 0),
                "MEDIUM": confidence_counts.get("MEDIUM", 0),
                "HIGH": confidence_counts.get("HIGH", 0),
            },
            "ml_claim": False,
            "fake_memory_claim": False,
            "limitations": [
                "Correlation is based only on persisted normalized events.",
                "No hidden attacker intent is inferred in Phase 3.2.",
                "INSUFFICIENT_DATA must not be presented as historical stability.",
            ],
            "generated_at": datetime.utcnow().isoformat(),
        }

    def _repeated_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped = self._group_by(events, lambda event: (
            event.get("source", "unknown"),
            event.get("category", "UNKNOWN"),
            event.get("classification", "UNKNOWN"),
        ))
        return self._groups_to_findings(grouped, "REPEATED_EVENT", minimum=2)

    def _recurring_anomalies(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        anomaly_classes = {"SUSPICIOUS", "HIGH_RISK", "CRITICAL"}
        filtered = [event for event in events if event.get("classification") in anomaly_classes]
        grouped = self._group_by(filtered, lambda event: (
            event.get("origin", {}).get("agent", "unknown"),
            event.get("category", "UNKNOWN"),
        ))
        return self._groups_to_findings(grouped, "RECURRING_ANOMALY", minimum=2)

    def _recurring_degradation(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        filtered = [event for event in events if event.get("classification") == "DEGRADED" or event.get("signal_state") == "low_confidence"]
        grouped = self._group_by(filtered, lambda event: (
            event.get("source", "unknown"),
            event.get("origin", {}).get("agent", "unknown"),
        ))
        return self._groups_to_findings(grouped, "RECURRING_DEGRADATION", minimum=2)

    def _recurring_auth_failures(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        filtered = []
        for event in events:
            text = " ".join([
                str(event.get("category", "")),
                str(event.get("operational_impact", "")),
                str(event.get("security_impact", "")),
            ]).upper()
            if "AUTH" in text or "401" in text or "UNAUTHORIZED" in text:
                filtered.append(event)
        grouped = self._group_by(filtered, lambda event: (
            event.get("source", "unknown"),
            event.get("origin", {}).get("user", "unknown"),
        ))
        return self._groups_to_findings(grouped, "RECURRING_AUTH_FAILURE", minimum=2)

    def _recurring_operational_incidents(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        filtered = [event for event in events if event.get("classification") in {"HIGH_RISK", "CRITICAL"}]
        grouped = self._group_by(filtered, lambda event: (
            event.get("source", "unknown"),
            event.get("severity", "UNKNOWN"),
        ))
        return self._groups_to_findings(grouped, "RECURRING_OPERATIONAL_INCIDENT", minimum=2)

    def _degradation_history(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_day: dict[str, Counter] = defaultdict(Counter)
        for event in events:
            day = self._parse_time(event.get("timestamp")).date().isoformat()
            by_day[day][event.get("classification", "UNKNOWN")] += 1
        return [
            {
                "date": day,
                "degraded": counts.get("DEGRADED", 0),
                "suspicious": counts.get("SUSPICIOUS", 0),
                "high_risk": counts.get("HIGH_RISK", 0),
                "critical": counts.get("CRITICAL", 0),
            }
            for day, counts in sorted(by_day.items(), reverse=True)[:14]
        ]

    def _group_by(self, events: list[dict[str, Any]], key_fn) -> dict[tuple[Any, ...], list[dict[str, Any]]]:
        grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            grouped[key_fn(event)].append(event)
        return grouped

    def _groups_to_findings(self, grouped: dict[tuple[Any, ...], list[dict[str, Any]]], finding_type: str, minimum: int) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for key, events in grouped.items():
            if len(events) < minimum:
                continue
            times = [self._parse_time(event.get("timestamp")) for event in events]
            severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            max_severity = max((str(event.get("severity", "LOW")).upper() for event in events), key=lambda value: severity_order.get(value, 0), default="LOW")
            findings.append({
                "type": finding_type,
                "key": [str(part) for part in key],
                "count": len(events),
                "confidence": self._confidence(len(events), max_severity, min(times), max(times)),
                "first_seen": min(times).isoformat(),
                "last_seen": max(times).isoformat(),
                "max_severity": max_severity,
                "event_ids": [event.get("event_id", "unknown") for event in events[:10]],
                "evidence_basis": "persisted normalized event grouping",
            })
        return sorted(findings, key=lambda item: (item["confidence"], item["count"]), reverse=True)[:20]

    def _confidence(self, count: int, severity: str, first_seen: datetime, last_seen: datetime) -> str:
        if count < 2:
            return "UNKNOWN"
        span_seconds = max(0.0, (last_seen - first_seen).total_seconds())
        if count >= 5 and (severity in {"HIGH", "CRITICAL"} or span_seconds > 60):
            return "HIGH"
        if count >= 3:
            return "MEDIUM"
        return "LOW"

    def _parse_time(self, value: Any) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str) and value:
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                return datetime.utcnow()
        return datetime.utcnow()
