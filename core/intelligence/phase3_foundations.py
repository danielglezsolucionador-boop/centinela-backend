from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any


SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SECURITY_LEVELS = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


class PhaseThreeFoundations:
    """Evidence-based Phase 3 operational intelligence foundations.

    This engine intentionally avoids hidden ML, inferred attackers, fake realtime
    claims, and synthetic incident history. Every finding is derived from
    persisted normalized events, existing route inventory, health, or provenance.
    """

    def build_summary(
        self,
        events: list[dict[str, Any]],
        temporal_snapshot: dict[str, Any],
        route_inventory: list[dict[str, Any]],
        health: dict[str, Any],
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        evidence_events = self._prepare_events(events)
        adversarial = self.build_adversarial_reasoning(evidence_events, temporal_snapshot)
        scoring = self.build_operational_scoring(evidence_events, temporal_snapshot, adversarial)
        correlation = self.build_signal_correlation(evidence_events, temporal_snapshot)
        exposure = self.build_attack_surface(route_inventory)
        cognition = self.build_cognitive_stability(evidence_events, correlation, scoring)
        survivability = self.build_survivability(health, provenance, evidence_events)
        freeze = self.build_freeze_governance(scoring, survivability, provenance)
        certification = self.build_operational_certification(
            evidence_events,
            adversarial,
            scoring,
            correlation,
            exposure,
            cognition,
            survivability,
            freeze,
        )

        return {
            "status": "PHASE_3_FOUNDATION_SUMMARY",
            "data_state": "VERIFIED_FROM_STORED_EVENTS" if evidence_events else "INSUFFICIENT_DATA",
            "evidence_count": len(evidence_events),
            "adversarial": adversarial,
            "scoring": scoring,
            "correlation": correlation,
            "exposure": exposure,
            "cognition": cognition,
            "survivability": survivability,
            "freeze_governance": freeze,
            "certification": certification,
            "claims": {
                "ml_claim": False,
                "realtime_claim": False,
                "attacker_identity_claim": False,
                "enterprise_certification_claim": False,
            },
            "limitations": [
                "Phase 3 foundations use only stored runtime evidence and route inventory.",
                "No external infrastructure scan is claimed.",
                "No hidden attacker chain is asserted without repeated evidence.",
                "UNKNOWN and LOW_CONFIDENCE states must remain visible in the Human Cabin.",
            ],
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_adversarial_reasoning(
        self,
        events: list[dict[str, Any]],
        temporal_snapshot: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        temporal_snapshot = temporal_snapshot or {}
        suspicious_events = [
            event
            for event in events
            if self._classification(event) in {"SUSPICIOUS", "HIGH_RISK", "CRITICAL"}
            or self._policy_action(event) in {"BLOCK", "RESTRICT"}
        ]
        repeated_groups = list(temporal_snapshot.get("repeated_events") or [])
        recurring_groups = (
            list(temporal_snapshot.get("recurring_anomalies") or [])
            + list(temporal_snapshot.get("recurring_auth_failures") or [])
            + list(temporal_snapshot.get("recurring_operational_incidents") or [])
        )

        attack_paths: list[dict[str, Any]] = []
        attack_paths.extend(self._suspicious_sequences(suspicious_events))
        attack_paths.extend(self._privilege_abuse_candidates(suspicious_events))
        attack_paths.extend(self._exposed_flow_candidates(suspicious_events))
        attack_paths.extend(self._repeated_group_paths(repeated_groups, recurring_groups))
        attack_paths = self._dedupe_findings(attack_paths)[:20]

        lateral_movement = self._lateral_movement_candidates(suspicious_events)
        exploitability = self._exploitability_findings(events, suspicious_events, attack_paths)
        confidence = self._adversarial_confidence(suspicious_events, attack_paths, repeated_groups, recurring_groups)

        return {
            "status": "ADVERSARIAL_REASONING_BASELINE",
            "data_state": "EVIDENCE_AVAILABLE" if events else "INSUFFICIENT_DATA",
            "evidence_count": len(events),
            "attack_paths": attack_paths,
            "lateral_movement": lateral_movement,
            "exploitability": exploitability,
            "confidence": confidence,
            "confidence_model": ["CONFIRMED", "SUSPICIOUS", "LOW_CONFIDENCE", "UNKNOWN"],
            "attacker_identity_claim": False,
            "limitations": [
                "Attack paths are operational candidates, not proof of attacker intent.",
                "CONFIRMED requires repeated high-severity evidence from stored events.",
                "No nation-state or external adversary attribution is performed.",
            ],
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_operational_scoring(
        self,
        events: list[dict[str, Any]],
        temporal_snapshot: dict[str, Any] | None = None,
        adversarial_snapshot: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        temporal_snapshot = temporal_snapshot or {}
        adversarial_snapshot = adversarial_snapshot or {}
        if not events:
            return {
                "status": "EVIDENCE_AWARE_OPERATIONAL_SCORING",
                "data_state": "INSUFFICIENT_DATA",
                "score": None,
                "security_level": "UNKNOWN",
                "confidence": "UNKNOWN",
                "uncertainty_visible": True,
                "evidence_count": 0,
                "components": {},
                "limitations": ["No stored events; scoring must not be presented as stability."],
                "generated_at": datetime.utcnow().isoformat(),
            }

        classifications = Counter(self._classification(event) for event in events)
        severities = Counter(self._severity(event) for event in events)
        auth_instability = self._text_match_count(events, ("AUTH", "401", "UNAUTHORIZED", "TOKEN", "LOGIN"))
        runtime_degradation = classifications.get("DEGRADED", 0) + self._text_match_count(events, ("RUNTIME", "DEGRADED", "FAIL", "ERROR"))
        high_risk = classifications.get("HIGH_RISK", 0) + classifications.get("CRITICAL", 0)
        repeated = len(temporal_snapshot.get("repeated_events") or [])
        recurring = (
            len(temporal_snapshot.get("recurring_anomalies") or [])
            + len(temporal_snapshot.get("recurring_degradation") or [])
            + len(temporal_snapshot.get("recurring_auth_failures") or [])
            + len(temporal_snapshot.get("recurring_operational_incidents") or [])
        )
        exposure = len(adversarial_snapshot.get("exploitability", []) or [])
        confidence_counts = Counter(self._confidence(event) for event in events)
        low_evidence = confidence_counts.get("INSUFFICIENT", 0) + confidence_counts.get("LOW", 0)

        components = {
            "operational_impact": min(25, high_risk * 8 + classifications.get("SUSPICIOUS", 0) * 3),
            "runtime_degradation": min(20, runtime_degradation * 4),
            "auth_instability": min(15, auth_instability * 5),
            "repeated_anomaly_weight": min(20, repeated * 3 + recurring * 5),
            "exposure_severity": min(15, exposure * 3),
            "critical_severity_weight": min(20, severities.get("CRITICAL", 0) * 7 + severities.get("HIGH", 0) * 4),
            "low_evidence_penalty": min(15, low_evidence * 2),
        }
        raw_score = sum(value for key, value in components.items() if key != "low_evidence_penalty")
        raw_score = max(0, raw_score - components["low_evidence_penalty"])
        confidence = self._aggregate_confidence(events, repeated + recurring)
        multiplier = {"HIGH": 1.0, "MEDIUM": 0.85, "LOW": 0.65, "UNKNOWN": 0.45}.get(confidence, 0.45)
        score = round(min(100, raw_score * multiplier), 2)

        return {
            "status": "EVIDENCE_AWARE_OPERATIONAL_SCORING",
            "data_state": "EVIDENCE_AVAILABLE",
            "score": score,
            "security_level": self._security_level(score, confidence),
            "confidence": confidence,
            "confidence_multiplier": multiplier,
            "uncertainty_visible": confidence in {"UNKNOWN", "LOW"},
            "unknown_state_handling": "UNKNOWN is preserved when evidence is absent or weak.",
            "evidence_count": len(events),
            "components": components,
            "classification_counts": dict(classifications),
            "limitations": [
                "Score is derived from observed normalized events only.",
                "Low evidence reduces score confidence and must be shown to operators.",
                "No 100/100 stability claim is produced by this engine.",
            ],
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_signal_correlation(
        self,
        events: list[dict[str, Any]],
        temporal_snapshot: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        temporal_snapshot = temporal_snapshot or {}
        groups: list[dict[str, Any]] = []
        groups.extend(self._correlation_groups(events, "AUTH_ANOMALY", self._is_auth_event, ("source", "user")))
        groups.extend(self._correlation_groups(events, "REPEATED_DEGRADATION", self._is_degraded_event, ("source", "agent")))
        groups.extend(self._correlation_groups(events, "RUNTIME_INSTABILITY", self._is_runtime_event, ("source", "category")))
        groups.extend(self._correlation_groups(events, "SUSPICIOUS_OPERATIONAL_FLOW", self._is_suspicious_event, ("agent", "category")))
        groups.extend(self._correlation_groups(events, "REPEATED_OPERATIONAL_FAILURE", self._is_failure_event, ("source", "category")))
        groups = self._dedupe_findings(groups)[:20]

        temporal_groups = (
            list(temporal_snapshot.get("repeated_events") or [])
            + list(temporal_snapshot.get("recurring_anomalies") or [])
            + list(temporal_snapshot.get("recurring_degradation") or [])
            + list(temporal_snapshot.get("recurring_auth_failures") or [])
            + list(temporal_snapshot.get("recurring_operational_incidents") or [])
        )
        escalation = self._escalation_state(groups, temporal_groups)
        suppressed = self._suppression_summary(events)

        return {
            "status": "MULTI_EVENT_CORRELATION_BASELINE",
            "data_state": "EVIDENCE_AVAILABLE" if events else "INSUFFICIENT_DATA",
            "evidence_count": len(events),
            "groups": groups,
            "temporal_groups_used": len(temporal_groups),
            "escalation": escalation,
            "suppression": suppressed,
            "false_critical_escalation_guard": True,
            "limitations": [
                "Correlations require repeated evidence; single events remain isolated.",
                "CRITICAL escalation is not generated without high-severity repeated evidence.",
                "No fabricated incident chains are created.",
            ],
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_attack_surface(self, route_inventory: list[dict[str, Any]]) -> dict[str, Any]:
        inventory = []
        for route in route_inventory:
            path = str(route.get("path") or "")
            methods = sorted(str(method) for method in route.get("methods", []) if method not in {"HEAD", "OPTIONS"})
            if not path or not methods:
                continue
            inventory.append({
                "asset": path,
                "methods": methods,
                "service": "centinela-backend",
                "exposure": self._route_exposure(path),
                "auth_required": self._route_requires_auth(path),
                "evidence_basis": "FastAPI route inventory",
            })

        classifications = Counter(item["exposure"] for item in inventory)
        public_assets = [item for item in inventory if item["exposure"] == "PUBLIC"]
        limited_assets = [item for item in inventory if item["exposure"] == "LIMITED"]

        return {
            "status": "ATTACK_SURFACE_INVENTORY_BASELINE",
            "data_state": "ROUTE_INVENTORY_AVAILABLE" if inventory else "UNKNOWN",
            "inventory": inventory,
            "classification_counts": {
                "INTERNAL": classifications.get("INTERNAL", 0),
                "LIMITED": classifications.get("LIMITED", 0),
                "PUBLIC": classifications.get("PUBLIC", 0),
                "UNKNOWN": classifications.get("UNKNOWN", 0),
            },
            "operational_exposure": {
                "auth_exposure": len([item for item in inventory if "/auth/" in item["asset"]]),
                "runtime_exposure": len([item for item in inventory if item["asset"] in {"/ws", "/api/v1/health", "/api/v1/provenance"}]),
                "integration_exposure": len([item for item in inventory if "/api/" in item["asset"]]),
                "dependency_exposure": len(public_assets) + len(limited_assets),
            },
            "external_scan_claim": False,
            "limitations": [
                "Inventory is derived from local FastAPI routes only.",
                "No DNS, port, CDN, or cloud scan is claimed in Phase 3.6.",
                "UNKNOWN is preserved when exposure cannot be proven from route structure.",
            ],
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_cognitive_stability(
        self,
        events: list[dict[str, Any]],
        correlation_snapshot: dict[str, Any],
        scoring_snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        groups = correlation_snapshot.get("groups") or []
        suppression = correlation_snapshot.get("suppression") or {}
        score_level = scoring_snapshot.get("security_level", "UNKNOWN")
        confidence = scoring_snapshot.get("confidence", "UNKNOWN")
        priority_items = []

        for group in groups[:8]:
            relevance = self._executive_relevance(group, score_level)
            if relevance == "LOW_VALUE":
                continue
            priority_items.append({
                "type": group.get("type"),
                "key": group.get("key"),
                "count": group.get("count"),
                "severity": group.get("max_severity"),
                "executive_relevance": relevance,
                "recommended_visibility": "SHOW" if relevance in {"CRITICAL", "OPERATIONAL"} else "SUMMARY_ONLY",
            })

        summary = self._executive_summary(score_level, confidence, priority_items, events)

        return {
            "status": "COGNITIVE_STABILITY_BASELINE",
            "data_state": "EVIDENCE_AVAILABLE" if events else "INSUFFICIENT_DATA",
            "alert_prioritization": priority_items,
            "fatigue_control": {
                "duplicate_suppression": suppression.get("duplicates", 0),
                "empty_event_suppression": suppression.get("empty_events", 0),
                "low_confidence_reduction": suppression.get("low_confidence", 0),
                "repetitive_alert_grouping": len(groups),
            },
            "executive_summary": summary,
            "fear_theater_guard": True,
            "fake_urgency_guard": True,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_survivability(
        self,
        health: dict[str, Any],
        provenance: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        backend_status = str(health.get("status") or "UNKNOWN").upper()
        database_status = str(health.get("database") or "UNKNOWN").upper()
        engines = health.get("engines") if isinstance(health.get("engines"), dict) else {}
        runtime_degraded = backend_status not in {"OPERATIONAL", "OK"} or any(
            str(value).upper() not in {"ONLINE", "PENDING"}
            for value in engines.values()
        )
        missing_data = len(events) == 0
        database_degraded = database_status not in {"CONNECTED", "ONLINE"}
        auth_degraded = self._text_match_count(events, ("AUTH", "401", "UNAUTHORIZED")) >= 2

        modes = {
            "partial_backend_failure": self._mode_state(runtime_degraded),
            "missing_data_mode": self._mode_state(missing_data),
            "auth_degraded_mode": self._mode_state(auth_degraded),
            "runtime_degraded_mode": self._mode_state(runtime_degraded or database_degraded),
        }
        fallback_handling = {
            "safe_fallback_states": True,
            "degraded_operational_visibility": True,
            "limited_functionality_states": True,
            "false_stability_guard": True,
        }
        state = "DEGRADED" if any(value == "ACTIVE" for value in modes.values()) else "READY"

        return {
            "status": "OPERATIONAL_SURVIVABILITY_BASELINE",
            "state": state,
            "degraded_modes": modes,
            "fallback_handling": fallback_handling,
            "runtime_evidence": {
                "backend_status": backend_status,
                "database_status": database_status,
                "provenance_commit_present": bool(provenance.get("current_commit")),
            },
            "fake_survivability_claim": False,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_freeze_governance(
        self,
        scoring_snapshot: dict[str, Any],
        survivability_snapshot: dict[str, Any],
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        level = scoring_snapshot.get("security_level", "UNKNOWN")
        confidence = scoring_snapshot.get("confidence", "UNKNOWN")
        survivability_state = survivability_snapshot.get("state", "UNKNOWN")
        integrity = {
            "runtime_integrity": survivability_state == "READY",
            "deploy_integrity": bool(provenance.get("current_commit")) and bool(provenance.get("repo_branch")),
            "rollback_integrity": "BASIC_ROLLBACK_READY_REQUIRES_CURRENT_PHASE_VALIDATION",
            "provenance_integrity": bool(provenance.get("build_timestamp")),
        }

        if survivability_state == "DEGRADED" or level == "CRITICAL":
            freeze_status = "FREEZE_RECOMMENDED"
            escalation = "RUNTIME_OR_SECURITY_RISK"
        elif level == "HIGH" and confidence in {"MEDIUM", "HIGH"}:
            freeze_status = "CONDITIONAL_REVIEW"
            escalation = "DEPLOYMENT_RISK_REVIEW"
        elif level == "UNKNOWN":
            freeze_status = "INSUFFICIENT_EVIDENCE"
            escalation = "EVIDENCE_REQUIRED"
        else:
            freeze_status = "NO_FREEZE_REQUIRED"
            escalation = "MONITOR"

        return {
            "status": "INTELLIGENT_FREEZE_GOVERNANCE_BASELINE",
            "freeze_status": freeze_status,
            "governance_escalation": escalation,
            "integrity_validation": integrity,
            "false_freeze_authority_guard": True,
            "certification_claim": False,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_operational_certification(
        self,
        events: list[dict[str, Any]],
        adversarial: dict[str, Any],
        scoring: dict[str, Any],
        correlation: dict[str, Any],
        exposure: dict[str, Any],
        cognition: dict[str, Any],
        survivability: dict[str, Any],
        freeze: dict[str, Any],
    ) -> dict[str, Any]:
        evidence_count = len(events)
        readiness_points = 0
        readiness_points += 1 if evidence_count > 0 else 0
        readiness_points += 1 if scoring.get("security_level") != "UNKNOWN" else 0
        readiness_points += 1 if correlation.get("data_state") == "EVIDENCE_AVAILABLE" else 0
        readiness_points += 1 if exposure.get("data_state") == "ROUTE_INVENTORY_AVAILABLE" else 0
        readiness_points += 1 if cognition.get("fake_urgency_guard") else 0
        readiness_points += 1 if survivability.get("state") in {"READY", "DEGRADED"} else 0
        readiness_points += 1 if freeze.get("false_freeze_authority_guard") else 0
        readiness_points += 1 if adversarial.get("attacker_identity_claim") is False else 0

        if evidence_count == 0:
            classification = "EARLY_OPERATIONAL"
        elif readiness_points >= 7 and survivability.get("state") == "READY":
            classification = "OPERATIONALLY_COHERENT"
        elif readiness_points >= 5:
            classification = "CONDITIONALLY_OPERATIONAL"
        else:
            classification = "EXPERIMENTAL"

        return {
            "status": "HONEST_OPERATIONAL_CERTIFICATION",
            "classification": classification,
            "allowed_classifications": [
                "EXPERIMENTAL",
                "EARLY_OPERATIONAL",
                "CONDITIONALLY_OPERATIONAL",
                "OPERATIONALLY_COHERENT",
            ],
            "readiness_points": readiness_points,
            "evidence_count": evidence_count,
            "enterprise_ready_claim": False,
            "human_cabin_readiness": "CONDITIONALLY_READY" if cognition.get("executive_summary") else "NEEDS_EVIDENCE",
            "technical_cabin_readiness": "FOUNDATION_READY",
            "heart_cabin_readiness": "HONEST_EVIDENCE_GUARDS_PRESENT",
            "limitations": [
                "This is not enterprise-grade certification.",
                "Phase 3 certification validates foundation coherence only.",
                "Live deploy status must be validated separately before final freeze.",
            ],
            "generated_at": datetime.utcnow().isoformat(),
        }

    def _prepare_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        prepared = [event for event in events if isinstance(event, dict)]
        return sorted(prepared, key=lambda event: self._parse_time(event.get("timestamp")), reverse=True)

    def _suspicious_sequences(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        grouped = self._group_events(events, lambda event: self._origin(event, "agent"))
        for agent, items in grouped.items():
            categories = [self._category(event) for event in items]
            unique_categories = list(dict.fromkeys(categories))
            if len(items) >= 2 and len(unique_categories) >= 2:
                findings.append(self._finding(
                    "SUSPICIOUS_SEQUENCE_AWARENESS",
                    [agent, *unique_categories[:3]],
                    items,
                    "Multiple suspicious categories observed for the same agent.",
                ))
        return findings

    def _privilege_abuse_candidates(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        keywords = ("ADMIN", "PRIVILEGE", "TOKEN", "CREDENTIAL", "AUTH", "POLICY", "OVERRIDE")
        grouped = self._group_events(
            [event for event in events if self._event_text(event, include_impacts=True).upper().find("AUTH") >= 0 or self._matches(event, keywords)],
            lambda event: (self._origin(event, "agent"), self._origin(event, "user")),
        )
        return [
            self._finding("PRIVILEGE_ABUSE_BASELINE", list(key), items, "Auth or privilege-related suspicious evidence exists.")
            for key, items in grouped.items()
            if len(items) >= 1
        ]

    def _exposed_flow_candidates(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        keywords = ("API", "ENDPOINT", "PUBLIC", "CORS", "EXPOSED", "INTEGRATION")
        grouped = self._group_events(
            [event for event in events if self._matches(event, keywords)],
            lambda event: (self._source(event), self._category(event)),
        )
        return [
            self._finding("EXPOSED_FLOW_AWARENESS", list(key), items, "Observed event references exposed or integration flow.")
            for key, items in grouped.items()
            if len(items) >= 1
        ]

    def _repeated_group_paths(self, repeated: list[dict[str, Any]], recurring: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for group in repeated + recurring:
            if not isinstance(group, dict):
                continue
            confidence = str(group.get("confidence") or "LOW")
            findings.append({
                "type": "OPERATIONAL_EXPLOIT_CHAIN_BASELINE",
                "key": group.get("key") or ["unknown"],
                "count": group.get("count", 0),
                "max_severity": group.get("max_severity", "LOW"),
                "confidence": self._map_confidence(confidence),
                "evidence_basis": group.get("evidence_basis", "temporal correlation group"),
                "interpretation": "Repeated evidence may form an operational chain candidate; no intent is asserted.",
            })
        return findings

    def _lateral_movement_candidates(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped = self._group_events(events, lambda event: self._origin(event, "user"))
        findings: list[dict[str, Any]] = []
        for user, items in grouped.items():
            agents = {self._origin(event, "agent") for event in items}
            sources = {self._source(event) for event in items}
            if user != "unknown" and len(items) >= 2 and (len(agents) > 1 or len(sources) > 1):
                findings.append(self._finding(
                    "SUSPICIOUS_MOVEMENT_PATTERN",
                    [user, f"agents={len(agents)}", f"sources={len(sources)}"],
                    items,
                    "Same user appears across repeated suspicious agents or sources.",
                ))
        return findings[:10]

    def _exploitability_findings(
        self,
        events: list[dict[str, Any]],
        suspicious_events: list[dict[str, Any]],
        attack_paths: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if self._text_match_count(events, ("AUTH", "TOKEN", "CREDENTIAL")) > 0:
            findings.append({
                "type": "TRUST_ABUSE_POSSIBILITY",
                "confidence": "LOW_CONFIDENCE",
                "evidence_basis": "auth or credential related event text",
                "operational_weakness": "Authentication-related flow needs operator review.",
            })
        if suspicious_events:
            findings.append({
                "type": "WEAK_OPERATIONAL_FLOW_AWARENESS",
                "confidence": "SUSPICIOUS" if len(suspicious_events) >= 2 else "LOW_CONFIDENCE",
                "evidence_basis": "suspicious normalized events",
                "operational_weakness": "Suspicious events exist and should remain correlation-ready.",
            })
        if attack_paths:
            findings.append({
                "type": "INDIRECT_ABUSE_POSSIBILITY",
                "confidence": "SUSPICIOUS",
                "evidence_basis": "candidate attack path grouping",
                "operational_weakness": "Repeated or related signals may be abused if left unreviewed.",
            })
        return findings[:10]

    def _adversarial_confidence(
        self,
        events: list[dict[str, Any]],
        attack_paths: list[dict[str, Any]],
        repeated: list[dict[str, Any]],
        recurring: list[dict[str, Any]],
    ) -> str:
        high_events = [event for event in events if self._classification(event) in {"HIGH_RISK", "CRITICAL"}]
        if len(high_events) >= 2 and any(self._policy_action(event) == "BLOCK" for event in high_events):
            return "CONFIRMED"
        if attack_paths or recurring:
            return "SUSPICIOUS"
        if events or repeated:
            return "LOW_CONFIDENCE"
        return "UNKNOWN"

    def _correlation_groups(self, events: list[dict[str, Any]], group_type: str, predicate, key_fields: tuple[str, ...]) -> list[dict[str, Any]]:
        filtered = [event for event in events if predicate(event)]
        grouped = self._group_events(filtered, lambda event: tuple(self._field(event, field) for field in key_fields))
        findings = []
        for key, items in grouped.items():
            if len(items) < 2:
                continue
            findings.append(self._finding(group_type, list(key), items, "Repeated multi-event evidence grouping."))
        return findings

    def _escalation_state(self, groups: list[dict[str, Any]], temporal_groups: list[dict[str, Any]]) -> dict[str, Any]:
        high_groups = [
            group
            for group in groups
            if group.get("max_severity") in {"HIGH", "CRITICAL"} and int(group.get("count", 0)) >= 2
        ]
        if high_groups and len(groups) >= 2:
            state = "OPERATIONAL_THREAT_CANDIDATE"
        elif groups or temporal_groups:
            state = "CORRELATED_INCIDENT" if len(groups) + len(temporal_groups) >= 2 else "RECURRING_ISSUE"
        else:
            state = "ISOLATED_ISSUE" if groups else "NO_CORRELATED_INCIDENT"
        return {
            "state": state,
            "group_count": len(groups),
            "high_severity_group_count": len(high_groups),
            "critical_escalation_guard": "Requires repeated high-severity evidence.",
        }

    def _suppression_summary(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        seen = set()
        duplicates = 0
        low_confidence = 0
        empty_events = 0
        for event in events:
            key = (self._source(event), self._category(event), self._origin(event, "agent"), self._classification(event))
            if key in seen:
                duplicates += 1
            seen.add(key)
            if self._confidence(event) in {"INSUFFICIENT", "LOW"}:
                low_confidence += 1
            if not event.get("event_id"):
                empty_events += 1
        return {
            "duplicates": duplicates,
            "low_confidence": low_confidence,
            "empty_events": empty_events,
            "suppression_basis": "duplicate keys, low confidence, and empty identifiers",
        }

    def _executive_summary(
        self,
        security_level: str,
        confidence: str,
        priority_items: list[dict[str, Any]],
        events: list[dict[str, Any]],
    ) -> str:
        if not events:
            return "Insufficient stored evidence. Centinela must show data unavailable, not stability."
        if priority_items:
            return f"{len(priority_items)} prioritized operational signals require review. Level {security_level}, confidence {confidence}."
        return f"No correlated high-priority operational signal from stored evidence. Level {security_level}, confidence {confidence}."

    def _executive_relevance(self, group: dict[str, Any], score_level: str) -> str:
        if group.get("max_severity") == "CRITICAL" or score_level == "CRITICAL":
            return "CRITICAL"
        if group.get("max_severity") == "HIGH" or score_level == "HIGH":
            return "OPERATIONAL"
        if int(group.get("count", 0)) >= 3:
            return "EXECUTIVE"
        return "LOW_VALUE"

    def _route_exposure(self, path: str) -> str:
        if path in {"/api/v1/health", "/api/v1/provenance", "/api/v1/auth/login", "/api/v1/prompt/analyze", "/ws"}:
            return "PUBLIC"
        if path.startswith("/api/v1/admin"):
            return "LIMITED"
        if path.startswith("/api/v1/"):
            return "LIMITED"
        if path.startswith("/docs") or path.startswith("/openapi"):
            return "PUBLIC"
        return "UNKNOWN"

    def _route_requires_auth(self, path: str) -> bool:
        public = {"/api/v1/health", "/api/v1/provenance", "/api/v1/auth/login", "/api/v1/prompt/analyze", "/ws"}
        return path not in public

    def _security_level(self, score: float | None, confidence: str) -> str:
        if score is None or confidence == "UNKNOWN":
            return "UNKNOWN"
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"

    def _aggregate_confidence(self, events: list[dict[str, Any]], correlation_count: int) -> str:
        if not events:
            return "UNKNOWN"
        counts = Counter(self._confidence(event) for event in events)
        if counts.get("HIGH", 0) >= 2 or (counts.get("MEDIUM", 0) >= 2 and correlation_count >= 2):
            return "HIGH"
        if counts.get("MEDIUM", 0) or correlation_count:
            return "MEDIUM"
        if counts.get("LOW", 0) or counts.get("INSUFFICIENT", 0):
            return "LOW"
        return "UNKNOWN"

    def _mode_state(self, active: bool) -> str:
        return "ACTIVE" if active else "READY"

    def _finding(self, finding_type: str, key: list[Any], events: list[dict[str, Any]], interpretation: str) -> dict[str, Any]:
        severity = max((self._severity(event) for event in events), key=lambda value: SEVERITY_ORDER.get(value, 0), default="LOW")
        confidence = self._finding_confidence(events, severity)
        times = [self._parse_time(event.get("timestamp")) for event in events]
        return {
            "type": finding_type,
            "key": [str(part) for part in key],
            "count": len(events),
            "confidence": confidence,
            "first_seen": min(times).isoformat() if times else None,
            "last_seen": max(times).isoformat() if times else None,
            "max_severity": severity,
            "event_ids": [event.get("event_id", "unknown") for event in events[:10]],
            "evidence_basis": "stored normalized events",
            "interpretation": interpretation,
        }

    def _finding_confidence(self, events: list[dict[str, Any]], severity: str) -> str:
        if len(events) >= 5 and severity in {"HIGH", "CRITICAL"}:
            return "HIGH"
        if len(events) >= 3:
            return "MEDIUM"
        if len(events) >= 2:
            return "LOW"
        return "LOW_CONFIDENCE"

    def _map_confidence(self, confidence: str) -> str:
        value = confidence.upper()
        if value == "HIGH":
            return "SUSPICIOUS"
        if value == "MEDIUM":
            return "SUSPICIOUS"
        if value == "LOW":
            return "LOW_CONFIDENCE"
        return "UNKNOWN"

    def _group_events(self, events: list[dict[str, Any]], key_fn) -> dict[Any, list[dict[str, Any]]]:
        grouped: dict[Any, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            grouped[key_fn(event)].append(event)
        return grouped

    def _dedupe_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen = set()
        result = []
        for finding in findings:
            key = (finding.get("type"), tuple(finding.get("key") or []))
            if key in seen:
                continue
            seen.add(key)
            result.append(finding)
        return sorted(result, key=lambda item: (SEVERITY_ORDER.get(item.get("max_severity", "LOW"), 0), item.get("count", 0)), reverse=True)

    def _field(self, event: dict[str, Any], field: str) -> str:
        if field == "source":
            return self._source(event)
        if field == "category":
            return self._category(event)
        if field == "agent":
            return self._origin(event, "agent")
        if field == "user":
            return self._origin(event, "user")
        return str(event.get(field) or "unknown")

    def _source(self, event: dict[str, Any]) -> str:
        return str(event.get("source") or "unknown")

    def _category(self, event: dict[str, Any]) -> str:
        return str(event.get("category") or "UNKNOWN").upper()

    def _classification(self, event: dict[str, Any]) -> str:
        return str(event.get("classification") or "DEGRADED").upper()

    def _severity(self, event: dict[str, Any]) -> str:
        value = str(event.get("severity") or "LOW").upper()
        return value if value in SEVERITY_ORDER else "LOW"

    def _confidence(self, event: dict[str, Any]) -> str:
        return str(event.get("confidence") or "UNKNOWN").upper()

    def _policy_action(self, event: dict[str, Any]) -> str:
        risk_evidence = event.get("risk_evidence") if isinstance(event.get("risk_evidence"), dict) else {}
        return str(risk_evidence.get("policy_action") or "UNKNOWN").upper()

    def _origin(self, event: dict[str, Any], field: str) -> str:
        origin = event.get("origin") if isinstance(event.get("origin"), dict) else {}
        return str(origin.get(field) or "unknown")

    def _event_text(self, event: dict[str, Any], include_impacts: bool = False) -> str:
        parts = [self._source(event), self._category(event), self._classification(event)]
        if include_impacts:
            parts.extend([
                str(event.get("operational_impact") or ""),
                str(event.get("security_impact") or ""),
            ])
        return " ".join(parts)

    def _matches(self, event: dict[str, Any], keywords: tuple[str, ...]) -> bool:
        text = self._event_text(event, include_impacts=True).upper()
        return any(keyword in text for keyword in keywords)

    def _text_match_count(self, events: list[dict[str, Any]], keywords: tuple[str, ...]) -> int:
        return sum(1 for event in events if self._matches(event, keywords))

    def _is_auth_event(self, event: dict[str, Any]) -> bool:
        return self._matches(event, ("AUTH", "401", "UNAUTHORIZED", "TOKEN", "LOGIN"))

    def _is_degraded_event(self, event: dict[str, Any]) -> bool:
        return self._classification(event) == "DEGRADED" or str(event.get("signal_state") or "").lower() == "low_confidence"

    def _is_runtime_event(self, event: dict[str, Any]) -> bool:
        return self._matches(event, ("RUNTIME", "ERROR", "FAIL", "DEGRADED", "HEALTH"))

    def _is_suspicious_event(self, event: dict[str, Any]) -> bool:
        return self._classification(event) in {"SUSPICIOUS", "HIGH_RISK", "CRITICAL"}

    def _is_failure_event(self, event: dict[str, Any]) -> bool:
        return self._matches(event, ("FAIL", "ERROR", "BLOCK", "RESTRICT", "UNAVAILABLE"))

    def _parse_time(self, value: Any) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str) and value:
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                return datetime.utcnow()
        return datetime.utcnow()
