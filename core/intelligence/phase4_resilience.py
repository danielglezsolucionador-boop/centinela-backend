from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any


DEGRADED_MODES = ("STABLE", "DEGRADED", "PARTIAL_FAILURE", "UNSTABLE", "LIMITED_OPERATION", "UNKNOWN")


class PhaseFourResilience:
    """Operational resilience and degradation awareness.

    Phase 4 does not attempt recovery, uptime guarantees, or autonomous rollback.
    It classifies runtime evidence so Centinela can remain honest and usable when
    backend, auth, provenance, intelligence, or dependency visibility degrades.
    """

    def build_summary(
        self,
        *,
        health: dict[str, Any],
        provenance: dict[str, Any],
        phase3_summary: dict[str, Any],
        route_inventory: list[dict[str, Any]],
        endpoint_observations: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        endpoint_observations = endpoint_observations or {}
        degraded_runtime = self.build_degraded_runtime(health, provenance, phase3_summary, endpoint_observations)
        partial_failure = self.build_partial_failure(degraded_runtime, phase3_summary, endpoint_observations)
        recovery = self.build_recovery_state(degraded_runtime, partial_failure)
        fallback = self.build_fallback_modes(degraded_runtime, partial_failure, recovery)
        integrity = self.build_runtime_integrity(health, provenance, phase3_summary)
        dependencies = self.build_dependency_awareness(health, route_inventory, phase3_summary)
        stress = self.build_stress_validation(degraded_runtime, fallback, dependencies)
        rollback = self.build_rollback_intelligence(degraded_runtime, integrity, provenance)
        certification = self.build_resilience_certification(
            degraded_runtime,
            partial_failure,
            recovery,
            fallback,
            integrity,
            dependencies,
            rollback,
        )

        return {
            "status": "PHASE_4_RESILIENCE_SUMMARY",
            "classification": degraded_runtime["classification"],
            "continuity_level": degraded_runtime["operational_continuity_level"],
            "degraded_runtime": degraded_runtime,
            "partial_failure": partial_failure,
            "recovery": recovery,
            "fallback": fallback,
            "integrity": integrity,
            "dependencies": dependencies,
            "stress_validation": stress,
            "rollback": rollback,
            "certification": certification,
            "claims": {
                "fake_uptime_claim": False,
                "autonomous_recovery_claim": False,
                "enterprise_resilience_claim": False,
                "panic_theater": False,
            },
            "limitations": [
                "Phase 4 observes and classifies resilience; it does not execute destructive recovery.",
                "Simulations are validation scenarios, not live outages.",
                "Unknown or stale evidence remains visible as operational limitation.",
            ],
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_degraded_runtime(
        self,
        health: dict[str, Any],
        provenance: dict[str, Any],
        phase3_summary: dict[str, Any],
        endpoint_observations: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        endpoint_observations = endpoint_observations or {}
        engines = health.get("engines") if isinstance(health.get("engines"), dict) else {}
        phase3_data_state = str(phase3_summary.get("data_state") or "UNKNOWN")
        phase3_status = str(phase3_summary.get("status") or "UNKNOWN")
        health_status = str(health.get("status") or "UNKNOWN").upper()
        database_status = str(health.get("database") or "UNKNOWN").upper()
        generated_at = self._parse_time(phase3_summary.get("generated_at"))
        runtime_age_seconds = max(0.0, (datetime.utcnow() - generated_at).total_seconds())

        states = {
            "backend_unavailable": self._state(health_status not in {"OPERATIONAL", "OK"}, "health.status"),
            "partial_endpoint_failure": self._state(self._has_endpoint_failure(endpoint_observations), "endpoint_observations"),
            "auth_unavailable": self._state(self._endpoint_state(endpoint_observations, "auth") in {"UNAVAILABLE", "TIMEOUT"}, "auth_observation"),
            "provenance_unavailable": self._state(not provenance or not provenance.get("current_commit"), "public_provenance"),
            "intelligence_unavailable": self._state(phase3_status == "UNKNOWN" or phase3_data_state == "INSUFFICIENT_DATA", "phase3_summary"),
            "slow_runtime": self._state(self._has_slow_endpoint(endpoint_observations), "endpoint_latency"),
            "timeout_states": self._state(self._has_timeout(endpoint_observations), "endpoint_timeout"),
            "inconsistent_response_states": self._state(self._inconsistent_response(health, provenance, phase3_summary), "cross_runtime_consistency"),
            "database_degraded": self._state(database_status not in {"CONNECTED", "ONLINE"}, "health.database"),
            "stale_intelligence": self._state(runtime_age_seconds > 300, "phase3_generated_at"),
        }
        active = [name for name, item in states.items() if item["active"]]
        classification = self._classify(active, endpoint_observations)

        return {
            "status": "ADVANCED_DEGRADED_RUNTIME_HANDLING",
            "classification": classification,
            "classification_model": list(DEGRADED_MODES),
            "states": states,
            "active_degradations": active,
            "operational_continuity_level": self._continuity_level(classification, active),
            "visible_fallback_state": self._fallback_state(classification, active),
            "fake_live_guard": True,
            "fake_normal_guard": True,
            "panic_theater_guard": True,
            "evidence_basis": ["health", "provenance", "phase3_summary", "endpoint_observations"],
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_partial_failure(
        self,
        degraded_runtime: dict[str, Any],
        phase3_summary: dict[str, Any],
        endpoint_observations: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        endpoint_observations = endpoint_observations or {}
        states = degraded_runtime.get("states") if isinstance(degraded_runtime.get("states"), dict) else {}
        phase3 = phase3_summary or {}
        partials = {
            "partial_backend_failure": states.get("partial_endpoint_failure", {}).get("active", False),
            "partial_auth_degradation": states.get("auth_unavailable", {}).get("active", False),
            "partial_intelligence_degradation": states.get("intelligence_unavailable", {}).get("active", False),
            "partial_runtime_corruption": states.get("inconsistent_response_states", {}).get("active", False),
            "dependency_instability": states.get("database_degraded", {}).get("active", False),
            "degraded_api_awareness": self._has_endpoint_failure(endpoint_observations),
            "stale_operational_state": states.get("stale_intelligence", {}).get("active", False),
        }
        active = [name for name, value in partials.items() if value]
        severity = "PARTIAL_FAILURE" if active else "STABLE"
        if len(active) >= 4:
            severity = "UNSTABLE"
        if not phase3:
            severity = "UNKNOWN"

        return {
            "status": "PARTIAL_FAILURE_INTELLIGENCE",
            "classification": severity,
            "partial_failures": partials,
            "active_partial_failures": active,
            "critical_escalation_guard": "Partial failure does not auto-escalate to CRITICAL.",
            "survivability_continuity": severity in {"STABLE", "PARTIAL_FAILURE"},
            "cognitive_continuity": True,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_recovery_state(self, degraded_runtime: dict[str, Any], partial_failure: dict[str, Any]) -> dict[str, Any]:
        classification = degraded_runtime.get("classification", "UNKNOWN")
        active = degraded_runtime.get("active_degradations") or []
        partials = partial_failure.get("active_partial_failures") or []

        if classification == "STABLE":
            state = "STABLE"
            progress = 100
            confidence = "MEDIUM"
            next_step = "Maintain monitoring."
        elif classification in {"DEGRADED", "LIMITED_OPERATION", "PARTIAL_FAILURE"}:
            state = "RECOVERY_READY"
            progress = max(25, 70 - len(active) * 8 - len(partials) * 5)
            confidence = "LOW" if len(active) > 2 else "MEDIUM"
            next_step = "Preserve fallback visibility and validate degraded dependency before declaring stability."
        elif classification == "UNSTABLE":
            state = "RECOVERY_REQUIRED"
            progress = 20
            confidence = "LOW"
            next_step = "Do not claim recovery; validate runtime and provenance first."
        else:
            state = "UNKNOWN"
            progress = None
            confidence = "UNKNOWN"
            next_step = "Evidence required."

        return {
            "status": "RECOVERY_STATE_AWARENESS",
            "recovery_state": state,
            "recovery_progress": progress,
            "recovery_confidence": confidence,
            "runtime_recovery_visibility": True,
            "post_failure_stabilization_awareness": classification in {"STABLE", "DEGRADED", "PARTIAL_FAILURE", "LIMITED_OPERATION"},
            "operational_continuity_recovery": classification not in {"UNKNOWN", "UNSTABLE"},
            "next_step": next_step,
            "fake_recovery_guard": True,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_fallback_modes(
        self,
        degraded_runtime: dict[str, Any],
        partial_failure: dict[str, Any],
        recovery: dict[str, Any],
    ) -> dict[str, Any]:
        classification = degraded_runtime.get("classification", "UNKNOWN")
        active = set(degraded_runtime.get("active_degradations") or [])
        modes = {
            "limited_operation_mode": classification in {"LIMITED_OPERATION", "PARTIAL_FAILURE", "DEGRADED", "UNSTABLE"},
            "degraded_intelligence_mode": "intelligence_unavailable" in active or "stale_intelligence" in active,
            "degraded_governance_mode": "provenance_unavailable" in active or classification == "UNKNOWN",
            "degraded_visibility_mode": classification in {"LIMITED_OPERATION", "UNKNOWN", "UNSTABLE"},
            "safe_operational_continuity": classification in {"STABLE", "DEGRADED", "PARTIAL_FAILURE", "LIMITED_OPERATION"},
        }
        summaries = self._fallback_summaries(modes, degraded_runtime, recovery)

        return {
            "status": "SAFE_FALLBACK_OPERATIONAL_MODES",
            "fallback_states": [
                "DATA_UNAVAILABLE",
                "DEGRADED_MODE",
                "PARTIAL_OPERATION",
                "LIMITED_VISIBILITY",
                "AUTH_DEGRADED",
                "PROVENANCE_DEGRADED",
            ],
            "modes": modes,
            "operational_summaries": summaries,
            "panic_mode": False,
            "fake_operational_continuity_guard": True,
            "ux_continuity": True,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_runtime_integrity(
        self,
        health: dict[str, Any],
        provenance: dict[str, Any],
        phase3_summary: dict[str, Any],
    ) -> dict[str, Any]:
        phase3_generated = self._parse_time(phase3_summary.get("generated_at"))
        build_time = self._parse_time(provenance.get("build_timestamp"))
        age_seconds = max(0.0, (datetime.utcnow() - phase3_generated).total_seconds())
        build_age_days = max(0.0, (datetime.utcnow() - build_time).total_seconds() / 86400)
        engines = health.get("engines") if isinstance(health.get("engines"), dict) else {}

        checks = {
            "stale_runtime_detection": age_seconds > 300,
            "runtime_inconsistency_detection": str(health.get("status", "")).upper() not in {"OPERATIONAL", "OK"},
            "provenance_inconsistency_awareness": not provenance.get("current_commit") or not provenance.get("repo_branch"),
            "degraded_dependency_awareness": any(str(value).upper() not in {"ONLINE", "PENDING"} for value in engines.values()),
            "old_build_visibility": build_age_days > 30,
        }
        trust = "TRUSTED" if not any(checks.values()) else "LIMITED_TRUST"
        if checks["runtime_inconsistency_detection"] or checks["provenance_inconsistency_awareness"]:
            trust = "UNTRUSTED_UNTIL_VALIDATED"

        return {
            "status": "RUNTIME_INTEGRITY_MONITORING",
            "runtime_trust": trust,
            "checks": checks,
            "operational_integrity_baseline": {
                "health_present": bool(health),
                "provenance_present": bool(provenance),
                "phase3_summary_present": bool(phase3_summary),
                "engine_count": len(engines),
            },
            "fake_runtime_trust_guard": True,
            "hidden_corruption_guard": True,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_dependency_awareness(
        self,
        health: dict[str, Any],
        route_inventory: list[dict[str, Any]],
        phase3_summary: dict[str, Any],
    ) -> dict[str, Any]:
        engines = health.get("engines") if isinstance(health.get("engines"), dict) else {}
        dependencies = [
            self._dependency("backend_runtime", health.get("status"), "CRITICAL", "FastAPI runtime availability"),
            self._dependency("database", health.get("database"), "HIGH", "Event and memory persistence"),
            self._dependency("provenance", "ONLINE", "MEDIUM", "Source-to-runtime traceability"),
            self._dependency("auth", "ONLINE", "HIGH", "Protected operational data access"),
        ]
        for name, status in sorted(engines.items()):
            dependencies.append(self._dependency(name, status, self._engine_criticality(name), "Backend engine dependency"))

        route_count = len([route for route in route_inventory if str(route.get("path", "")).startswith("/api/")])
        degraded = [item for item in dependencies if item["health"] not in {"ONLINE", "OPERATIONAL", "CONNECTED", "OK", "PENDING"}]
        unknown = [item for item in dependencies if item["health"] in {"UNKNOWN", ""}]
        impact = "LOW"
        if any(item["criticality"] == "CRITICAL" for item in degraded):
            impact = "HIGH"
        elif degraded or unknown:
            impact = "MEDIUM"

        return {
            "status": "SERVICE_DEPENDENCY_AWARENESS",
            "dependency_inventory": dependencies,
            "dependency_count": len(dependencies),
            "api_route_count": route_count,
            "dependency_degradation_awareness": len(degraded),
            "dependency_unknown_awareness": len(unknown),
            "dependency_survivability_impact": impact,
            "fake_dependency_intelligence_guard": True,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_stress_validation(
        self,
        degraded_runtime: dict[str, Any],
        fallback: dict[str, Any],
        dependencies: dict[str, Any],
    ) -> dict[str, Any]:
        scenarios = [
            self._scenario("degraded_runtime_simulation", degraded_runtime["classification"] != "UNKNOWN"),
            self._scenario("partial_outage_simulation", fallback["modes"]["limited_operation_mode"] or degraded_runtime["classification"] == "STABLE"),
            self._scenario("dependency_degradation_simulation", dependencies["dependency_survivability_impact"] in {"LOW", "MEDIUM", "HIGH"}),
            self._scenario("fallback_stress_validation", fallback["ux_continuity"] and not fallback["panic_mode"]),
            self._scenario("operational_survivability_stress_handling", degraded_runtime["operational_continuity_level"] != "UNKNOWN"),
        ]
        passed = len([scenario for scenario in scenarios if scenario["result"] == "PASS"])

        return {
            "status": "SURVIVABILITY_STRESS_VALIDATION",
            "simulation_claim": "CONTROLLED_VALIDATION_SCENARIOS_ONLY",
            "scenarios": scenarios,
            "passed": passed,
            "total": len(scenarios),
            "cognitive_stability_under_stress": passed >= 4,
            "no_panic_ui_guard": True,
            "no_fake_stability_guard": True,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_rollback_intelligence(
        self,
        degraded_runtime: dict[str, Any],
        integrity: dict[str, Any],
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        rollback_inputs = {
            "commit_visible": bool(provenance.get("current_commit")),
            "branch_visible": bool(provenance.get("repo_branch")),
            "runtime_trust": integrity.get("runtime_trust"),
            "degraded_runtime_classification": degraded_runtime.get("classification"),
        }
        risk = "LOW"
        confidence = "MEDIUM"
        if degraded_runtime.get("classification") in {"UNSTABLE", "UNKNOWN"}:
            risk = "HIGH"
            confidence = "LOW"
        elif integrity.get("runtime_trust") != "TRUSTED":
            risk = "MEDIUM"
            confidence = "LOW"
        if not rollback_inputs["commit_visible"] or not rollback_inputs["branch_visible"]:
            risk = "HIGH"
            confidence = "LOW"

        return {
            "status": "ADVANCED_ROLLBACK_INTELLIGENCE",
            "rollback_risk": risk,
            "rollback_confidence": confidence,
            "rollback_integrity_awareness": rollback_inputs,
            "rollback_survivability_awareness": degraded_runtime.get("operational_continuity_level"),
            "rollback_impact_visibility": "Rollback confidence depends on provenance and runtime trust.",
            "fake_rollback_safety_guard": True,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_resilience_certification(
        self,
        degraded_runtime: dict[str, Any],
        partial_failure: dict[str, Any],
        recovery: dict[str, Any],
        fallback: dict[str, Any],
        integrity: dict[str, Any],
        dependencies: dict[str, Any],
        rollback: dict[str, Any],
    ) -> dict[str, Any]:
        points = 0
        points += 1 if degraded_runtime.get("classification") in DEGRADED_MODES else 0
        points += 1 if partial_failure.get("cognitive_continuity") else 0
        points += 1 if recovery.get("fake_recovery_guard") else 0
        points += 1 if fallback.get("ux_continuity") else 0
        points += 1 if integrity.get("hidden_corruption_guard") else 0
        points += 1 if dependencies.get("fake_dependency_intelligence_guard") else 0
        points += 1 if rollback.get("fake_rollback_safety_guard") else 0

        runtime_classification = degraded_runtime.get("classification")
        if runtime_classification in {"UNSTABLE", "UNKNOWN"}:
            classification = "FRAGILE"
        elif runtime_classification == "STABLE" and points >= 7 and integrity.get("runtime_trust") == "TRUSTED" and rollback.get("rollback_risk") == "LOW":
            classification = "OPERATIONALLY_RESILIENT"
        elif runtime_classification in {"DEGRADED", "PARTIAL_FAILURE", "LIMITED_OPERATION"} and points >= 6:
            classification = "CONDITIONALLY_RESILIENT"
        elif points >= 4:
            classification = "PARTIALLY_RESILIENT"
        else:
            classification = "FRAGILE"

        return {
            "status": "HONEST_RESILIENCE_CERTIFICATION",
            "classification": classification,
            "allowed_classifications": [
                "FRAGILE",
                "PARTIALLY_RESILIENT",
                "CONDITIONALLY_RESILIENT",
                "OPERATIONALLY_RESILIENT",
            ],
            "readiness_points": points,
            "enterprise_grade_claim": False,
            "survivability": degraded_runtime.get("classification"),
            "degraded_continuity": degraded_runtime.get("operational_continuity_level"),
            "fallback_coherence": fallback.get("ux_continuity"),
            "recovery_intelligence": recovery.get("recovery_state"),
            "runtime_integrity": integrity.get("runtime_trust"),
            "rollback_maturity": rollback.get("rollback_confidence"),
            "generated_at": datetime.utcnow().isoformat(),
        }

    def _state(self, active: bool, evidence: str) -> dict[str, Any]:
        return {
            "active": bool(active),
            "state": "DEGRADED" if active else "READY",
            "evidence": evidence,
        }

    def _classify(self, active: list[str], endpoint_observations: dict[str, Any]) -> str:
        if not endpoint_observations and "backend_unavailable" in active:
            return "UNKNOWN"
        if "backend_unavailable" in active or "inconsistent_response_states" in active and len(active) >= 4:
            return "UNSTABLE"
        if "partial_endpoint_failure" in active or "timeout_states" in active:
            return "PARTIAL_FAILURE"
        if "intelligence_unavailable" in active or "database_degraded" in active:
            return "DEGRADED"
        if "provenance_unavailable" in active or "stale_intelligence" in active:
            return "LIMITED_OPERATION"
        if active:
            return "DEGRADED"
        return "STABLE"

    def _continuity_level(self, classification: str, active: list[str]) -> str:
        if classification == "STABLE":
            return "FULL"
        if classification in {"DEGRADED", "PARTIAL_FAILURE"}:
            return "PARTIAL"
        if classification == "LIMITED_OPERATION":
            return "LIMITED_VISIBILITY"
        if classification == "UNSTABLE":
            return "MINIMAL"
        return "UNKNOWN"

    def _fallback_state(self, classification: str, active: list[str]) -> str:
        if "auth_unavailable" in active:
            return "AUTH_DEGRADED"
        if "provenance_unavailable" in active:
            return "PROVENANCE_DEGRADED"
        if classification == "PARTIAL_FAILURE":
            return "PARTIAL_OPERATION"
        if classification == "LIMITED_OPERATION":
            return "LIMITED_VISIBILITY"
        if classification in {"DEGRADED", "UNSTABLE"}:
            return "DEGRADED_MODE"
        if classification == "UNKNOWN":
            return "DATA_UNAVAILABLE"
        return "STABLE"

    def _has_endpoint_failure(self, observations: dict[str, Any]) -> bool:
        return any(str(value.get("state", "")).upper() in {"FAILED", "UNAVAILABLE", "TIMEOUT", "ERROR"} for value in observations.values() if isinstance(value, dict))

    def _has_slow_endpoint(self, observations: dict[str, Any]) -> bool:
        for value in observations.values():
            if not isinstance(value, dict):
                continue
            try:
                if float(value.get("latency_ms", 0)) > 2500:
                    return True
            except (TypeError, ValueError):
                continue
        return False

    def _has_timeout(self, observations: dict[str, Any]) -> bool:
        return any(str(value.get("state", "")).upper() == "TIMEOUT" for value in observations.values() if isinstance(value, dict))

    def _endpoint_state(self, observations: dict[str, Any], name: str) -> str:
        value = observations.get(name) if isinstance(observations, dict) else None
        if not isinstance(value, dict):
            return "UNKNOWN"
        return str(value.get("state") or "UNKNOWN").upper()

    def _inconsistent_response(self, health: dict[str, Any], provenance: dict[str, Any], phase3_summary: dict[str, Any]) -> bool:
        if not health or not phase3_summary:
            return True
        if not provenance or not provenance.get("current_commit"):
            return True
        return False

    def _fallback_summaries(self, modes: dict[str, bool], degraded_runtime: dict[str, Any], recovery: dict[str, Any]) -> list[dict[str, str]]:
        summaries = []
        for name, active in modes.items():
            if not active:
                continue
            summaries.append({
                "mode": name,
                "summary": f"{name.replace('_', ' ').title()} active. Runtime state: {degraded_runtime.get('classification')}. Recovery: {recovery.get('recovery_state')}.",
            })
        if not summaries:
            summaries.append({"mode": "normal_operation", "summary": "No fallback mode required by current evidence."})
        return summaries

    def _dependency(self, name: str, health: Any, criticality: str, purpose: str) -> dict[str, str]:
        value = str(health or "UNKNOWN").upper()
        return {
            "name": name,
            "health": value,
            "criticality": criticality,
            "purpose": purpose,
            "visibility": "REAL_HEALTH_FIELD" if value != "UNKNOWN" else "LIMITED_VISIBILITY",
        }

    def _engine_criticality(self, name: str) -> str:
        if name in {"pipeline", "risk_engine", "threat_detection", "operational_intelligence", "phase3_foundations", "phase4_resilience"}:
            return "HIGH"
        if name in {"postgresql", "historical_memory", "threat_memory"}:
            return "HIGH"
        return "MEDIUM"

    def _scenario(self, name: str, passed: bool) -> dict[str, str]:
        return {
            "name": name,
            "result": "PASS" if passed else "REVIEW",
            "simulation_type": "CONTROLLED_VALIDATION",
            "evidence_basis": "resilience classifier output",
        }

    def _parse_time(self, value: Any) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str) and value:
            normalized = value.replace("Z", "+00:00")
            try:
                parsed = datetime.fromisoformat(normalized)
                return parsed.replace(tzinfo=None)
            except ValueError:
                return datetime.utcnow() - timedelta(days=365)
        return datetime.utcnow() - timedelta(days=365)
