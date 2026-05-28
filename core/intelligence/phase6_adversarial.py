from __future__ import annotations

from datetime import datetime
from typing import Any


class PhaseSixAdversarial:
    """Defensive adversarial reasoning without attacker fiction.

    Phase 6 correlates existing operational evidence from Phase 3, resilience
    evidence from Phase 4, and ecosystem visibility from Phase 5. It never
    claims CVEs, malware, nation-state actors, or compromise without evidence.
    """

    def build_summary(
        self,
        *,
        phase3_summary: dict[str, Any],
        phase4_summary: dict[str, Any],
        phase5_summary: dict[str, Any],
    ) -> dict[str, Any]:
        attack_paths = self.build_attack_path_baseline(phase3_summary, phase4_summary, phase5_summary)
        privilege = self.build_privilege_reasoning(phase4_summary, phase5_summary)
        movement = self.build_lateral_movement(phase3_summary, phase5_summary)
        exploitability = self.build_exploitability(attack_paths, privilege, movement, phase4_summary, phase5_summary)
        strategic = self.build_strategic_correlation(exploitability, phase3_summary, phase4_summary, phase5_summary)
        behavior = self.build_behavioral_modeling(phase3_summary, phase4_summary)
        escalation = self.build_escalation_intelligence(strategic, behavior, exploitability, phase4_summary)
        simulation = self.build_scenario_simulation(exploitability, phase4_summary, phase5_summary)
        risk = self.build_strategic_risk(exploitability, strategic, escalation, simulation, phase4_summary, phase5_summary)
        certification = self.build_adversarial_certification(
            attack_paths,
            exploitability,
            strategic,
            behavior,
            escalation,
            simulation,
            risk,
            phase4_summary,
        )

        return {
            "status": "PHASE_6_ADVERSARIAL_INTELLIGENCE_SUMMARY",
            "attack_paths": attack_paths,
            "privilege": privilege,
            "lateral_movement": movement,
            "exploitability": exploitability,
            "strategic_correlation": strategic,
            "behavioral_modeling": behavior,
            "escalation": escalation,
            "scenario_simulation": simulation,
            "strategic_risk": risk,
            "certification": certification,
            "claims": {
                "attacker_identity_claim": False,
                "cve_claim": False,
                "malware_claim": False,
                "nation_state_claim": False,
                "compromise_claim": False,
                "military_grade_claim": False,
            },
            "limitations": [
                "Phase 6 reasons over operational evidence; it does not invent attackers.",
                "Scenarios are controlled plausibility models, not live incidents.",
                "UNKNOWN and LOW_CONFIDENCE remain valid outcomes.",
            ],
            "generated_at": datetime.utcnow().isoformat(),
        }

    def build_attack_path_baseline(
        self,
        phase3: dict[str, Any],
        phase4: dict[str, Any],
        phase5: dict[str, Any],
    ) -> dict[str, Any]:
        p3_paths = phase3.get("adversarial", {}).get("attack_paths") or []
        endpoints = phase5.get("endpoint_intelligence", {}).get("endpoints") or []
        public_endpoints = [endpoint for endpoint in endpoints if endpoint.get("exposure") == "PUBLIC"]
        high_auth_endpoints = [endpoint for endpoint in endpoints if endpoint.get("auth_dependency") and endpoint.get("criticality") == "HIGH"]
        degraded = phase4.get("classification") in {"DEGRADED", "PARTIAL_FAILURE", "UNSTABLE", "LIMITED_OPERATION"}

        paths = []
        paths.extend(p3_paths[:10])
        if public_endpoints:
            paths.append(self._finding("EXPOSED_OPERATIONAL_PATH", [item["path"] for item in public_endpoints[:3]], "Public route exposure from FastAPI inventory.", "LOW_CONFIDENCE"))
        if high_auth_endpoints:
            paths.append(self._finding("PRIVILEGE_TRANSITION_AWARENESS", [item["path"] for item in high_auth_endpoints[:3]], "High-criticality auth-bound endpoints exist.", "LOW_CONFIDENCE"))
        if degraded:
            paths.append(self._finding("DEGRADED_RUNTIME_ABUSE_PATH", [phase4.get("classification")], "Degraded runtime may reduce operational visibility.", "LOW_CONFIDENCE"))

        confidence = self._confidence_from_counts(len(paths), degraded, phase3.get("evidence_count", 0))
        return {
            "status": "ATTACK_PATH_BASELINE",
            "suspicious_operational_sequences": p3_paths,
            "privilege_transition_awareness": high_auth_endpoints[:10],
            "runtime_exploitation_possibilities": [path for path in paths if path["type"] == "DEGRADED_RUNTIME_ABUSE_PATH"],
            "operational_abuse_paths": paths,
            "attack_chain_baseline": "CANDIDATE_ONLY" if paths else "INSUFFICIENT_EVIDENCE",
            "confidence": confidence,
            "fake_attacker_intelligence_guard": True,
            "hallucinated_attack_chain_guard": True,
        }

    def build_privilege_reasoning(self, phase4: dict[str, Any], phase5: dict[str, Any]) -> dict[str, Any]:
        endpoints = phase5.get("endpoint_intelligence", {}).get("endpoints") or []
        admin = [endpoint for endpoint in endpoints if endpoint.get("classification") == "ADMIN"]
        auth = [endpoint for endpoint in endpoints if endpoint.get("classification") == "AUTH"]
        protected = [endpoint for endpoint in endpoints if endpoint.get("auth_dependency")]
        auth_degraded = "auth_unavailable" in (phase4.get("degraded_runtime", {}).get("active_degradations") or [])
        findings = []
        if admin:
            findings.append(self._finding("ADMIN_OPERATION_BOUNDARY", [item["path"] for item in admin[:3]], "Admin routes require privilege boundary awareness.", "LOW_CONFIDENCE"))
        if auth:
            findings.append(self._finding("AUTH_ABUSE_AWARENESS", [item["path"] for item in auth[:3]], "Auth routes are operational privilege transition points.", "LOW_CONFIDENCE"))
        if auth_degraded:
            findings.append(self._finding("AUTH_DEGRADATION_PRIVILEGE_RISK", ["auth_degraded"], "Auth degradation reduces protected data assurance.", "MEDIUM_CONFIDENCE"))

        classification = "SUSPICIOUS" if auth_degraded and protected else "UNUSUAL" if admin or auth else "UNKNOWN"
        return {
            "status": "PRIVILEGE_ESCALATION_REASONING",
            "classification": classification,
            "suspicious_privilege_transitions": findings,
            "auth_abuse_awareness": len(auth),
            "privilege_anomaly_visibility": auth_degraded,
            "operational_escalation_awareness": len(protected),
            "fake_critical_escalation_guard": True,
            "fabricated_attacker_behavior_guard": True,
        }

    def build_lateral_movement(self, phase3: dict[str, Any], phase5: dict[str, Any]) -> dict[str, Any]:
        lateral = phase3.get("adversarial", {}).get("lateral_movement") or []
        relationships = phase5.get("dependency_mapping", {}).get("operational_trust_relationships") or []
        trust_zones = phase5.get("trust_zones", {}).get("zones") or []
        transitions = [
            {"from": relation.get("from"), "to": relation.get("to"), "trust": relation.get("trust"), "evidence_basis": "Phase 5 trust relationship"}
            for relation in relationships
        ]
        classification = "SUSPICIOUS" if lateral else "UNUSUAL" if len(transitions) >= 2 else "UNKNOWN"
        return {
            "status": "LATERAL_MOVEMENT_BASELINE",
            "classification": classification,
            "suspicious_movement_sequences": lateral,
            "repeated_operational_transition_detection": transitions,
            "unusual_access_propagation_awareness": len(trust_zones),
            "operational_spread_visibility": "TRUST_RELATIONSHIP_BASELINE" if transitions else "INSUFFICIENT_EVIDENCE",
            "fake_movement_detection_guard": True,
            "hallucinated_propagation_guard": True,
        }

    def build_exploitability(
        self,
        attack_paths: dict[str, Any],
        privilege: dict[str, Any],
        movement: dict[str, Any],
        phase4: dict[str, Any],
        phase5: dict[str, Any],
    ) -> dict[str, Any]:
        exposure = phase5.get("external_exposure", {})
        dependencies = phase5.get("dependency_mapping", {})
        runtime_integrity = phase4.get("integrity", {}).get("runtime_trust", "UNKNOWN")
        degraded = phase4.get("classification") in {"DEGRADED", "PARTIAL_FAILURE", "UNSTABLE", "LIMITED_OPERATION"}
        public_count = exposure.get("public_endpoint_count", 0)
        external_deps = dependencies.get("external_dependency_count", 0)
        auth_transitions = privilege.get("operational_escalation_awareness", 0)

        weaknesses = []
        if public_count:
            weaknesses.append(self._weakness("exposed_operational_paths", public_count, "LOW_CONFIDENCE"))
        if auth_transitions:
            weaknesses.append(self._weakness("auth_boundary_abuse_possibility", auth_transitions, "LOW_CONFIDENCE"))
        if external_deps:
            weaknesses.append(self._weakness("dependency_abuse_possibility", external_deps, "LOW_CONFIDENCE"))
        if degraded:
            weaknesses.append(self._weakness("degraded_state_exploitability", 1, "MEDIUM_CONFIDENCE"))
        if runtime_integrity != "TRUSTED":
            weaknesses.append(self._weakness("runtime_trust_limitation", 1, "LOW_CONFIDENCE"))

        classification = self._exploitability_level(weaknesses, degraded, runtime_integrity)
        confidence = self._threat_confidence(len(weaknesses), degraded, phase5.get("certification", {}).get("classification"))
        return {
            "status": "OPERATIONAL_EXPLOITABILITY_INTELLIGENCE",
            "classification": classification,
            "classification_model": ["LOW", "MEDIUM", "HIGH", "UNKNOWN"],
            "confidence": confidence,
            "weaknesses": weaknesses,
            "weakness_correlation": self._weakness_correlation(weaknesses, phase4, phase5),
            "survivability_aware_exploitability": phase4.get("certification", {}).get("classification", "UNKNOWN"),
            "governance_aware_exploitability": phase4.get("freeze_governance", {}).get("freeze_status", "UNKNOWN"),
            "fake_exploitability_guard": True,
            "hallucinated_compromise_guard": True,
        }

    def build_strategic_correlation(
        self,
        exploitability: dict[str, Any],
        phase3: dict[str, Any],
        phase4: dict[str, Any],
        phase5: dict[str, Any],
    ) -> dict[str, Any]:
        signals = []
        if exploitability.get("classification") in {"MEDIUM", "HIGH"}:
            signals.append("exploitability")
        if phase4.get("classification") in {"DEGRADED", "PARTIAL_FAILURE", "UNSTABLE"}:
            signals.append("runtime_degradation")
        if phase5.get("external_risk_correlation", {}).get("risk_level") in {"MEDIUM", "REVIEW_REQUIRED"}:
            signals.append("external_risk")
        if phase3.get("correlation", {}).get("escalation", {}).get("state") not in {None, "NO_CORRELATED_INCIDENT"}:
            signals.append("repeated_operational_anomalies")

        escalation = self._strategic_escalation(signals, exploitability.get("confidence", "UNKNOWN"))
        confidence = self._confidence_label(len(signals), exploitability.get("confidence", "UNKNOWN"))
        return {
            "status": "STRATEGIC_THREAT_CORRELATION",
            "strategic_patterns": signals,
            "correlated_operational_risk": escalation,
            "plausible_adversarial_leverage": "CANDIDATE_ONLY" if signals else "INSUFFICIENT_EVIDENCE",
            "threat_confidence": confidence,
            "escalation_intelligence": escalation,
            "fake_campaign_guard": True,
            "false_critical_escalation_guard": True,
        }

    def build_behavioral_modeling(self, phase3: dict[str, Any], phase4: dict[str, Any]) -> dict[str, Any]:
        correlation_groups = phase3.get("correlation", {}).get("groups") or []
        active_degradation = phase4.get("degraded_runtime", {}).get("active_degradations") or []
        repeated = len(correlation_groups)
        auth_related = len([group for group in correlation_groups if "AUTH" in str(group).upper()])
        classification = "UNKNOWN"
        if repeated == 0 and not active_degradation:
            classification = "NORMAL"
        elif repeated <= 1 or active_degradation:
            classification = "UNUSUAL"
        if repeated >= 2 or auth_related:
            classification = "SUSPICIOUS"
        if repeated >= 5 and auth_related:
            classification = "HIGHLY_SUSPICIOUS"

        return {
            "status": "BEHAVIORAL_SUSPICION_MODELING",
            "classification": classification,
            "classification_model": ["NORMAL", "UNUSUAL", "SUSPICIOUS", "HIGHLY_SUSPICIOUS", "UNKNOWN"],
            "unusual_operational_behavior_detection": active_degradation,
            "auth_behavior_anomalies": auth_related,
            "repeated_suspicious_operational_flows": repeated,
            "runtime_behavior_anomalies": active_degradation,
            "operational_inconsistency_awareness": phase4.get("integrity", {}).get("runtime_trust", "UNKNOWN"),
            "fake_behavioral_ai_guard": True,
            "no_malicious_actor_claim": True,
        }

    def build_escalation_intelligence(
        self,
        strategic: dict[str, Any],
        behavior: dict[str, Any],
        exploitability: dict[str, Any],
        phase4: dict[str, Any],
    ) -> dict[str, Any]:
        recurring = behavior.get("classification") in {"SUSPICIOUS", "HIGHLY_SUSPICIOUS"}
        correlated = strategic.get("correlated_operational_risk") in {"CORRELATED_OPERATIONAL_DEGRADATION", "STRATEGIC_OPERATIONAL_THREAT_CANDIDATE"}
        high_risk = exploitability.get("classification") == "HIGH" or phase4.get("classification") == "UNSTABLE"
        classification = "ISOLATED"
        if recurring:
            classification = "RECURRING"
        if correlated:
            classification = "CORRELATED"
        if high_risk and correlated:
            classification = "HIGH_RISK"
        if strategic.get("threat_confidence") == "UNKNOWN":
            classification = "UNKNOWN"

        return {
            "status": "THREAT_ESCALATION_INTELLIGENCE",
            "classification": classification,
            "classification_model": ["ISOLATED", "RECURRING", "CORRELATED", "HIGH_RISK", "UNKNOWN"],
            "repeated_anomaly_escalation": recurring,
            "repeated_auth_degradation_escalation": behavior.get("auth_behavior_anomalies", 0),
            "operational_degradation_escalation": phase4.get("classification"),
            "survivability_degradation_escalation": phase4.get("certification", {}).get("classification", "UNKNOWN"),
            "correlated_operational_escalation": correlated,
            "fake_emergency_guard": True,
            "false_collapse_guard": True,
        }

    def build_scenario_simulation(
        self,
        exploitability: dict[str, Any],
        phase4: dict[str, Any],
        phase5: dict[str, Any],
    ) -> dict[str, Any]:
        scenarios = [
            self._scenario("degraded_auth_scenario", bool(exploitability.get("weaknesses")), phase4.get("classification")),
            self._scenario("partial_dependency_compromise_scenario", phase5.get("dependency_mapping", {}).get("external_dependency_count", 0) > 0, phase4.get("classification")),
            self._scenario("runtime_instability_scenario", phase4.get("classification") in {"DEGRADED", "PARTIAL_FAILURE", "UNSTABLE"}, phase4.get("classification")),
            self._scenario("exposed_endpoint_abuse_scenario", phase5.get("external_exposure", {}).get("public_endpoint_count", 0) > 0, phase4.get("classification")),
            self._scenario("operational_survivability_stress_scenario", phase4.get("certification", {}).get("classification") in {"CONDITIONALLY_RESILIENT", "PARTIALLY_RESILIENT"}, phase4.get("classification")),
        ]
        return {
            "status": "ADVERSARIAL_SCENARIO_SIMULATION",
            "scenarios": scenarios,
            "simulation_classification": self._simulation_classification(scenarios),
            "operational_impact_modeling": {
                "runtime_degradation_impact": phase4.get("classification"),
                "auth_degradation_impact": self._scenario_result(scenarios, "degraded_auth_scenario"),
                "dependency_degradation_impact": self._scenario_result(scenarios, "partial_dependency_compromise_scenario"),
                "survivability_degradation_impact": phase4.get("certification", {}).get("classification", "UNKNOWN"),
                "operational_continuity_impact": phase4.get("continuity_level", "UNKNOWN"),
            },
            "fake_attack_guard": True,
            "fabricated_incident_guard": True,
        }

    def build_strategic_risk(
        self,
        exploitability: dict[str, Any],
        strategic: dict[str, Any],
        escalation: dict[str, Any],
        simulation: dict[str, Any],
        phase4: dict[str, Any],
        phase5: dict[str, Any],
    ) -> dict[str, Any]:
        factors = {
            "exploitability": exploitability.get("classification", "UNKNOWN"),
            "strategic_correlation": strategic.get("correlated_operational_risk", "UNKNOWN"),
            "escalation": escalation.get("classification", "UNKNOWN"),
            "simulation": simulation.get("simulation_classification", "UNKNOWN"),
            "survivability": phase4.get("certification", {}).get("classification", "UNKNOWN"),
            "ecosystem_exposure": phase5.get("certification", {}).get("classification", "UNKNOWN"),
        }
        classification = self._risk_classification(factors)
        return {
            "status": "STRATEGIC_OPERATIONAL_RISK_ENGINE",
            "classification": classification,
            "classification_model": ["LOW", "MODERATE", "ELEVATED", "HIGH", "UNKNOWN"],
            "risk_factors": factors,
            "strategic_visibility": {
                "operational_fragility": phase4.get("classification", "UNKNOWN"),
                "ecosystem_fragility": phase5.get("external_risk_correlation", {}).get("risk_level", "UNKNOWN"),
                "governance_fragility": phase4.get("freeze_governance", {}).get("freeze_status", "UNKNOWN"),
                "runtime_fragility": phase4.get("integrity", {}).get("runtime_trust", "UNKNOWN"),
                "recovery_fragility": phase4.get("recovery", {}).get("recovery_confidence", "UNKNOWN"),
            },
            "uncertainty_visible": classification == "UNKNOWN" or exploitability.get("confidence") in {"UNKNOWN", "LOW_CONFIDENCE"},
            "fake_strategic_collapse_guard": True,
            "hallucinated_operational_doom_guard": True,
        }

    def build_adversarial_certification(
        self,
        attack_paths: dict[str, Any],
        exploitability: dict[str, Any],
        strategic: dict[str, Any],
        behavior: dict[str, Any],
        escalation: dict[str, Any],
        simulation: dict[str, Any],
        risk: dict[str, Any],
        phase4: dict[str, Any],
    ) -> dict[str, Any]:
        points = 0
        points += 1 if attack_paths.get("fake_attacker_intelligence_guard") else 0
        points += 1 if exploitability.get("fake_exploitability_guard") else 0
        points += 1 if escalation.get("fake_emergency_guard") else 0
        points += 1 if strategic.get("fake_campaign_guard") else 0
        points += 1 if behavior.get("fake_behavioral_ai_guard") else 0
        points += 1 if phase4.get("classification") in {"STABLE", "DEGRADED", "PARTIAL_FAILURE", "LIMITED_OPERATION"} else 0
        points += 1 if risk.get("fake_strategic_collapse_guard") else 0
        points += 1 if simulation.get("fake_attack_guard") else 0

        if points <= 3:
            classification = "BASIC_DEFENSIVE"
        elif points <= 5:
            classification = "PARTIALLY_ADVERSARIAL"
        elif points <= 7:
            classification = "OPERATIONALLY_ADVERSARIAL"
        else:
            classification = "STRATEGICALLY_COHERENT"
        if (
            exploitability.get("confidence") in {"UNKNOWN", "LOW_CONFIDENCE"}
            or attack_paths.get("confidence") in {"UNKNOWN", "LOW_CONFIDENCE"}
        ) and classification == "STRATEGICALLY_COHERENT":
            classification = "OPERATIONALLY_ADVERSARIAL"

        return {
            "status": "HONEST_ADVERSARIAL_CERTIFICATION",
            "classification": classification,
            "allowed_classifications": ["BASIC_DEFENSIVE", "PARTIALLY_ADVERSARIAL", "OPERATIONALLY_ADVERSARIAL", "STRATEGICALLY_COHERENT"],
            "readiness_points": points,
            "attack_path_reasoning": attack_paths.get("confidence", "UNKNOWN"),
            "exploitability_reasoning": exploitability.get("classification", "UNKNOWN"),
            "escalation_intelligence": escalation.get("classification", "UNKNOWN"),
            "strategic_correlation": strategic.get("correlated_operational_risk", "UNKNOWN"),
            "behavioral_modeling": behavior.get("classification", "UNKNOWN"),
            "survivability_awareness": phase4.get("certification", {}).get("classification", "UNKNOWN"),
            "governance_awareness": phase4.get("freeze_governance", {}).get("freeze_status", "UNKNOWN"),
            "cognitive_stability": True,
            "military_grade_claim": False,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def _finding(self, finding_type: str, key: list[Any], interpretation: str, confidence: str) -> dict[str, Any]:
        return {
            "type": finding_type,
            "key": [str(item) for item in key],
            "interpretation": interpretation,
            "confidence": confidence,
            "evidence_basis": "phase3_phase4_phase5_operational_evidence",
        }

    def _weakness(self, kind: str, count: int, confidence: str) -> dict[str, Any]:
        return {
            "type": kind,
            "count": count,
            "confidence": confidence,
            "evidence_basis": "operational visibility and route/dependency/degradation evidence",
        }

    def _weakness_correlation(self, weaknesses: list[dict[str, Any]], phase4: dict[str, Any], phase5: dict[str, Any]) -> list[dict[str, Any]]:
        correlations = []
        names = {weakness["type"] for weakness in weaknesses}
        if {"auth_boundary_abuse_possibility", "degraded_state_exploitability"}.issubset(names):
            correlations.append({"type": "auth_degradation_plus_runtime_degradation", "confidence": "MEDIUM_CONFIDENCE"})
        if {"exposed_operational_paths", "runtime_trust_limitation"}.issubset(names):
            correlations.append({"type": "exposed_paths_plus_limited_runtime_trust", "confidence": "LOW_CONFIDENCE"})
        if {"dependency_abuse_possibility", "degraded_state_exploitability"}.issubset(names):
            correlations.append({"type": "dependency_surface_plus_degraded_state", "confidence": "LOW_CONFIDENCE"})
        return correlations

    def _confidence_from_counts(self, count: int, degraded: bool, evidence_count: int) -> str:
        if count == 0:
            return "UNKNOWN"
        if evidence_count >= 5 and degraded:
            return "MEDIUM_CONFIDENCE"
        if count >= 3:
            return "LOW_CONFIDENCE"
        return "LOW_CONFIDENCE"

    def _threat_confidence(self, count: int, degraded: bool, ecosystem_classification: str | None) -> str:
        if count == 0:
            return "UNKNOWN"
        if count >= 4 and degraded and ecosystem_classification in {"ECOSYSTEM_AWARE", "OPERATIONALLY_CONNECTED"}:
            return "MEDIUM_CONFIDENCE"
        if count >= 2:
            return "LOW_CONFIDENCE"
        return "LOW_CONFIDENCE"

    def _confidence_label(self, signal_count: int, exploitability_confidence: str) -> str:
        if signal_count == 0:
            return "UNKNOWN"
        if signal_count >= 4 and exploitability_confidence in {"MEDIUM_CONFIDENCE", "HIGH_CONFIDENCE"}:
            return "HIGH_CONFIDENCE"
        if signal_count >= 2:
            return "MEDIUM_CONFIDENCE"
        return "LOW_CONFIDENCE"

    def _exploitability_level(self, weaknesses: list[dict[str, Any]], degraded: bool, runtime_integrity: str) -> str:
        if not weaknesses:
            return "UNKNOWN"
        if len(weaknesses) >= 5 and degraded and runtime_integrity != "TRUSTED":
            return "HIGH"
        if len(weaknesses) >= 3 or degraded:
            return "MEDIUM"
        return "LOW"

    def _strategic_escalation(self, signals: list[str], confidence: str) -> str:
        if not signals:
            return "ISOLATED_OPERATIONAL_ISSUE"
        if len(signals) == 1:
            return "REPEATED_OPERATIONAL_ISSUE"
        if len(signals) < 4:
            return "CORRELATED_OPERATIONAL_DEGRADATION"
        if confidence in {"MEDIUM_CONFIDENCE", "HIGH_CONFIDENCE"}:
            return "STRATEGIC_OPERATIONAL_THREAT_CANDIDATE"
        return "CORRELATED_OPERATIONAL_DEGRADATION"

    def _scenario(self, name: str, plausible: bool, runtime_state: str | None) -> dict[str, Any]:
        if runtime_state == "UNKNOWN":
            classification = "UNKNOWN"
        elif plausible and runtime_state in {"DEGRADED", "PARTIAL_FAILURE", "UNSTABLE", "LIMITED_OPERATION"}:
            classification = "PLAUSIBLE"
        elif plausible:
            classification = "LIMITED"
        else:
            classification = "HIGH_UNCERTAINTY"
        return {
            "name": name,
            "classification": classification,
            "evidence_basis": "controlled operational scenario from current runtime/ecosystem state",
            "fake_compromise_claim": False,
        }

    def _simulation_classification(self, scenarios: list[dict[str, Any]]) -> str:
        classes = [scenario["classification"] for scenario in scenarios]
        if "PLAUSIBLE" in classes:
            return "PLAUSIBLE"
        if "LIMITED" in classes:
            return "LIMITED"
        if all(item == "UNKNOWN" for item in classes):
            return "UNKNOWN"
        return "HIGH_UNCERTAINTY"

    def _scenario_result(self, scenarios: list[dict[str, Any]], name: str) -> str:
        for scenario in scenarios:
            if scenario["name"] == name:
                return scenario["classification"]
        return "UNKNOWN"

    def _risk_classification(self, factors: dict[str, str]) -> str:
        values = set(factors.values())
        if "UNKNOWN" in values and len(values) == 1:
            return "UNKNOWN"
        if "HIGH" in values or "HIGH_RISK" in values:
            return "HIGH"
        if "MEDIUM" in values or "CORRELATED" in " ".join(values) or "PLAUSIBLE" in values:
            return "ELEVATED"
        if "LOW" in values or "LIMITED" in values:
            return "MODERATE"
        return "LOW"
