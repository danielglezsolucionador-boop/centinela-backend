from datetime import datetime
from typing import Optional

DEFAULT_POLICIES = {
    "PLUMA": {
        "max_risk_score": 70,
        "allowed_models": ["claude-haiku", "claude-sonnet", "gpt-4o"],
        "blocked_threat_types": ["PROMPT_INJECTION", "DATA_EXFILTRATION"],
        "max_prompt_length": 10000,
        "action_on_violation": "BLOCK",
        "alert_threshold": 50,
    },
    "LENTE": {
        "max_risk_score": 65,
        "allowed_models": ["claude-haiku", "claude-sonnet", "gpt-4o"],
        "blocked_threat_types": ["PROMPT_INJECTION", "JAILBREAK", "DATA_EXFILTRATION"],
        "max_prompt_length": 8000,
        "action_on_violation": "BLOCK",
        "alert_threshold": 45,
    },
    "CEREBRO": {
        "max_risk_score": 50,
        "allowed_models": ["claude-sonnet", "claude-opus"],
        "blocked_threat_types": ["PROMPT_INJECTION", "JAILBREAK", "DATA_EXFILTRATION", "SYSTEM_EXTRACTION", "ROLE_MANIPULATION"],
        "max_prompt_length": 15000,
        "action_on_violation": "BLOCK",
        "alert_threshold": 35,
    },
    "MCF": {
        "max_risk_score": 40,
        "allowed_models": ["claude-haiku", "claude-sonnet"],
        "blocked_threat_types": ["PROMPT_INJECTION", "JAILBREAK", "DATA_EXFILTRATION", "SYSTEM_EXTRACTION"],
        "max_prompt_length": 5000,
        "action_on_violation": "BLOCK",
        "alert_threshold": 30,
    },
    "BUSCADOR": {
        "max_risk_score": 75,
        "allowed_models": ["claude-haiku", "gpt-4o-mini"],
        "blocked_threat_types": ["DATA_EXFILTRATION"],
        "max_prompt_length": 3000,
        "action_on_violation": "WARN",
        "alert_threshold": 60,
    },
    "SNIFF_AMAZON": {
        "max_risk_score": 45,
        "allowed_models": ["claude-haiku"],
        "blocked_threat_types": ["PROMPT_INJECTION", "DATA_EXFILTRATION", "SYSTEM_EXTRACTION"],
        "max_prompt_length": 4000,
        "action_on_violation": "BLOCK",
        "alert_threshold": 35,
    },
    "LABORATORIO": {
        "max_risk_score": 70,
        "allowed_models": ["claude-haiku", "claude-sonnet", "gpt-4o"],
        "blocked_threat_types": ["PROMPT_INJECTION", "DATA_EXFILTRATION"],
        "max_prompt_length": 8000,
        "action_on_violation": "BLOCK",
        "alert_threshold": 50,
    },
    "CREADOR_APIS": {
        "max_risk_score": 45,
        "allowed_models": ["claude-sonnet"],
        "blocked_threat_types": ["PROMPT_INJECTION", "JAILBREAK", "DATA_EXFILTRATION", "SYSTEM_EXTRACTION"],
        "max_prompt_length": 6000,
        "action_on_violation": "BLOCK",
        "alert_threshold": 30,
    },
    "DEFAULT": {
        "max_risk_score": 60,
        "allowed_models": ["claude-haiku", "claude-sonnet"],
        "blocked_threat_types": ["PROMPT_INJECTION", "DATA_EXFILTRATION"],
        "max_prompt_length": 5000,
        "action_on_violation": "WARN",
        "alert_threshold": 45,
    },
}

class PolicyEngine:
    def __init__(self):
        self.policies = DEFAULT_POLICIES.copy()
        self.violation_log = []
        self.enforcement_stats = {
            "total_evaluated": 0,
            "blocked": 0,
            "warned": 0,
            "allowed": 0,
            "by_agent": {},
        }

    def evaluate(self, event: dict, detection: dict, risk: dict) -> dict:
        self.enforcement_stats["total_evaluated"] += 1

        agent = event.get("agent", "DEFAULT").upper()
        policy = self.policies.get(agent, self.policies["DEFAULT"])
        model = event.get("model", "unknown")
        content = event.get("content", "")
        risk_score = risk.get("score", 0)
        threat_types = detection.get("threat_types", [])
        threat_detected = detection.get("threat_detected", False)

        violations = []
        action = "ALLOW"

        # Verificar score de riesgo
        if risk_score >= policy["max_risk_score"]:
            violations.append({
                "type": "RISK_THRESHOLD_EXCEEDED",
                "detail": f"Risk score {risk_score} exceeds policy limit {policy['max_risk_score']}",
                "severity": "HIGH",
            })

        # Verificar tipos de amenaza bloqueados
        for threat in threat_types:
            if threat in policy["blocked_threat_types"]:
                violations.append({
                    "type": "BLOCKED_THREAT_TYPE",
                    "detail": f"Threat type {threat} is blocked for agent {agent}",
                    "severity": "CRITICAL",
                })

        # Verificar modelo permitido
        if model not in policy["allowed_models"] and model != "unknown":
            violations.append({
                "type": "UNAUTHORIZED_MODEL",
                "detail": f"Model {model} not allowed for agent {agent}",
                "severity": "MEDIUM",
            })

        # Verificar longitud del prompt
        if len(content) > policy["max_prompt_length"]:
            violations.append({
                "type": "PROMPT_TOO_LONG",
                "detail": f"Prompt length {len(content)} exceeds limit {policy['max_prompt_length']}",
                "severity": "LOW",
            })

        # Determinar acción
        has_critical = any(v["severity"] == "CRITICAL" for v in violations)
        has_high = any(v["severity"] == "HIGH" for v in violations)

        if violations:
            if has_critical or (has_high and policy["action_on_violation"] == "BLOCK"):
                action = "BLOCK"
                self.enforcement_stats["blocked"] += 1
            elif risk_score >= policy["alert_threshold"]:
                action = "WARN"
                self.enforcement_stats["warned"] += 1
            else:
                action = "ALLOW"
                self.enforcement_stats["allowed"] += 1
        else:
            action = "ALLOW"
            self.enforcement_stats["allowed"] += 1

        # Actualizar stats por agente
        if agent not in self.enforcement_stats["by_agent"]:
            self.enforcement_stats["by_agent"][agent] = {"blocked": 0, "warned": 0, "allowed": 0}
       
            action_key = {"BLOCK": "blocked", "WARN": "warned", "ALLOW": "allowed"}.get(action, "allowed")
        self.enforcement_stats["by_agent"][agent][action_key] += 1

        # Log de violaciones
        if violations:
            self.violation_log.append({
                "timestamp": datetime.utcnow().isoformat(),
                "agent": agent,
                "action": action,
                "violations": violations,
                "risk_score": risk_score,
                "event_id": event.get("id"),
            })
            if len(self.violation_log) > 1000:
                self.violation_log = self.violation_log[-500:]

        return {
            "action": action,
            "violations": violations,
            "policy_applied": agent,
            "risk_score": risk_score,
            "enforcement_timestamp": datetime.utcnow().isoformat(),
            "blocked": action == "BLOCK",
            "reason": violations[0]["detail"] if violations else "Policy compliant",
        }

    def get_policy(self, agent: str) -> dict:
        return self.policies.get(agent.upper(), self.policies["DEFAULT"])

    def update_policy(self, agent: str, updates: dict) -> dict:
        agent = agent.upper()
        if agent not in self.policies:
            self.policies[agent] = self.policies["DEFAULT"].copy()
        self.policies[agent].update(updates)
        return self.policies[agent]

    def get_stats(self) -> dict:
        return {
            **self.enforcement_stats,
            "recent_violations": self.violation_log[-10:],
        }

    def get_all_policies(self) -> dict:
        return self.policies
