from datetime import datetime, timedelta
import uuid


class ThreatCorrelationEngine:
    def __init__(self, threat_memory):
        self.threat_memory = threat_memory
        self.active_correlations: dict[str, dict] = {}

    def correlate(self, event: dict) -> dict:
        signals = []
        correlation_id = None

        user_signal = self._check_user_pattern(event)
        if user_signal:
            signals.append(user_signal)

        vector_signal = self._check_vector_spread(event)
        if vector_signal:
            signals.append(vector_signal)

        escalation_signal = self._check_escalation(event)
        if escalation_signal:
            signals.append(escalation_signal)

        evasion_signal = self._check_evasion(event)
        if evasion_signal:
            signals.append(evasion_signal)

        if signals:
            correlation_id = self._create_correlation(event, signals)

        return {
            "correlated": len(signals) > 0,
            "correlation_id": correlation_id,
            "signals": signals,
            "signal_count": len(signals),
            "correlated_at": datetime.utcnow().isoformat(),
        }

    def _check_user_pattern(self, event: dict) -> dict | None:
        user = event.get("user", "unknown")
        history = self.threat_memory.get_user_history(user)
        recent = [e for e in history[-50:] if e.get("detection", {}).get("threat_detected")]
        if len(recent) >= 3:
            return {
                "type": "REPEATED_ATTACK",
                "description": f"User {user} has {len(recent)} threat events",
                "severity": "HIGH" if len(recent) >= 5 else "MEDIUM",
                "count": len(recent),
            }
        return None

    def _check_vector_spread(self, event: dict) -> dict | None:
        threat_types = event.get("detection", {}).get("threat_types", [])
        if not threat_types:
            return None
        history = self.threat_memory.get_recent_events(minutes=5)
        matching = [
            e for e in history
            if any(t in e.get("detection", {}).get("threat_types", []) for t in threat_types)
            and e.get("agent") != event.get("agent")
        ]
        if len(matching) >= 2:
            agents = list(set(e.get("agent") for e in matching))
            return {
                "type": "VECTOR_SPREAD",
                "description": f"Same attack vector across {len(agents)} agents",
                "severity": "CRITICAL",
                "agents_affected": agents,
                "vector": threat_types,
            }
        return None

    def _check_escalation(self, event: dict) -> dict | None:
        agent = event.get("agent", "unknown")
        history = self.threat_memory.get_agent_history(agent)
        if len(history) < 3:
            return None
        recent_scores = [e.get("risk", {}).get("score", 0) for e in history[-5:]]
        if len(recent_scores) >= 3:
            increasing = all(recent_scores[i] < recent_scores[i+1] for i in range(len(recent_scores)-1))
            if increasing and recent_scores[-1] >= 60:
                return {
                    "type": "RISK_ESCALATION",
                    "description": f"Agent {agent} risk escalating: {recent_scores}",
                    "severity": "HIGH",
                    "score_progression": recent_scores,
                }
        return None

    def _check_evasion(self, event: dict) -> dict | None:
        user = event.get("user", "unknown")
        history = self.threat_memory.get_user_history(user)
        blocked = [e for e in history[-20:] if e.get("policy", {}).get("action") == "BLOCK"]
        current_threat = event.get("detection", {}).get("threat_detected", False)
        if len(blocked) >= 2 and current_threat:
            return {
                "type": "EVASION_ATTEMPT",
                "description": f"User {user} attempting new vector after {len(blocked)} blocks",
                "severity": "CRITICAL",
                "previous_blocks": len(blocked),
            }
        return None

    def _create_correlation(self, event: dict, signals: list) -> str:
        cid = str(uuid.uuid4())[:8].upper()
        severity = "CRITICAL" if any(s["severity"] == "CRITICAL" for s in signals) else "HIGH"
        self.active_correlations[cid] = {
            "id": cid,
            "created_at": datetime.utcnow().isoformat(),
            "agent": event.get("agent"),
            "user": event.get("user"),
            "signals": signals,
            "severity": severity,
            "event_id": event.get("id"),
        }
        return cid

    def get_active_correlations(self) -> list:
        return list(self.active_correlations.values())