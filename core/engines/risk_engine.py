from datetime import datetime

AGENT_BASE_RISK = {
    "cerebro":     45,
    "mcf":         55,
    "laboratorio": 30,
    "buscador":    25,
    "sniff":       20,
    "pluma":       40,
    "unknown":     50,
}

MODEL_RISK = {
    "claude-sonnet":  10,
    "claude-opus":    15,
    "gpt-4":          20,
    "gpt-3.5":        12,
    "unknown":        25,
}

class RiskEngine:
    def __init__(self, threat_memory):
        self.threat_memory = threat_memory
        self.agent_scores: dict[str, float] = {}

    def score(self, event: dict) -> dict:
        agent = event.get("agent", "unknown").lower()
        model = event.get("model", "unknown").lower()
        user = event.get("user", "unknown")
        content = event.get("content", "")
        base = AGENT_BASE_RISK.get(agent, 50)
        model_risk = MODEL_RISK.get(model, 25)
        history = self.threat_memory.get_agent_history(agent)
        behavior_score = self._behavioral_score(history)
        content_score = self._content_score(content)
        user_score = self._user_risk(user)
        raw = (
            base * 0.25 +
            model_risk * 0.10 +
            behavior_score * 0.30 +
            content_score * 0.25 +
            user_score * 0.10
        )
        score = min(100, max(0, raw))
        self.agent_scores[agent] = round(
            (self.agent_scores.get(agent, score) * 0.7 + score * 0.3), 2
        )
        return {
            "score": round(score, 2),
            "level": self._level(score),
            "components": {
                "base_agent_risk": base,
                "model_risk": model_risk,
                "behavioral_score": round(behavior_score, 2),
                "content_score": round(content_score, 2),
                "user_score": round(user_score, 2),
            },
            "agent_running_score": self.agent_scores[agent],
            "scored_at": datetime.utcnow().isoformat(),
        }

    def _behavioral_score(self, history: list) -> float:
        if not history:
            return 20.0
        recent = history[-20:]
        high_risk = sum(1 for e in recent if e.get("risk", {}).get("score", 0) >= 70)
        ratio = high_risk / len(recent)
        return min(100, 20 + (ratio * 80) + (high_risk * 3))

    def _content_score(self, content: str) -> float:
        if not content:
            return 10.0
        score = 10.0
        length = len(content)
        if length > 2000:
            score += 20
        elif length > 1000:
            score += 10
        suspicious = [
            "ignore", "bypass", "override", "jailbreak", "secret",
            "password", "token", "key", "credentials", "admin",
            "root", "sudo", "execute", "eval", "inject",
        ]
        hits = sum(1 for w in suspicious if w in content.lower())
        score += min(60, hits * 12)
        return min(100, score)

    def _user_risk(self, user: str) -> float:
        history = self.threat_memory.get_user_history(user)
        if not history:
            return 15.0
        blocked = sum(1 for e in history if e.get("policy", {}).get("action") == "BLOCK")
        return min(100, 15 + blocked * 10)

    def _level(self, score: float) -> str:
        if score >= 90: return "CRITICAL"
        if score >= 70: return "HIGH"
        if score >= 50: return "MEDIUM"
        if score >= 30: return "LOW"
        return "MINIMAL"

    def get_ecosystem_scores(self) -> dict:
        agents = ["cerebro", "mcf", "laboratorio", "buscador", "sniff", "pluma"]
        return {
            "agents": {
                a: {
                    "score": self.agent_scores.get(a, AGENT_BASE_RISK.get(a, 50)),
                    "level": self._level(self.agent_scores.get(a, AGENT_BASE_RISK.get(a, 50))),
                }
                for a in agents
            },
            "ecosystem_avg": round(
                sum(self.agent_scores.get(a, AGENT_BASE_RISK.get(a, 50)) for a in agents) / len(agents), 2
            ),
            "timestamp": datetime.utcnow().isoformat(),
        }