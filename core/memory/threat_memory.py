from datetime import datetime, timedelta
from collections import defaultdict
import uuid


class ThreatMemory:
    def __init__(self):
        self.events: list[dict] = []
        self.incidents: list[dict] = []
        self.agent_index: dict[str, list] = defaultdict(list)
        self.user_index: dict[str, list] = defaultdict(list)
        self.threat_patterns: list[dict] = []
        self.fingerprints: set[str] = set()

    def store(self, event: dict):
        self.events.append(event)
        agent = event.get("agent", "unknown")
        user = event.get("user", "unknown")
        self.agent_index[agent].append(event)
        self.user_index[user].append(event)
        if event.get("detection", {}).get("threat_detected"):
            fp = self._fingerprint(event)
            self.fingerprints.add(fp)
            self.threat_patterns.append({
                "fingerprint": fp,
                "type": event["detection"]["threat_types"],
                "agent": agent,
                "risk_score": event.get("risk", {}).get("score", 0),
                "timestamp": event.get("timestamp"),
            })
        if len(self.events) > 10000:
            self.events = self.events[-10000:]

    def create_incident(self, event: dict) -> dict:
        severity = event.get("risk", {}).get("level", "MEDIUM")
        incident = {
            "id": f"INC-{str(uuid.uuid4())[:6].upper()}",
            "created_at": datetime.utcnow().isoformat(),
            "severity": severity,
            "agent": event.get("agent"),
            "user": event.get("user"),
            "risk_score": event.get("risk", {}).get("score", 0),
            "threat_types": event.get("detection", {}).get("threat_types", []),
            "correlation_id": event.get("correlation", {}).get("correlation_id"),
            "policy_action": event.get("policy", {}).get("action"),
            "status": "OPEN",
            "event_id": event.get("id"),
        }
        self.incidents.append(incident)
        return incident

    def get_agent_history(self, agent: str) -> list:
        return self.agent_index.get(agent.lower(), [])

    def get_user_history(self, user: str) -> list:
        return self.user_index.get(user, [])

    def get_recent_events(self, minutes: int = 5) -> list:
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        return [
            e for e in self.events
            if datetime.fromisoformat(e.get("timestamp", "2000-01-01")) > cutoff
        ]

    def get_incidents(self) -> list:
        return sorted(self.incidents, key=lambda x: x["created_at"], reverse=True)

    def get_summary(self) -> dict:
        total = len(self.events)
        threats = sum(1 for e in self.events if e.get("detection", {}).get("threat_detected"))
        blocked = sum(1 for e in self.events if e.get("policy", {}).get("action") == "BLOCK")
        return {
            "total_events": total,
            "threat_events": threats,
            "blocked_events": blocked,
            "total_incidents": len(self.incidents),
            "unique_fingerprints": len(self.fingerprints),
            "agents_monitored": len(self.agent_index),
            "users_tracked": len(self.user_index),
            "threat_patterns": len(self.threat_patterns),
        }

    def add_threat_fingerprint(self, fingerprint_data: dict):
        fp_key = f"{fingerprint_data.get('threat_types', [])}:{fingerprint_data.get('content_preview', '')[:50]}"
        self.fingerprints.add(fp_key)
        self.threat_patterns.append({
            "fingerprint": fp_key,
            "type": fingerprint_data.get("threat_types", []),
            "score": fingerprint_data.get("score", 0),
            "patterns": fingerprint_data.get("patterns", []),
            "timestamp": fingerprint_data.get("timestamp"),
        })
        if len(self.threat_patterns) > 5000:
            self.threat_patterns = self.threat_patterns[-2500:]

    def _fingerprint(self, event: dict) -> str:
        content = event.get("content", "")
        threat_types = ",".join(sorted(event.get("detection", {}).get("threat_types", [])))
        agent = event.get("agent", "")
        words = sorted(set(content.lower().split()))[:10]
        return f"{agent}:{threat_types}:{':'.join(words)}"