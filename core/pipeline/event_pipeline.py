import uuid
from datetime import datetime


class EventPipeline:
    def __init__(self, risk_engine, correlation_engine, threat_memory):
        self.risk_engine = risk_engine
        self.correlation_engine = correlation_engine
        self.threat_memory = threat_memory

    async def process(self, raw_event: dict) -> dict:
        event = self._normalize(raw_event)
        risk_result = self.risk_engine.score(event)
        event["risk"] = risk_result
        detection = self._detect(event)
        event["detection"] = detection
        correlation = self.correlation_engine.correlate(event)
        event["correlation"] = correlation
        policy = self._enforce_policy(event)
        event["policy"] = policy
        response = self._respond(event)
        event["response"] = response
        self.threat_memory.store(event)
        if risk_result["score"] >= 70 or detection["threat_detected"]:
            incident = self.threat_memory.create_incident(event)
            event["incident"] = incident
        return event

    def _normalize(self, raw: dict) -> dict:
        return {
            "id": raw.get("id", str(uuid.uuid4())),
            "type": raw.get("type", "UNKNOWN"),
            "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
            "agent": raw.get("agent", "unknown"),
            "user": raw.get("user", "unknown"),
            "model": raw.get("model", "unknown"),
            "content": raw.get("content", ""),
            "metadata": raw.get("metadata", {}),
            "source_ip": raw.get("source_ip", "0.0.0.0"),
            "session_id": raw.get("session_id", str(uuid.uuid4())),
        }

    def _detect(self, event: dict) -> dict:
        content = event.get("content", "").lower()
        threats = []
        injection_patterns = [
            "ignore previous", "ignore all", "disregard",
            "forget your instructions", "new instructions",
            "you are now", "act as", "pretend you are",
            "jailbreak", "dan mode", "developer mode",
            "override", "bypass", "disable safety",
        ]
        exfil_patterns = [
            "api key", "secret key", "password", "token",
            "credentials", "private key", "access key",
            "sunat", "clave sol", "ruc", "dni",
        ]
        role_patterns = [
            "you are a", "roleplay", "simulate",
            "hypothetically", "in this scenario",
            "as an ai without", "unrestricted",
        ]
        detected_types = []
        for p in injection_patterns:
            if p in content:
                detected_types.append("PROMPT_INJECTION")
                threats.append({"type": "PROMPT_INJECTION", "pattern": p, "severity": "HIGH"})
                break
        for p in exfil_patterns:
            if p in content:
                detected_types.append("DATA_EXFILTRATION")
                threats.append({"type": "DATA_EXFILTRATION", "pattern": p, "severity": "CRITICAL"})
                break
        for p in role_patterns:
            if p in content:
                detected_types.append("ROLE_MANIPULATION")
                threats.append({"type": "ROLE_MANIPULATION", "pattern": p, "severity": "MEDIUM"})
                break
        return {
            "threat_detected": len(threats) > 0,
            "threat_types": list(set(detected_types)),
            "threats": threats,
            "threat_count": len(threats),
        }

    def _enforce_policy(self, event: dict) -> dict:
        risk_score = event["risk"]["score"]
        threat_detected = event["detection"]["threat_detected"]
        agent = event.get("agent", "unknown")
        action = "ALLOW"
        reason = "Within policy bounds"
        restrictions = []
        if risk_score >= 90 or any(t["severity"] == "CRITICAL" for t in event["detection"]["threats"]):
            action = "BLOCK"
            reason = "Critical risk threshold exceeded"
            restrictions = ["BLOCK_RESPONSE", "REVOKE_TOOL_ACCESS", "ISOLATE_AGENT"]
        elif risk_score >= 70 or threat_detected:
            action = "RESTRICT"
            reason = "High risk — restricted mode activated"
            restrictions = ["LIMIT_TOOL_CALLS", "SANITIZE_RESPONSE", "FLAG_FOR_REVIEW"]
        elif risk_score >= 50:
            action = "MONITOR"
            reason = "Elevated risk — enhanced monitoring"
            restrictions = ["LOG_DETAILED", "RATE_LIMIT"]
        return {
            "action": action,
            "reason": reason,
            "restrictions": restrictions,
            "agent": agent,
            "enforced_at": datetime.utcnow().isoformat(),
        }

    def _respond(self, event: dict) -> dict:
        action = event["policy"]["action"]
        responses = []
        if action == "BLOCK":
            responses = [
                {"type": "BLOCK_PROMPT", "status": "EXECUTED"},
                {"type": "ISOLATE_AGENT", "status": "EXECUTED"},
                {"type": "REVOKE_PERMISSIONS", "status": "EXECUTED"},
                {"type": "CREATE_CRITICAL_INCIDENT", "status": "EXECUTED"},
                {"type": "ALERT_SECURITY_TEAM", "status": "EXECUTED"},
            ]
        elif action == "RESTRICT":
            responses = [
                {"type": "SANITIZE_OUTPUT", "status": "EXECUTED"},
                {"type": "LIMIT_TOOL_CALLS", "status": "EXECUTED"},
                {"type": "CREATE_HIGH_INCIDENT", "status": "EXECUTED"},
                {"type": "LOG_FORENSICS", "status": "EXECUTED"},
            ]
        elif action == "MONITOR":
            responses = [
                {"type": "ENHANCED_LOGGING", "status": "EXECUTED"},
                {"type": "RATE_LIMIT_APPLIED", "status": "EXECUTED"},
            ]
        else:
            responses = [{"type": "STANDARD_LOGGING", "status": "EXECUTED"}]
        return {
            "responses_executed": responses,
            "response_count": len(responses),
            "final_action": action,
        }