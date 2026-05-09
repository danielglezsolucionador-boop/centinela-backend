from datetime import datetime
from typing import Optional
import uuid

RESPONSE_PLAYBOOKS = {
    "PROMPT_INJECTION": {
        "immediate": "BLOCK_PROMPT",
        "containment": "ISOLATE_SESSION",
        "remediation": "Revisar y actualizar system prompt del agente afectado",
        "escalation": "ALERT_HIGH",
        "auto_resolve": False,
    },
    "JAILBREAK": {
        "immediate": "BLOCK_PROMPT",
        "containment": "FLAG_USER",
        "remediation": "Analizar técnica de jailbreak y actualizar patrones de detección",
        "escalation": "ALERT_HIGH",
        "auto_resolve": False,
    },
    "DATA_EXFILTRATION": {
        "immediate": "BLOCK_PROMPT",
        "containment": "ISOLATE_AGENT",
        "remediation": "Auditar accesos recientes del agente y revisar permisos",
        "escalation": "ALERT_CRITICAL",
        "auto_resolve": False,
    },
    "SYSTEM_EXTRACTION": {
        "immediate": "BLOCK_PROMPT",
        "containment": "FLAG_SESSION",
        "remediation": "Verificar integridad del system prompt",
        "escalation": "ALERT_MEDIUM",
        "auto_resolve": True,
    },
    "ROLE_MANIPULATION": {
        "immediate": "BLOCK_PROMPT",
        "containment": "RESET_CONTEXT",
        "remediation": "Reforzar instrucciones de rol en el system prompt",
        "escalation": "ALERT_MEDIUM",
        "auto_resolve": True,
    },
}

class ResponseEngine:
    def __init__(self):
        self.active_containments = {}
        self.response_log = []
        self.response_stats = {
            "total_responses": 0,
            "blocks_executed": 0,
            "isolations": 0,
            "alerts_sent": 0,
            "by_type": {},
        }

    def respond(self, event: dict, detection: dict, policy: dict) -> dict:
        self.response_stats["total_responses"] += 1

        action = policy.get("action", "ALLOW")
        threat_types = detection.get("threat_types", [])
        agent = event.get("agent", "unknown")
        user = event.get("user", "unknown")
        event_id = event.get("id", str(uuid.uuid4()))

        if action == "ALLOW" and not threat_types:
            return {
                "response_id": str(uuid.uuid4()),
                "action_taken": "NONE",
                "status": "CLEAN",
                "timestamp": datetime.utcnow().isoformat(),
            }

        responses_taken = []
        playbook = None

        # Seleccionar playbook más severo
        severity_order = [
            "DATA_EXFILTRATION",
            "PROMPT_INJECTION",
            "JAILBREAK",
            "ROLE_MANIPULATION",
            "SYSTEM_EXTRACTION",
        ]

        for threat in severity_order:
            if threat in threat_types:
                playbook = RESPONSE_PLAYBOOKS[threat]
                primary_threat = threat
                break

        if not playbook and threat_types:
            primary_threat = threat_types[0]
            playbook = RESPONSE_PLAYBOOKS.get(primary_threat, {
                "immediate": "BLOCK_PROMPT",
                "containment": "FLAG_SESSION",
                "remediation": "Revisar actividad sospechosa",
                "escalation": "ALERT_MEDIUM",
                "auto_resolve": True,
            })

        # Ejecutar respuestas
        if not playbook:
            playbook = {
                "immediate": "BLOCK_PROMPT",
                "containment": "FLAG_SESSION",
                "remediation": "Revisar actividad sospechosa",
                "escalation": "ALERT_MEDIUM",
                "auto_resolve": True,
            }
        if action in ("BLOCK", "WARN"):
            responses_taken.append({
                "action": playbook.get("immediate", "BLOCK_PROMPT"),
                "target": f"prompt:{event_id}",
                "status": "EXECUTED",
                "timestamp": datetime.utcnow().isoformat(),
            })
            self.response_stats["blocks_executed"] += 1

            # Contención
            containment = playbook.get("containment", "FLAG_SESSION")
            if containment in ["ISOLATE_AGENT", "ISOLATE_SESSION"]:
                containment_id = str(uuid.uuid4())
                self.active_containments[containment_id] = {
                    "id": containment_id,
                    "agent": agent,
                    "user": user,
                    "type": containment,
                    "reason": primary_threat,
                    "started_at": datetime.utcnow().isoformat(),
                    "event_id": event_id,
                    "auto_resolve": playbook.get("auto_resolve", False),
                }
                responses_taken.append({
                    "action": containment,
                    "target": f"agent:{agent}",
                    "containment_id": containment_id,
                    "status": "EXECUTED",
                    "timestamp": datetime.utcnow().isoformat(),
                })
                self.response_stats["isolations"] += 1
            else:
                responses_taken.append({
                    "action": containment,
                    "target": f"session:{user}",
                    "status": "EXECUTED",
                    "timestamp": datetime.utcnow().isoformat(),
                })

        # Alerta
        escalation = playbook.get("escalation", "ALERT_MEDIUM")
        alert_level = escalation.replace("ALERT_", "")
        responses_taken.append({
            "action": "ALERT",
            "level": alert_level,
            "target": "security_team",
            "status": "SENT",
            "timestamp": datetime.utcnow().isoformat(),
        })
        self.response_stats["alerts_sent"] += 1

        # Actualizar stats por tipo
        if threat_types:
            for t in threat_types:
                if t not in self.response_stats["by_type"]:
                    self.response_stats["by_type"][t] = 0
                self.response_stats["by_type"][t] += 1

        response_record = {
            "response_id": str(uuid.uuid4()),
            "event_id": event_id,
            "action_taken": action,
            "threat_types": threat_types,
            "responses_executed": responses_taken,
            "remediation": playbook.get("remediation", "") if playbook else "",
            "auto_resolve": playbook.get("auto_resolve", False) if playbook else True,
            "agent": agent,
            "timestamp": datetime.utcnow().isoformat(),
        }

        self.response_log.append(response_record)
        if len(self.response_log) > 500:
            self.response_log = self.response_log[-250:]

        return response_record

    def get_active_containments(self) -> list:
        return list(self.active_containments.values())

    def resolve_containment(self, containment_id: str) -> dict:
        if containment_id in self.active_containments:
            containment = self.active_containments.pop(containment_id)
            containment["resolved_at"] = datetime.utcnow().isoformat()
            containment["status"] = "RESOLVED"
            return containment
        return {"error": "Containment not found"}

    def get_stats(self) -> dict:
        return {
            **self.response_stats,
            "active_containments": len(self.active_containments),
            "recent_responses": self.response_log[-10:],
        }