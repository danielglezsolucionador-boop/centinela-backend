from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict
import uuid

AGENT_PROFILES = {
    "PLUMA": {
        "allowed_tools": ["text_generation", "content_analysis", "translation", "summarization"],
        "max_tool_calls_per_hour": 200,
        "max_context_length": 10000,
        "risk_baseline": 15,
        "capabilities": ["write", "analyze", "translate"],
    },
    "LENTE": {
        "allowed_tools": ["video_analysis", "trend_detection", "content_generation", "scheduling"],
        "max_tool_calls_per_hour": 150,
        "max_context_length": 8000,
        "risk_baseline": 20,
        "capabilities": ["analyze", "generate", "schedule"],
    },
    "CEREBRO": {
        "allowed_tools": ["strategy_analysis", "decision_making", "orchestration", "reporting"],
        "max_tool_calls_per_hour": 100,
        "max_context_length": 15000,
        "risk_baseline": 10,
        "capabilities": ["orchestrate", "decide", "report", "analyze"],
    },
    "MCF": {
        "allowed_tools": ["financial_analysis", "sunat_query", "report_generation", "tax_calculation"],
        "max_tool_calls_per_hour": 80,
        "max_context_length": 5000,
        "risk_baseline": 25,
        "capabilities": ["analyze", "calculate", "report"],
    },
    "BUSCADOR": {
        "allowed_tools": ["web_search", "trend_analysis", "data_extraction", "summarization"],
        "max_tool_calls_per_hour": 300,
        "max_context_length": 3000,
        "risk_baseline": 20,
        "capabilities": ["search", "extract", "analyze"],
    },
    "SNIFF_AMAZON": {
        "allowed_tools": ["product_search", "price_analysis", "market_research", "csv_export"],
        "max_tool_calls_per_hour": 200,
        "max_context_length": 4000,
        "risk_baseline": 30,
        "capabilities": ["search", "analyze", "export"],
    },
    "LABORATORIO": {
        "allowed_tools": ["content_generation", "social_media_post", "analytics", "scheduling"],
        "max_tool_calls_per_hour": 150,
        "max_context_length": 8000,
        "risk_baseline": 15,
        "capabilities": ["generate", "post", "analyze"],
    },
    "CREADOR_APIS": {
        "allowed_tools": ["api_generation", "code_analysis", "testing", "documentation"],
        "max_tool_calls_per_hour": 100,
        "max_context_length": 6000,
        "risk_baseline": 35,
        "capabilities": ["generate", "analyze", "test", "document"],
    },
}

class AgentSecurityEngine:
    def __init__(self):
        self.agent_sessions = {}
        self.tool_call_log = []
        self.anomaly_log = []
        self.agent_stats = defaultdict(lambda: {
            "total_events": 0,
            "tool_calls": 0,
            "anomalies_detected": 0,
            "risk_scores": [],
            "avg_risk": 0,
            "status": "NORMAL",
            "last_seen": None,
        })
        self.hourly_tool_calls = defaultdict(lambda: defaultdict(int))

    def analyze_agent_behavior(self, event: dict, risk: dict) -> dict:
        agent = event.get("agent", "unknown").upper()
        event_id = event.get("id", str(uuid.uuid4()))
        risk_score = risk.get("score", 0)
        tool_calls = event.get("metadata", {}).get("tool_calls", [])
        timestamp = datetime.utcnow()

        profile = AGENT_PROFILES.get(agent, {
            "allowed_tools": [],
            "max_tool_calls_per_hour": 100,
            "max_context_length": 5000,
            "risk_baseline": 25,
            "capabilities": [],
        })

        anomalies = []
        behavior_score = 0

        # Actualizar stats del agente
        stats = self.agent_stats[agent]
        stats["total_events"] += 1
        stats["last_seen"] = timestamp.isoformat()
        stats["risk_scores"].append(risk_score)
        if len(stats["risk_scores"]) > 100:
            stats["risk_scores"] = stats["risk_scores"][-50:]
        stats["avg_risk"] = round(sum(stats["risk_scores"]) / len(stats["risk_scores"]), 1)

        # Analizar tool calls
        unauthorized_tools = []
        for tool in tool_calls:
            tool_name = tool.get("name", "") if isinstance(tool, dict) else str(tool)
            stats["tool_calls"] += 1

            # Registrar tool call
            self.tool_call_log.append({
                "agent": agent,
                "tool": tool_name,
                "timestamp": timestamp.isoformat(),
                "event_id": event_id,
            })

            # Verificar si tool está permitida
            if profile["allowed_tools"] and tool_name not in profile["allowed_tools"]:
                unauthorized_tools.append(tool_name)
                behavior_score += 25

        if unauthorized_tools:
            anomalies.append({
                "type": "UNAUTHORIZED_TOOL_USE",
                "detail": f"Herramientas no autorizadas: {', '.join(unauthorized_tools)}",
                "severity": "HIGH",
                "agent": agent,
                "timestamp": timestamp.isoformat(),
            })

        # Verificar rate de tool calls por hora
        hour_key = timestamp.strftime("%Y-%m-%d-%H")
        self.hourly_tool_calls[agent][hour_key] += len(tool_calls)
        hourly_count = self.hourly_tool_calls[agent][hour_key]

        if hourly_count > profile["max_tool_calls_per_hour"]:
            anomalies.append({
                "type": "TOOL_CALL_RATE_EXCEEDED",
                "detail": f"{hourly_count} tool calls en la última hora (límite: {profile['max_tool_calls_per_hour']})",
                "severity": "MEDIUM",
                "agent": agent,
                "timestamp": timestamp.isoformat(),
            })
            behavior_score += 20

        # Detectar risk drift
        baseline = profile.get("risk_baseline", 20)
        if risk_score > baseline * 2.5 and stats["avg_risk"] > baseline * 1.5:
            anomalies.append({
                "type": "RISK_DRIFT_DETECTED",
                "detail": f"Risk score {risk_score} significativamente sobre baseline {baseline}",
                "severity": "HIGH",
                "agent": agent,
                "timestamp": timestamp.isoformat(),
            })
            behavior_score += 30

        # Detectar comportamiento repetitivo sospechoso
        recent_events = [
            e for e in self.tool_call_log[-50:]
            if e["agent"] == agent and
            datetime.fromisoformat(e["timestamp"]) > timestamp - timedelta(minutes=5)
        ]
        if len(recent_events) > 20:
            anomalies.append({
                "type": "RAPID_REPEATED_CALLS",
                "detail": f"{len(recent_events)} llamadas en los últimos 5 minutos",
                "severity": "MEDIUM",
                "agent": agent,
                "timestamp": timestamp.isoformat(),
            })
            behavior_score += 15

        # Actualizar status del agente
        if behavior_score >= 50 or any(a["severity"] == "HIGH" for a in anomalies):
            stats["status"] = "SUSPICIOUS"
        elif behavior_score >= 25:
            stats["status"] = "MONITORING"
        else:
            stats["status"] = "NORMAL"

        if anomalies:
            stats["anomalies_detected"] += len(anomalies)
            self.anomaly_log.extend(anomalies)
            if len(self.anomaly_log) > 500:
                self.anomaly_log = self.anomaly_log[-250:]

        # Limpiar tool call log
        if len(self.tool_call_log) > 1000:
            self.tool_call_log = self.tool_call_log[-500:]

        return {
            "agent": agent,
            "behavior_score": behavior_score,
            "status": stats["status"],
            "anomalies": anomalies,
            "tool_calls_analyzed": len(tool_calls),
            "unauthorized_tools": unauthorized_tools,
            "hourly_tool_calls": hourly_count,
            "avg_risk_score": stats["avg_risk"],
            "analysis_timestamp": timestamp.isoformat(),
        }

    def get_agent_map(self) -> list:
        agents = []
        for agent_name, profile in AGENT_PROFILES.items():
            stats = self.agent_stats[agent_name]
            agents.append({
                "name": agent_name,
                "status": stats["status"],
                "total_events": stats["total_events"],
                "tool_calls": stats["tool_calls"],
                "anomalies": stats["anomalies_detected"],
                "avg_risk": stats["avg_risk"],
                "last_seen": stats["last_seen"],
                "allowed_tools": profile["allowed_tools"],
                "capabilities": profile["capabilities"],
                "risk_baseline": profile["risk_baseline"],
            })
        return agents

    def get_recent_anomalies(self, limit: int = 20) -> list:
        return self.anomaly_log[-limit:]

    def get_stats(self) -> dict:
        total_anomalies = sum(s["anomalies_detected"] for s in self.agent_stats.values())
        suspicious_agents = [
            name for name, s in self.agent_stats.items()
            if s["status"] == "SUSPICIOUS"
        ]
        return {
            "total_agents": len(AGENT_PROFILES),
            "active_agents": len([s for s in self.agent_stats.values() if s["total_events"] > 0]),
            "suspicious_agents": suspicious_agents,
            "total_anomalies": total_anomalies,
            "total_tool_calls": sum(s["tool_calls"] for s in self.agent_stats.values()),
            "agent_details": dict(self.agent_stats),
        }