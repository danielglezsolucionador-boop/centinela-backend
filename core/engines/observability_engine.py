from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict
import uuid

class ObservabilityEngine:
    def __init__(self):
        self.traces = []
        self.model_metrics = defaultdict(lambda: {
            "total_calls": 0,
            "total_tokens": 0,
            "total_cost_usd": 0.0,
            "total_latency_ms": 0,
            "errors": 0,
            "hallucinations_detected": 0,
            "avg_latency_ms": 0,
        })
        self.agent_metrics = defaultdict(lambda: {
            "total_calls": 0,
            "blocked_calls": 0,
            "tool_calls": 0,
            "anomalies": 0,
            "avg_risk_score": 0,
            "risk_scores": [],
        })
        self.hourly_stats = defaultdict(lambda: {
            "calls": 0,
            "threats": 0,
            "blocked": 0,
            "tokens": 0,
        })
        self.anomalies = []
        self.stats = {
            "total_traces": 0,
            "total_tokens_used": 0,
            "total_cost_usd": 0.0,
            "total_hallucinations": 0,
            "total_errors": 0,
        }

        # Costos por modelo (USD por 1M tokens)
        self.model_costs = {
            "claude-haiku": {"input": 0.25, "output": 1.25},
            "claude-haiku-4-5": {"input": 0.25, "output": 1.25},
            "claude-sonnet": {"input": 3.0, "output": 15.0},
            "claude-sonnet-4": {"input": 3.0, "output": 15.0},
            "claude-opus": {"input": 15.0, "output": 75.0},
            "gpt-4o": {"input": 2.5, "output": 10.0},
            "gpt-4o-mini": {"input": 0.15, "output": 0.60},
            "default": {"input": 1.0, "output": 5.0},
        }

    def record_trace(self, event: dict, detection: dict, risk: dict, policy: dict) -> dict:
        self.stats["total_traces"] += 1

        model = event.get("model", "unknown")
        agent = event.get("agent", "unknown")
        content = event.get("content", "")
        latency_ms = event.get("metadata", {}).get("latency_ms", 0)
        input_tokens = event.get("metadata", {}).get("input_tokens", len(content.split()) * 1.3)
        output_tokens = event.get("metadata", {}).get("output_tokens", 0)
        is_error = event.get("metadata", {}).get("error", False)
        is_blocked = policy.get("blocked", False)
        risk_score = risk.get("score", 0)
        threat_detected = detection.get("threat_detected", False)

        # Calcular costo
        costs = self.model_costs.get(model, self.model_costs["default"])
        cost = (input_tokens / 1_000_000 * costs["input"]) + (output_tokens / 1_000_000 * costs["output"])

        # Detectar alucinación (heurística simple)
        hallucination_detected = self._detect_hallucination(event)

        # Actualizar métricas por modelo
        mm = self.model_metrics[model]
        mm["total_calls"] += 1
        mm["total_tokens"] += int(input_tokens + output_tokens)
        mm["total_cost_usd"] += cost
        mm["total_latency_ms"] += latency_ms
        mm["avg_latency_ms"] = mm["total_latency_ms"] / mm["total_calls"]
        if is_error:
            mm["errors"] += 1
        if hallucination_detected:
            mm["hallucinations_detected"] += 1

        # Actualizar métricas por agente
        am = self.agent_metrics[agent]
        am["total_calls"] += 1
        am["risk_scores"].append(risk_score)
        am["avg_risk_score"] = sum(am["risk_scores"]) / len(am["risk_scores"])
        if is_blocked:
            am["blocked_calls"] += 1
        if threat_detected:
            am["anomalies"] += 1
        if len(am["risk_scores"]) > 100:
            am["risk_scores"] = am["risk_scores"][-50:]

        # Stats por hora
        hour_key = datetime.utcnow().strftime("%Y-%m-%d %H:00")
        hs = self.hourly_stats[hour_key]
        hs["calls"] += 1
        hs["tokens"] += int(input_tokens + output_tokens)
        if threat_detected:
            hs["threats"] += 1
        if is_blocked:
            hs["blocked"] += 1

        # Stats globales
        self.stats["total_tokens_used"] += int(input_tokens + output_tokens)
        self.stats["total_cost_usd"] += cost
        if hallucination_detected:
            self.stats["total_hallucinations"] += 1
        if is_error:
            self.stats["total_errors"] += 1

        # Detectar anomalías
        anomaly = self._detect_anomaly(agent, risk_score, latency_ms, am)
        if anomaly:
            self.anomalies.append(anomaly)
            if len(self.anomalies) > 200:
                self.anomalies = self.anomalies[-100:]

        trace = {
            "trace_id": str(uuid.uuid4()),
            "event_id": event.get("id"),
            "agent": agent,
            "model": model,
            "timestamp": datetime.utcnow().isoformat(),
            "latency_ms": latency_ms,
            "input_tokens": int(input_tokens),
            "output_tokens": int(output_tokens),
            "cost_usd": round(cost, 6),
            "risk_score": risk_score,
            "threat_detected": threat_detected,
            "blocked": is_blocked,
            "hallucination_detected": hallucination_detected,
            "error": is_error,
            "anomaly": anomaly is not None,
        }

        self.traces.append(trace)
        if len(self.traces) > 1000:
            self.traces = self.traces[-500:]

        return trace

    def _detect_hallucination(self, event: dict) -> bool:
        content = event.get("content", "").lower()
        hallucination_signals = [
            "como ia no tengo acceso",
            "no puedo verificar",
            "según mis datos de entrenamiento",
            "no tengo información actualizada",
            "podría estar equivocado",
        ]
        return any(signal in content for signal in hallucination_signals)

    def _detect_anomaly(self, agent: str, risk_score: float, latency_ms: float, agent_metrics: dict) -> Optional[dict]:
        anomaly = None

        # Riesgo anormalmente alto
        avg_risk = agent_metrics.get("avg_risk_score", 0)
        if risk_score > 70 and risk_score > avg_risk * 2:
            anomaly = {
                "type": "RISK_SPIKE",
                "agent": agent,
                "detail": f"Risk score {risk_score} es {round(risk_score/max(avg_risk,1), 1)}x el promedio",
                "severity": "HIGH",
                "timestamp": datetime.utcnow().isoformat(),
            }

        # Latencia anormalmente alta
        elif latency_ms > 10000:
            anomaly = {
                "type": "HIGH_LATENCY",
                "agent": agent,
                "detail": f"Latencia de {latency_ms}ms detectada",
                "severity": "MEDIUM",
                "timestamp": datetime.utcnow().isoformat(),
            }

        # Muchas llamadas bloqueadas
        elif agent_metrics["total_calls"] > 10:
            block_rate = agent_metrics["blocked_calls"] / agent_metrics["total_calls"]
            if block_rate > 0.3:
                anomaly = {
                    "type": "HIGH_BLOCK_RATE",
                    "agent": agent,
                    "detail": f"Tasa de bloqueo del {round(block_rate*100)}% detectada",
                    "severity": "HIGH",
                    "timestamp": datetime.utcnow().isoformat(),
                }

        return anomaly

    def get_dashboard_metrics(self) -> dict:
        model_summary = {}
        for model, metrics in self.model_metrics.items():
            model_summary[model] = {
                "calls": metrics["total_calls"],
                "tokens": metrics["total_tokens"],
                "cost_usd": round(metrics["total_cost_usd"], 4),
                "avg_latency_ms": round(metrics["avg_latency_ms"], 1),
                "errors": metrics["errors"],
                "hallucinations": metrics["hallucinations_detected"],
            }

        agent_summary = {}
        for agent, metrics in self.agent_metrics.items():
            agent_summary[agent] = {
                "calls": metrics["total_calls"],
                "blocked": metrics["blocked_calls"],
                "anomalies": metrics["anomalies"],
                "avg_risk": round(metrics["avg_risk_score"], 1),
                "block_rate": round(
                    metrics["blocked_calls"] / max(metrics["total_calls"], 1) * 100, 1
                ),
            }

        # Últimas 24 horas
        now = datetime.utcnow()
        hourly = []
        for i in range(24):
            hour = now - timedelta(hours=i)
            key = hour.strftime("%Y-%m-%d %H:00")
            stats = self.hourly_stats.get(key, {"calls": 0, "threats": 0, "blocked": 0, "tokens": 0})
            hourly.append({"hour": key, **stats})

        return {
            "global": {
                **self.stats,
                "total_cost_usd": round(self.stats["total_cost_usd"], 4),
            },
            "by_model": model_summary,
            "by_agent": agent_summary,
            "hourly_last_24h": list(reversed(hourly)),
            "recent_anomalies": self.anomalies[-10:],
            "recent_traces": self.traces[-20:],
        }

    def get_stats(self) -> dict:
        return self.get_dashboard_metrics()