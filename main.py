from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
import uuid
from datetime import datetime
from core.pipeline.event_pipeline import EventPipeline
from core.engines.risk_engine import RiskEngine
from core.engines.threat_correlation import ThreatCorrelationEngine
from core.engines.threat_detection import ThreatDetectionEngine
from core.engines.policy_engine import PolicyEngine
from core.engines.response_engine import ResponseEngine
from core.engines.observability_engine import ObservabilityEngine
from core.engines.agent_security import AgentSecurityEngine
from core.memory.threat_memory import ThreatMemory
from core.database import init_db, save_event, save_incident, get_stats

app = FastAPI(
    title="CENTINELA Core Intelligence Engine",
    description="AI Runtime Security Platform — Core Backend",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inicializar todos los motores
threat_memory = ThreatMemory()
risk_engine = RiskEngine(threat_memory)
correlation_engine = ThreatCorrelationEngine(threat_memory)
threat_detection = ThreatDetectionEngine(threat_memory)
policy_engine = PolicyEngine()
response_engine = ResponseEngine()
observability_engine = ObservabilityEngine()
agent_security = AgentSecurityEngine()
pipeline = EventPipeline(risk_engine, correlation_engine, threat_memory)

@app.on_event("startup")
async def startup():
    init_db()
    print("CENTINELA Core v2.0 — All engines online")

class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        for ws in self.active:
            try:
                await ws.send_json(data)
            except:
                pass

manager = ConnectionManager()

async def process_full_pipeline(event: dict) -> dict:
    # 1. Pipeline base
    result = await pipeline.process(event)

    # 2. Threat Detection
    content = event.get("content", "")
    detection = threat_detection.analyze(content, {
        "agent": event.get("agent"),
        "model": event.get("model"),
        "user": event.get("user"),
    })

    # 3. Risk Engine
    risk = result.get("risk", {"score": 0, "level": "LOW"})

    # 4. Policy Engine
    policy = policy_engine.evaluate(event, detection, risk)

    # 5. Response Engine
    response = response_engine.respond(event, detection, policy)

    # 6. Observability
    trace = observability_engine.record_trace(event, detection, risk, policy)

    # 7. Agent Security
    agent_analysis = agent_security.analyze_agent_behavior(event, risk)

    # 8. Persistir en DB
    enriched = {
        **result,
        "detection": detection,
        "policy": policy,
        "response": response,
        "trace_id": trace.get("trace_id"),
        "agent_status": agent_analysis.get("status"),
    }
    save_event(enriched)

    if detection.get("threat_detected"):
        for inc in result.get("incidents", []):
            save_incident(inc)

    return enriched

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            event = json.loads(data)
            result = await process_full_pipeline(event)
            await manager.broadcast(result)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.post("/api/v1/event")
async def ingest_event(event: dict):
    result = await process_full_pipeline(event)
    await manager.broadcast(result)
    return result

@app.post("/api/v1/prompt/analyze")
async def analyze_prompt(payload: dict):
    event = {
        "id": str(uuid.uuid4()),
        "type": "PROMPT",
        "timestamp": datetime.utcnow().isoformat(),
        "agent": payload.get("agent", "unknown"),
        "user": payload.get("user", "unknown"),
        "model": payload.get("model", "claude-sonnet"),
        "content": payload.get("prompt", ""),
        "metadata": payload.get("metadata", {}),
    }
    result = await process_full_pipeline(event)
    await manager.broadcast(result)
    return result

@app.get("/api/v1/threat-memory")
async def get_threat_memory():
    return threat_memory.get_summary()

@app.get("/api/v1/risk/ecosystem")
async def get_ecosystem_risk():
    return risk_engine.get_ecosystem_scores()

@app.get("/api/v1/correlations/active")
async def get_active_correlations():
    return correlation_engine.get_active_correlations()

@app.get("/api/v1/incidents")
async def get_incidents():
    return threat_memory.get_incidents()

@app.get("/api/v1/detection/stats")
async def get_detection_stats():
    return threat_detection.get_stats()

@app.get("/api/v1/policy/all")
async def get_all_policies():
    return policy_engine.get_all_policies()

@app.post("/api/v1/policy/update")
async def update_policy(payload: dict):
    agent = payload.get("agent", "DEFAULT")
    updates = payload.get("updates", {})
    return policy_engine.update_policy(agent, updates)

@app.get("/api/v1/policy/stats")
async def get_policy_stats():
    return policy_engine.get_stats()

@app.get("/api/v1/response/stats")
async def get_response_stats():
    return response_engine.get_stats()

@app.get("/api/v1/response/containments")
async def get_containments():
    return response_engine.get_active_containments()

@app.post("/api/v1/response/resolve/{containment_id}")
async def resolve_containment(containment_id: str):
    return response_engine.resolve_containment(containment_id)

@app.get("/api/v1/observability/metrics")
async def get_observability_metrics():
    return observability_engine.get_dashboard_metrics()

@app.get("/api/v1/agents/map")
async def get_agent_map():
    return agent_security.get_agent_map()

@app.get("/api/v1/agents/stats")
async def get_agent_stats():
    return agent_security.get_stats()

@app.get("/api/v1/agents/anomalies")
async def get_agent_anomalies():
    return agent_security.get_recent_anomalies()

@app.get("/api/v1/stats/db")
async def get_db_stats():
    return get_stats()

@app.get("/api/v1/health")
async def health():
    db_stats = get_stats()
    return {
        "status": "OPERATIONAL",
        "engine": "CENTINELA Core v2.0",
        "timestamp": datetime.utcnow().isoformat(),
        "database": "CONNECTED" if db_stats else "RAM_ONLY",
        "engines": {
            "pipeline": "ONLINE",
            "risk_engine": "ONLINE",
            "threat_detection": "ONLINE",
            "correlation_engine": "ONLINE",
            "policy_engine": "ONLINE",
            "response_engine": "ONLINE",
            "observability_engine": "ONLINE",
            "agent_security": "ONLINE",
            "threat_memory": "ONLINE",
            "postgresql": "ONLINE" if db_stats else "PENDING",
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)