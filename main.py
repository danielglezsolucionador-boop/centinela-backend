from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
import uuid
from datetime import datetime
from core.pipeline.event_pipeline import EventPipeline
from core.engines.risk_engine import RiskEngine
from core.engines.threat_correlation import ThreatCorrelationEngine
from core.memory.threat_memory import ThreatMemory
from core.database import init_db, save_event, save_incident, get_stats

app = FastAPI(
    title="CENTINELA Core Intelligence Engine",
    description="AI Runtime Security Platform — Core Backend",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

threat_memory = ThreatMemory()
risk_engine = RiskEngine(threat_memory)
correlation_engine = ThreatCorrelationEngine(threat_memory)
pipeline = EventPipeline(risk_engine, correlation_engine, threat_memory)

@app.on_event("startup")
async def startup():
    init_db()

class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, data: dict):
        for ws in self.active:
            try:
                await ws.send_json(data)
            except:
                pass

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            event = json.loads(data)
            result = await pipeline.process(event)
            if result.get("detection", {}).get("threat_detected"):
                save_event(result)
                for inc in result.get("incidents", []):
                    save_incident(inc)
            await manager.broadcast(result)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.post("/api/v1/event")
async def ingest_event(event: dict):
    result = await pipeline.process(event)
    save_event(result)
    if result.get("detection", {}).get("threat_detected"):
        for inc in result.get("incidents", []):
            save_incident(inc)
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
    result = await pipeline.process(event)
    save_event(result)
    if result.get("detection", {}).get("threat_detected"):
        for inc in result.get("incidents", []):
            save_incident(inc)
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

@app.get("/api/v1/stats/db")
async def get_db_stats():
    return get_stats()

@app.get("/api/v1/health")
async def health():
    db_stats = get_stats()
    return {
        "status": "OPERATIONAL",
        "engine": "CENTINELA Core v1.0",
        "timestamp": datetime.utcnow().isoformat(),
        "database": "CONNECTED" if db_stats else "RAM_ONLY",
        "components": {
            "pipeline": "ONLINE",
            "risk_engine": "ONLINE",
            "correlation_engine": "ONLINE",
            "threat_memory": "ONLINE",
            "postgresql": "ONLINE" if db_stats else "PENDING",
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)