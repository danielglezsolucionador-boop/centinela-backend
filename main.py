from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
import json
import uuid
from datetime import datetime
import logging
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("centinela")
from core.pipeline.event_pipeline import EventPipeline
from core.engines.risk_engine import RiskEngine
from core.engines.threat_correlation import ThreatCorrelationEngine
from core.engines.threat_detection import ThreatDetectionEngine
from core.engines.policy_engine import PolicyEngine
from core.engines.response_engine import ResponseEngine
from core.engines.observability_engine import ObservabilityEngine
from core.engines.agent_security import AgentSecurityEngine
from core.memory.threat_memory import ThreatMemory
from core.database import init_db, save_event, save_incident, get_stats, SessionLocal, IncidentModel
from core.auth import (
    get_current_user, get_admin_user, init_default_admin,
    create_access_token, verify_password, create_user, get_user
)

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="CENTINELA Core Intelligence Engine",
    description="AI Runtime Security Platform â€” Core Backend",
    version="2.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://centinela-btdd.vercel.app",
        "http://localhost:3000",
        "http://localhost:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# â”€â”€ Initialize Core Engines â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
threat_memory = ThreatMemory()
threat_memory.hydrate_from_db()
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
    init_default_admin()
    print("CENTINELA Core v2.0 â€” All engines online")

# â”€â”€ WebSocket Manager â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

# â”€â”€ Full Pipeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async def process_full_pipeline(event: dict) -> dict:
    t0 = time.time()
    logger.info(f"PIPELINE START | agent={event.get('agent')} user={event.get('user')} id={event.get('id','')[:8]}")
    result = await pipeline.process(event)
    content = event.get("content", "")
    detection = result.get("detection", threat_detection.analyze(content, {
        "agent": event.get("agent"),
        "model": event.get("model"),
        "user": event.get("user"),
    }))
    risk = result.get("risk", {"score": 0, "level": "LOW"})
    if detection.get("threat_detected"):
         risk["score"] = max(risk.get("score", 0), 75)
    policy = policy_engine.evaluate(event, detection, risk)
    response = response_engine.respond(event, detection, policy)
    trace = observability_engine.record_trace(event, detection, risk, policy)
    agent_analysis = agent_security.analyze_agent_behavior(event, risk)
    enriched = {
        **result,
        "user": event.get("user", "unknown"),
        "agent": event.get("agent", "unknown"),
        "model": event.get("model", "unknown"),
        "detection": detection,
        "policy": policy,
        "response": response,
        "trace_id": trace.get("trace_id"),
        "agent_status": agent_analysis.get("status"),
    }
    save_event(enriched)
    elapsed = round((time.time()-t0)*1000)
    threat = detection.get("threat_detected", False)
    action = enriched.get("policy", {}).get("action", "?")
    logger.info(f"PIPELINE END | agent={event.get('agent')} threat={threat} action={action} risk={enriched.get('risk',{}).get('score',0)} ms={elapsed}")
    if detection.get("threat_detected"):
        incident = result.get("incident") or {}
        incident_to_save = {
            "id": incident.get("id") or f"INC-{str(uuid.uuid4())[:6].upper()}",
            "severity": incident.get("severity") or risk.get("level", "MEDIUM"),
            "agent": event.get("agent"),
            "user": event.get("user"),
            "risk_score": risk.get("score", 0),
            "threat_types": detection.get("threat_types", []),
            "policy_action": policy.get("action", "BLOCK"),
            "status": "OPEN",
            "event_id": event.get("id"),
        }
        save_incident(incident_to_save)
        logger.warning(f"INCIDENT CREATED | id={incident_to_save['id']} agent={incident_to_save['agent']} severity={incident_to_save['severity']} risk={incident_to_save['risk_score']}")
    return enriched

# â”€â”€ Auth Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.post("/api/v1/auth/login")
async def login(payload: dict):
    username = payload.get("username")
    password = payload.get("password")
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    user = get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=401, detail="User inactive")
    token = create_access_token({"sub": user.username})
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin,
    }

@app.post("/api/v1/auth/register")
async def register(payload: dict, current_user=Depends(get_admin_user)):
    username = payload.get("username")
    email = payload.get("email")
    password = payload.get("password")
    is_admin = payload.get("is_admin", False)
    if not username or not email or not password:
        raise HTTPException(status_code=400, detail="username, email and password required")
    existing = get_user(username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    user = create_user(username, email, password, is_admin)
    return {"id": user.id, "username": user.username, "email": user.email, "is_admin": user.is_admin}

@app.get("/api/v1/auth/me")
async def me(current_user=Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "is_admin": current_user.is_admin,
        "created_at": current_user.created_at,
    }

# â”€â”€ WebSocket â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

# â”€â”€ Protected Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.post("/api/v1/event")
async def ingest_event(event: dict, current_user=Depends(get_current_user)):
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
        "user": payload.get("user", "anonymous"),
        "model": payload.get("model", "claude-sonnet"),
        "content": payload.get("content", payload.get("prompt", "")),
        "metadata": payload.get("metadata", {}),
    }
    result = await process_full_pipeline(event)
    await manager.broadcast(result)
    return result

@app.get("/api/v1/threat-memory")
async def get_threat_memory(current_user=Depends(get_current_user)):
    return get_stats()

@app.get("/api/v1/risk/ecosystem")
async def get_ecosystem_risk(current_user=Depends(get_current_user)):
    return risk_engine.get_ecosystem_scores()

@app.get("/api/v1/correlations/active")
async def get_active_correlations(current_user=Depends(get_current_user)):
    return correlation_engine.get_active_correlations()

@app.get("/api/v1/incidents")
async def get_incidents(current_user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        records = db.query(IncidentModel).order_by(IncidentModel.created_at.desc()).limit(100).all()
        result = []
        for r in records:
            try:
                if not r.threat_types or not r.threat_types.strip():
                    threat_types = []
                elif r.threat_types.startswith("["):
                    threat_types = json.loads(r.threat_types)
                else:
                    threat_types = [t.strip() for t in r.threat_types.split(",") if t.strip()]
            except:
                threat_types = []
            result.append({
                "id": r.id,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "severity": r.severity,
                "agent": r.agent,
                "user": r.user,
                "risk_score": r.risk_score,
                "threat_types": threat_types,
                "policy_action": r.policy_action,
                "status": r.status,
                "event_id": r.event_id,
            })
        return result
    except Exception as e:
        return {"error": str(e)}
    finally:
        db.close()

@app.get("/api/v1/detection/stats")
async def get_detection_stats(current_user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        from sqlalchemy import func
        total = db.query(func.count(EventModel.id)).scalar() or 0
        detected = db.query(func.count(EventModel.id)).filter(EventModel.threat_detected == True).scalar() or 0
        by_type_raw = db.query(EventModel.threat_types).filter(EventModel.threat_detected == True).all()
        by_type = {}
        for row in by_type_raw:
            if row[0]:
                for t in row[0].split(","):
                    t = t.strip()
                    if t: by_type[t] = by_type.get(t, 0) + 1
        all_types = ["PROMPT_INJECTION","JAILBREAK","DATA_EXFILTRATION","SYSTEM_EXTRACTION","ROLE_MANIPULATION","PII_LEAKAGE","TOOL_ABUSE"]
        return {"total_analyzed": total, "threats_detected": detected, "by_type": {t: by_type.get(t, 0) for t in all_types}, "detection_rate": round(detected / total * 100, 2) if total > 0 else 0}
    except Exception as e:
        return threat_detection.get_stats()
    finally:
        db.close()

@app.get("/api/v1/policy/all")
async def get_all_policies(current_user=Depends(get_current_user)):
    return policy_engine.get_all_policies()

@app.post("/api/v1/policy/update")
async def update_policy(payload: dict, current_user=Depends(get_admin_user)):
    agent = payload.get("agent", "DEFAULT")
    updates = payload.get("updates", {})
    return policy_engine.update_policy(agent, updates)

@app.get("/api/v1/policy/stats")
async def get_policy_stats(current_user=Depends(get_current_user)):
    return policy_engine.get_stats()

@app.get("/api/v1/response/stats")
async def get_response_stats(current_user=Depends(get_current_user)):
    return response_engine.get_stats()

@app.get("/api/v1/response/containments")
async def get_containments(current_user=Depends(get_current_user)):
    return response_engine.get_active_containments()

@app.post("/api/v1/response/resolve/{containment_id}")
async def resolve_containment(containment_id: str, current_user=Depends(get_admin_user)):
    return response_engine.resolve_containment(containment_id)

@app.get("/api/v1/observability/metrics")
async def get_observability_metrics(current_user=Depends(get_current_user)):
    return observability_engine.get_dashboard_metrics()

@app.get("/api/v1/agents/map")
async def get_agent_map(current_user=Depends(get_current_user)):
    return agent_security.get_agent_map()

@app.get("/api/v1/agents/stats")
async def get_agent_stats(current_user=Depends(get_current_user)):
    return agent_security.get_stats()

@app.get("/api/v1/agents/anomalies")
async def get_agent_anomalies(current_user=Depends(get_current_user)):
    return agent_security.get_recent_anomalies()

@app.get("/api/v1/stats/db")
async def get_db_stats(current_user=Depends(get_current_user)):
    return get_stats()

# â”€â”€ Health (pÃºblico) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.post("/api/v1/admin/reset")
async def reset_admin(current_user=Depends(get_admin_user)):
    from core.database import SessionLocal
    from core.auth import UserModel, create_user
    db = SessionLocal()
    try:
        db.query(UserModel).filter(UserModel.username == "daniel").delete()
        db.commit()
    finally:
        db.close()
    create_user("daniel", "daniel.glez.solucionador@gmail.com", "Centinela24", is_admin=True)
    return {"status": "admin reset ok"}
@app.post("/api/v1/admin/migrate")
async def run_migration(current_user=Depends(get_admin_user)):
    from core.database import engine
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            conn.execute(text('ALTER TABLE events RENAME COLUMN "user" TO user_id'))
            conn.commit()
        return {"status": "migrated"}
    except Exception as e:
        return {"status": "already done", "detail": str(e)}
@app.get("/api/v1/admin/db-columns")
async def get_db_columns(current_user=Depends(get_admin_user)):
    from core.database import engine
    from sqlalchemy import text
    with engine.connect() as conn:
        result = conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='events'"))
        return {"columns": [row[0] for row in result]}
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
@app.post("/api/v1/admin/reset-db")
async def reset_db(request: Request, current_user=Depends(get_current_user)):
    body = await request.json()
    if body.get("confirm") != "yes":
        return {"error": "Send confirm=yes"}
    from core.database import Base, engine
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    return {"status": "DB recreada limpia"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
    



