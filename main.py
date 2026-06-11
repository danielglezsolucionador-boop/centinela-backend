from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
import json
import uuid
from datetime import datetime, timedelta
import logging
import sys
import time
import os
import subprocess

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
from core.intelligence.historical_memory import HistoricalMemoryCorrelation
from core.intelligence.operational_intelligence import OperationalIntelligenceFoundation
from core.intelligence.phase3_foundations import PhaseThreeFoundations
from core.intelligence.phase4_resilience import PhaseFourResilience
from core.intelligence.phase5_ecosystem import PhaseFiveEcosystem
from core.intelligence.phase6_adversarial import PhaseSixAdversarial
from core.intelligence.phase7_governance import PhaseSevenGovernance
from core.memory.threat_memory import ThreatMemory
from core.database import (
    NormalizedEventModel,
    HumanReviewRequestModel,
    HumanReviewAuditEventModel,
    SentinelaClientSecuritySummaryModel,
    SentinelaPricingPlanModel,
    delete_old_normalized_events,
    init_db,
    normalized_event_to_dict,
    save_event,
    save_incident,
    save_normalized_event,
    get_stats,
    SessionLocal,
    EventModel,
    IncidentModel,
)
from core.auth import (
    get_current_user, get_admin_user, init_default_admin,
    create_access_token, verify_password, create_user, get_user
)

RUNTIME_VERSION = "2.0.0"

def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").lower() in {"1", "true", "yes", "on"}

SERVERLESS_MODE = _env_flag("SERVERLESS_MODE") or _env_flag("VERCEL")

def _local_git_value(args: list[str], fallback: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", os.path.dirname(__file__), *args],
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
        ).strip() or fallback
    except Exception:
        return fallback

def _deployment_target_default() -> str:
    vercel_url = os.environ.get("VERCEL_URL")
    if vercel_url:
        return f"https://{vercel_url}"
    return "Render backend: https://centinela-backend-kzwk.onrender.com"

PROVENANCE_BRANCH = (
    os.environ.get("VERCEL_GIT_COMMIT_REF")
    or os.environ.get("RENDER_GIT_BRANCH")
    or _local_git_value(["branch", "--show-current"], "main")
)
PROVENANCE_COMMIT = (
    os.environ.get("VERCEL_GIT_COMMIT_SHA")
    or os.environ.get("RENDER_GIT_COMMIT")
    or os.environ.get("GIT_COMMIT")
    or _local_git_value(["rev-parse", "HEAD"], "unknown")
)
PROVENANCE_BUILD_TIMESTAMP = os.environ.get("BUILD_TIMESTAMP", "2026-05-27T06:09:24-05:00")
PROVENANCE_DEPLOYMENT_TARGET = os.environ.get(
    "DEPLOYMENT_TARGET",
    _deployment_target_default(),
)
PROVENANCE_PHASE_STATUS = "Phase 2.3 provenance visible; no secrets or local paths exposed"

def public_provenance() -> dict:
    return {
        "app_name": "CENTINELA Backend",
        "runtime_version": RUNTIME_VERSION,
        "repo_branch": PROVENANCE_BRANCH,
        "current_commit": PROVENANCE_COMMIT,
        "build_timestamp": PROVENANCE_BUILD_TIMESTAMP,
        "deployment_target": PROVENANCE_DEPLOYMENT_TARGET,
        "phase_status": PROVENANCE_PHASE_STATUS,
    }

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="CENTINELA Core Intelligence Engine",
    description="AI Runtime Security Platform â€” Core Backend",
    version=RUNTIME_VERSION
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
cors_origins = [
    "https://centinela-alpha.vercel.app",
    "https://centinela-btdd.vercel.app",
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:3107",
    "http://localhost:3111",
    "http://127.0.0.1:3107",
    "http://127.0.0.1:3111",
]
extra_cors_origins = [
    origin.strip()
    for origin in os.environ.get("CORS_ORIGINS", "").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(set(cors_origins + extra_cors_origins)),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# â”€â”€ Initialize Core Engines â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
threat_memory = ThreatMemory()
if SERVERLESS_MODE:
    logger.info("SERVERLESS MODE | threat memory hydration deferred")
else:
    threat_memory.hydrate_from_db()
risk_engine = RiskEngine(threat_memory)
correlation_engine = ThreatCorrelationEngine(threat_memory)
threat_detection = ThreatDetectionEngine(threat_memory)
policy_engine = PolicyEngine()
response_engine = ResponseEngine()
observability_engine = ObservabilityEngine()
agent_security = AgentSecurityEngine()
pipeline = EventPipeline(risk_engine, correlation_engine, threat_memory)
operational_intelligence = OperationalIntelligenceFoundation()
historical_memory = HistoricalMemoryCorrelation()
phase3_foundations = PhaseThreeFoundations()
phase4_resilience = PhaseFourResilience()
phase5_ecosystem = PhaseFiveEcosystem()
phase6_adversarial = PhaseSixAdversarial()
phase7_governance = PhaseSevenGovernance()

@app.on_event("startup")
async def startup():
    if SERVERLESS_MODE:
        logger.info("SERVERLESS MODE | DB startup initialization deferred")
        print("CENTINELA Core v2.0 - serverless startup ready")
        return
    db_ready = init_db()
    if db_ready:
        init_default_admin()
    else:
        logger.warning("DB unavailable during startup; API will expose degraded health")
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
    save_normalized_event(enriched.get("operational_intelligence", {}))
    delete_old_normalized_events(retention_days=30)
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
@limiter.limit("5/minute")
async def login(request: Request, payload: dict):
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
        "content": payload.get("content", payload.get("prompt", ""))[:10000],
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

@app.get("/api/v1/intelligence/operational")
async def get_operational_intelligence(current_user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = db.query(EventModel).order_by(EventModel.timestamp.desc()).limit(100).all()
        events = [operational_intelligence.event_from_database_row(row) for row in rows]
        return operational_intelligence.build_snapshot(events)
    finally:
        db.close()

@app.get("/api/v1/intelligence/temporal-correlation")
async def get_temporal_correlation(current_user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        rows = db.query(NormalizedEventModel).order_by(NormalizedEventModel.timestamp.desc()).limit(200).all()
        events = [normalized_event_to_dict(row) for row in rows]
        if not events:
            legacy_rows = db.query(EventModel).order_by(EventModel.timestamp.desc()).limit(100).all()
            events = [
                operational_intelligence.normalize_event(
                    operational_intelligence.event_from_database_row(row)
                )
                for row in legacy_rows
            ]
            snapshot = historical_memory.build_temporal_snapshot(events)
            snapshot["data_state"] = "DERIVED_FROM_LEGACY_EVENTS_NOT_PERSISTED" if events else "INSUFFICIENT_DATA"
            return snapshot
        return historical_memory.build_temporal_snapshot(events)
    finally:
        db.close()

def _normalized_events_for_intelligence(limit: int = 200) -> list[dict]:
    db = SessionLocal()
    try:
        try:
            rows = db.query(NormalizedEventModel).order_by(NormalizedEventModel.timestamp.desc()).limit(limit).all()
            events = [normalized_event_to_dict(row) for row in rows]
        except Exception as exc:
            logger.warning(f"normalized event query unavailable: {exc}")
            events = []
        if events:
            return events
        try:
            legacy_rows = db.query(EventModel).order_by(EventModel.timestamp.desc()).limit(min(limit, 100)).all()
            return [
                operational_intelligence.normalize_event(
                    operational_intelligence.event_from_database_row(row)
                )
                for row in legacy_rows
            ]
        except Exception as exc:
            logger.warning(f"legacy event fallback unavailable: {exc}")
            return []
    finally:
        db.close()

def _phase3_evidence(limit: int = 200) -> tuple[list[dict], dict]:
    events = _normalized_events_for_intelligence(limit=limit)
    temporal_snapshot = historical_memory.build_temporal_snapshot(events)
    if events and temporal_snapshot.get("data_state") == "INSUFFICIENT_DATA":
        temporal_snapshot["data_state"] = "DERIVED_FROM_STORED_OR_LEGACY_EVENTS"
    return events, temporal_snapshot

def _route_inventory() -> list[dict]:
    inventory = []
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = sorted(getattr(route, "methods", []) or [])
        if not path or path.startswith("/static"):
            continue
        inventory.append({
            "path": path,
            "methods": methods,
            "name": getattr(route, "name", "unknown"),
        })
    return inventory

@app.get("/api/v1/intelligence/adversarial")
async def get_adversarial_reasoning(current_user=Depends(get_current_user)):
    events, temporal_snapshot = _phase3_evidence()
    return phase3_foundations.build_adversarial_reasoning(events, temporal_snapshot)

@app.get("/api/v1/intelligence/scoring")
async def get_operational_scoring(current_user=Depends(get_current_user)):
    events, temporal_snapshot = _phase3_evidence()
    adversarial = phase3_foundations.build_adversarial_reasoning(events, temporal_snapshot)
    return phase3_foundations.build_operational_scoring(events, temporal_snapshot, adversarial)

@app.get("/api/v1/intelligence/signal-correlation")
async def get_signal_correlation(current_user=Depends(get_current_user)):
    events, temporal_snapshot = _phase3_evidence()
    return phase3_foundations.build_signal_correlation(events, temporal_snapshot)

@app.get("/api/v1/intelligence/exposure")
async def get_attack_surface_exposure(current_user=Depends(get_current_user)):
    return phase3_foundations.build_attack_surface(_route_inventory())

@app.get("/api/v1/intelligence/cognition")
async def get_cognitive_stability(current_user=Depends(get_current_user)):
    events, temporal_snapshot = _phase3_evidence()
    adversarial = phase3_foundations.build_adversarial_reasoning(events, temporal_snapshot)
    scoring = phase3_foundations.build_operational_scoring(events, temporal_snapshot, adversarial)
    correlation = phase3_foundations.build_signal_correlation(events, temporal_snapshot)
    return phase3_foundations.build_cognitive_stability(events, correlation, scoring)

@app.get("/api/v1/intelligence/survivability")
async def get_operational_survivability(current_user=Depends(get_current_user)):
    events, _ = _phase3_evidence()
    return phase3_foundations.build_survivability(_health_payload(), public_provenance(), events)

@app.get("/api/v1/intelligence/freeze-governance")
async def get_freeze_governance(current_user=Depends(get_current_user)):
    events, temporal_snapshot = _phase3_evidence()
    adversarial = phase3_foundations.build_adversarial_reasoning(events, temporal_snapshot)
    scoring = phase3_foundations.build_operational_scoring(events, temporal_snapshot, adversarial)
    survivability = phase3_foundations.build_survivability(_health_payload(), public_provenance(), events)
    return phase3_foundations.build_freeze_governance(scoring, survivability, public_provenance())

@app.get("/api/v1/intelligence/certification")
async def get_operational_certification(current_user=Depends(get_current_user)):
    events, temporal_snapshot = _phase3_evidence()
    summary = phase3_foundations.build_summary(
        events,
        temporal_snapshot,
        _route_inventory(),
        _health_payload(),
        public_provenance(),
    )
    return summary["certification"]

@app.get("/api/v1/intelligence/phase3-summary")
async def get_phase3_summary(current_user=Depends(get_current_user)):
    events, temporal_snapshot = _phase3_evidence()
    return phase3_foundations.build_summary(
        events,
        temporal_snapshot,
        _route_inventory(),
        _health_payload(),
        public_provenance(),
    )

def _phase3_summary_payload() -> dict:
    events, temporal_snapshot = _phase3_evidence()
    return phase3_foundations.build_summary(
        events,
        temporal_snapshot,
        _route_inventory(),
        _health_payload(),
        public_provenance(),
    )

def _local_endpoint_observations() -> dict:
    return {
        "health": {
            "state": "READY",
            "latency_ms": 0,
            "evidence": "in_process_health_payload",
        },
        "provenance": {
            "state": "READY" if public_provenance().get("current_commit") else "UNAVAILABLE",
            "latency_ms": 0,
            "evidence": "in_process_public_provenance",
        },
        "intelligence": {
            "state": "READY" if _phase3_summary_payload().get("status") else "UNAVAILABLE",
            "latency_ms": 0,
            "evidence": "in_process_phase3_summary",
        },
    }

def _phase4_summary_payload(endpoint_observations: dict | None = None) -> dict:
    return phase4_resilience.build_summary(
        health=_health_payload(),
        provenance=public_provenance(),
        phase3_summary=_phase3_summary_payload(),
        route_inventory=_route_inventory(),
        endpoint_observations=endpoint_observations or _local_endpoint_observations(),
    )

@app.get("/api/v1/resilience/degraded-runtime")
async def get_degraded_runtime(current_user=Depends(get_current_user)):
    return _phase4_summary_payload()["degraded_runtime"]

@app.get("/api/v1/resilience/partial-failure")
async def get_partial_failure(current_user=Depends(get_current_user)):
    return _phase4_summary_payload()["partial_failure"]

@app.get("/api/v1/resilience/recovery")
async def get_recovery_state(current_user=Depends(get_current_user)):
    return _phase4_summary_payload()["recovery"]

@app.get("/api/v1/resilience/fallback")
async def get_fallback_modes(current_user=Depends(get_current_user)):
    return _phase4_summary_payload()["fallback"]

@app.get("/api/v1/resilience/integrity")
async def get_runtime_integrity(current_user=Depends(get_current_user)):
    return _phase4_summary_payload()["integrity"]

@app.get("/api/v1/resilience/dependencies")
async def get_dependency_awareness(current_user=Depends(get_current_user)):
    return _phase4_summary_payload()["dependencies"]

@app.get("/api/v1/resilience/stress-validation")
async def get_resilience_stress_validation(current_user=Depends(get_current_user)):
    return _phase4_summary_payload()["stress_validation"]

@app.get("/api/v1/resilience/rollback-intelligence")
async def get_rollback_intelligence(current_user=Depends(get_current_user)):
    return _phase4_summary_payload()["rollback"]

@app.get("/api/v1/resilience/certification")
async def get_resilience_certification(current_user=Depends(get_current_user)):
    return _phase4_summary_payload()["certification"]

@app.get("/api/v1/resilience/phase4-summary")
async def get_phase4_summary(current_user=Depends(get_current_user)):
    return _phase4_summary_payload()

def _phase5_summary_payload() -> dict:
    return phase5_ecosystem.build_summary(
        health=_health_payload(),
        provenance=public_provenance(),
        route_inventory=_route_inventory(),
        phase4_summary=_phase4_summary_payload(),
    )

@app.get("/api/v1/ecosystem/assets")
async def get_ecosystem_assets(current_user=Depends(get_current_user)):
    return _phase5_summary_payload()["asset_inventory"]

@app.get("/api/v1/ecosystem/endpoints")
async def get_endpoint_intelligence(current_user=Depends(get_current_user)):
    return _phase5_summary_payload()["endpoint_intelligence"]

@app.get("/api/v1/ecosystem/dependencies")
async def get_ecosystem_dependencies(current_user=Depends(get_current_user)):
    return _phase5_summary_payload()["dependency_mapping"]

@app.get("/api/v1/ecosystem/exposure")
async def get_ecosystem_exposure(current_user=Depends(get_current_user)):
    return _phase5_summary_payload()["external_exposure"]

@app.get("/api/v1/ecosystem/sensitive-exposure")
async def get_sensitive_exposure(current_user=Depends(get_current_user)):
    return _phase5_summary_payload()["sensitive_exposure"]

@app.get("/api/v1/ecosystem/supply-chain")
async def get_supply_chain_awareness(current_user=Depends(get_current_user)):
    return _phase5_summary_payload()["supply_chain"]

@app.get("/api/v1/ecosystem/trust-zones")
async def get_trust_zones(current_user=Depends(get_current_user)):
    return _phase5_summary_payload()["trust_zones"]

@app.get("/api/v1/ecosystem/external-risk")
async def get_external_risk_correlation(current_user=Depends(get_current_user)):
    return _phase5_summary_payload()["external_risk_correlation"]

@app.get("/api/v1/ecosystem/intelligence")
async def get_ecosystem_intelligence(current_user=Depends(get_current_user)):
    return _phase5_summary_payload()["ecosystem_intelligence"]

@app.get("/api/v1/ecosystem/certification")
async def get_ecosystem_certification(current_user=Depends(get_current_user)):
    return _phase5_summary_payload()["certification"]

@app.get("/api/v1/ecosystem/phase5-summary")
async def get_phase5_summary(current_user=Depends(get_current_user)):
    return _phase5_summary_payload()

def _phase6_summary_payload() -> dict:
    return phase6_adversarial.build_summary(
        phase3_summary=_phase3_summary_payload(),
        phase4_summary=_phase4_summary_payload(),
        phase5_summary=_phase5_summary_payload(),
    )

@app.get("/api/v1/adversarial/attack-paths")
async def get_phase6_attack_paths(current_user=Depends(get_current_user)):
    return _phase6_summary_payload()["attack_paths"]

@app.get("/api/v1/adversarial/privilege")
async def get_phase6_privilege(current_user=Depends(get_current_user)):
    return _phase6_summary_payload()["privilege"]

@app.get("/api/v1/adversarial/lateral-movement")
async def get_phase6_lateral_movement(current_user=Depends(get_current_user)):
    return _phase6_summary_payload()["lateral_movement"]

@app.get("/api/v1/adversarial/exploitability")
async def get_phase6_exploitability(current_user=Depends(get_current_user)):
    return _phase6_summary_payload()["exploitability"]

@app.get("/api/v1/adversarial/strategic-correlation")
async def get_phase6_strategic_correlation(current_user=Depends(get_current_user)):
    return _phase6_summary_payload()["strategic_correlation"]

@app.get("/api/v1/adversarial/behavior")
async def get_phase6_behavior(current_user=Depends(get_current_user)):
    return _phase6_summary_payload()["behavioral_modeling"]

@app.get("/api/v1/adversarial/escalation")
async def get_phase6_escalation(current_user=Depends(get_current_user)):
    return _phase6_summary_payload()["escalation"]

@app.get("/api/v1/adversarial/simulation")
async def get_phase6_simulation(current_user=Depends(get_current_user)):
    return _phase6_summary_payload()["scenario_simulation"]

@app.get("/api/v1/adversarial/strategic-risk")
async def get_phase6_strategic_risk(current_user=Depends(get_current_user)):
    return _phase6_summary_payload()["strategic_risk"]

@app.get("/api/v1/adversarial/certification")
async def get_phase6_certification(current_user=Depends(get_current_user)):
    return _phase6_summary_payload()["certification"]

@app.get("/api/v1/adversarial/phase6-summary")
async def get_phase6_summary(current_user=Depends(get_current_user)):
    return _phase6_summary_payload()

def _git_source_state(label: str, path: str) -> dict:
    def git(args: list[str]) -> str:
        return subprocess.check_output(
            ["git", "-C", path, *args],
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
        ).strip()

    try:
        status_lines = [line for line in git(["status", "--short"]).splitlines() if line.strip()]
        deploy_relevant = [
            line for line in status_lines
            if _is_deploy_relevant_status_path(label, line[3:].strip())
        ]
        remotes = [line for line in git(["remote", "-v"]).splitlines() if line.strip()]
        branch = git(["branch", "--show-current"]) or "UNKNOWN"
        commit = git(["rev-parse", "HEAD"]) or "UNKNOWN"
        return {
            "label": label,
            "branch": branch,
            "commit": commit,
            "short_commit": commit[:7] if commit and commit != "UNKNOWN" else "unknown",
            "dirty": bool(status_lines),
            "change_count": len(status_lines),
            "deploy_relevant_dirty": bool(deploy_relevant),
            "deploy_relevant_change_count": len(deploy_relevant),
            "remote_visible": bool(remotes),
            "remote_kind": "github" if any("github.com" in remote.lower() for remote in remotes) else "configured" if remotes else "missing",
            "status_state": "DIRTY" if deploy_relevant else "CLEAN",
            "untracked_or_auxiliary_change_count": max(0, len(status_lines) - len(deploy_relevant)),
            "evidence_basis": "local_git_metadata_without_paths_or_secrets",
        }
    except Exception as exc:
        return {
            "label": label,
            "branch": "UNKNOWN",
            "commit": "UNKNOWN",
            "short_commit": "unknown",
            "dirty": False,
            "change_count": 0,
            "deploy_relevant_dirty": False,
            "deploy_relevant_change_count": 0,
            "remote_visible": False,
            "remote_kind": "UNKNOWN",
            "status_state": "UNAVAILABLE",
            "error": str(exc),
            "evidence_basis": "git_metadata_unavailable",
        }

def _is_deploy_relevant_status_path(label: str, repo_path: str) -> bool:
    repo_path = repo_path.replace("\\", "/")
    if not repo_path or repo_path.startswith("logs/"):
        return False
    if repo_path.startswith(".env") or "/.env" in repo_path:
        return False
    if label == "frontend":
        prefixes = ("app/", "components/", "lib/", "public/")
        exact = {"package.json", "package-lock.json", "next.config.js", "next.config.mjs", "tailwind.config.ts", "tailwind.config.js", "tsconfig.json"}
        return repo_path.startswith(prefixes) or repo_path in exact
    if label == "backend":
        prefixes = ("core/", "api/", "models/", "migrations/", "alembic/")
        exact = {"main.py", "requirements.txt", "render.yaml", "Procfile", "alembic.ini"}
        return repo_path.startswith(prefixes) or repo_path in exact
    return True

def _release_evidence_payload() -> dict:
    frontend_source = os.environ.get("CENTINELA_FRONTEND_SOURCE", r"C:\Users\admin\Desktop\centinela")
    backend_source = os.environ.get("CENTINELA_BACKEND_SOURCE", r"C:\Users\admin\Desktop\centinela-backend")
    frontend = _git_source_state("frontend", frontend_source)
    backend = _git_source_state("backend", backend_source)
    provenance = public_provenance()
    runtime_commit = provenance.get("current_commit")
    backend_commit = backend.get("commit")
    backend_match = None
    if runtime_commit and backend_commit and backend_commit != "UNKNOWN":
        backend_match = backend_commit == runtime_commit
    frontend_match = None
    dirty_count = int(frontend.get("deploy_relevant_change_count", 0) or 0) + int(backend.get("deploy_relevant_change_count", 0) or 0)

    if not runtime_commit:
        source_live_state = "UNKNOWN"
    elif dirty_count > 0:
        source_live_state = "LOCAL_CHANGES_NOT_DEPLOYED"
    elif backend_match is False:
        source_live_state = "SOURCE_LIVE_MISMATCH"
    elif backend_match is True and frontend_match is True:
        source_live_state = "SOURCE_LIVE_MATCH_VERIFIED"
    else:
        source_live_state = "PARTIAL_TRACEABILITY"

    return {
        "status": "BASIC_RELEASE_EVIDENCE",
        "local_sources": {
            "frontend": frontend,
            "backend": backend,
        },
        "runtime_provenance": {
            "repo_branch": provenance.get("repo_branch"),
            "current_commit": runtime_commit,
            "build_timestamp_visible": bool(provenance.get("build_timestamp")),
            "deployment_target_visible": bool(provenance.get("deployment_target")),
        },
        "source_to_live_validation": {
            "state": source_live_state,
            "backend_commit_matches_runtime": backend_match,
            "frontend_commit_matches_runtime": frontend_match,
            "frontend_live_validation": "NOT_VALIDATED_BY_BACKEND_RUNTIME",
            "dirty_local_change_count": dirty_count,
            "evidence_basis": "local_git_metadata_and_runtime_provenance",
        },
        "secrets_exposed": False,
        "local_paths_exposed_publicly": False,
    }

def _phase7_summary_payload() -> dict:
    return phase7_governance.build_summary(
        health=_health_payload(),
        provenance=public_provenance(),
        phase4_summary=_phase4_summary_payload(),
        phase5_summary=_phase5_summary_payload(),
        phase6_summary=_phase6_summary_payload(),
        release_evidence=_release_evidence_payload(),
    )

@app.get("/api/v1/governance/freeze")
async def get_phase7_freeze_governance(current_user=Depends(get_current_user)):
    return _phase7_summary_payload()["freeze_governance"]

@app.get("/api/v1/governance/release-integrity")
async def get_phase7_release_integrity(current_user=Depends(get_current_user)):
    return _phase7_summary_payload()["release_integrity"]

@app.get("/api/v1/governance/deployment-trust")
async def get_phase7_deployment_trust(current_user=Depends(get_current_user)):
    return _phase7_summary_payload()["deployment_trust"]

@app.get("/api/v1/governance/runtime-trust")
async def get_phase7_runtime_trust(current_user=Depends(get_current_user)):
    return _phase7_summary_payload()["runtime_trust"]

@app.get("/api/v1/governance/operational-audit")
async def get_phase7_operational_audit(current_user=Depends(get_current_user)):
    return _phase7_summary_payload()["operational_audit"]

@app.get("/api/v1/governance/escalation")
async def get_phase7_governance_escalation(current_user=Depends(get_current_user)):
    return _phase7_summary_payload()["governance_escalation"]

@app.get("/api/v1/governance/executive-risk")
async def get_phase7_executive_risk(current_user=Depends(get_current_user)):
    return _phase7_summary_payload()["executive_risk"]

@app.get("/api/v1/governance/survivability")
async def get_phase7_enterprise_survivability(current_user=Depends(get_current_user)):
    return _phase7_summary_payload()["enterprise_survivability"]

@app.get("/api/v1/governance/readiness")
async def get_phase7_operational_readiness(current_user=Depends(get_current_user)):
    return _phase7_summary_payload()["operational_readiness"]

@app.get("/api/v1/governance/final-certification")
async def get_phase7_final_certification(current_user=Depends(get_current_user)):
    return _phase7_summary_payload()["final_certification"]

@app.get("/api/v1/governance/phase7-summary")
async def get_phase7_summary(current_user=Depends(get_current_user)):
    return _phase7_summary_payload()

SEVERITY_WEIGHT = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

BLOCKED_HUMAN_ACTION_TYPES = {
    "delete_data",
    "offensive_action",
    "attack_system",
    "exploit_vulnerability",
    "touch_real_cloud",
    "automatic_production_change",
    "rotate_real_secrets",
    "automatic_deploy",
    "delete_user",
    "mass_email",
    "irreversible_action",
    "reveal_protected_source",
}

BLOCKED_ACTION_MESSAGE = (
    "Acción no permitida en esta versión. Requiere autorización superior "
    "y política explícita."
)

def _json_loads(value, fallback):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback

def _safe_source_agent(value: str | None) -> str:
    normalized = str(value or "Motor de riesgo").strip()
    if normalized.lower() in {"sombra", "fuente sombra", "entidad sombra", "cabina sombra"}:
        return "Inteligencia de amenazas"
    return normalized

def _is_sensitive_human_action(action_type: str | None, proposed_action: str | None) -> bool:
    action = str(action_type or "").lower().strip()
    proposed = str(proposed_action or "").lower()
    if action in BLOCKED_HUMAN_ACTION_TYPES:
        return True
    blocked_terms = (
        "borrar datos",
        "atacar",
        "explotar vulnerabilidad",
        "deploy automático",
        "rotar secretos",
        "eliminar usuarios",
        "correo masivo",
        "acción irreversible",
        "fuente protegida",
    )
    return any(term in proposed for term in blocked_terms)

def _human_cabin_seed_records():
    now = datetime.utcnow()
    return [
        {
            "id": "HC-CRIT-001",
            "title": "Riesgo crítico cliente: bloqueo defensivo pendiente",
            "description": "Se detectó una señal de exfiltración simulada en ambiente local/demo. No se afirma incidente real.",
            "severity": "critical",
            "status": "pending_review",
            "proposed_action": "Congelar la ruta afectada y pedir más evidencia antes de cualquier cambio real.",
            "action_type": "containment_review",
            "source_agent": "Motor de riesgo",
            "target_system": "API Gateway demo",
            "client_name": "Cliente Norte Demo",
            "risk_score": 94,
            "confidence_score": 0.84,
            "evidence_json": {
                "data_state": "DEMO_LOCAL",
                "origin": "Inteligencia de amenazas",
                "signals": ["policy_gate", "anomaly_pattern", "missing_context"],
                "visible_to_client": True,
            },
            "recommended_decision": "Pedir evidencia adicional y mantener contención reversible.",
            "metadata_json": {"demo_local": True, "protection_claim": "not_real_runtime"},
            "created_at": now,
        },
        {
            "id": "HC-HIGH-001",
            "title": "Permiso sensible en agente interno",
            "description": "Una capacidad de escritura debe quedar bajo revisión humana antes de uso prolongado.",
            "severity": "high",
            "status": "pending_review",
            "proposed_action": "Pausar ejecución y solicitar revisión de permisos.",
            "action_type": "pause_sensitive_permission",
            "source_agent": "Análisis interno",
            "target_system": "Agente operativo demo",
            "client_name": "Cliente Sur Demo",
            "risk_score": 82,
            "confidence_score": 0.76,
            "evidence_json": {"data_state": "DEMO_LOCAL", "origin": "Análisis interno", "visible_to_client": True},
            "recommended_decision": "Pausar hasta completar evidencia técnica.",
            "metadata_json": {"demo_local": True},
            "created_at": now,
        },
        {
            "id": "HC-HIGH-002",
            "title": "Cambio de política requiere confirmación",
            "description": "La política podría reducir protección si se aplica sin auditoría.",
            "severity": "high",
            "status": "escalated",
            "proposed_action": "Escalar para decisión interna antes de cambiar reglas.",
            "action_type": "policy_escalation",
            "source_agent": "Motor de política",
            "target_system": "Policy Engine demo",
            "client_name": "Cliente Norte Demo",
            "risk_score": 79,
            "confidence_score": 0.7,
            "evidence_json": {"data_state": "DEMO_LOCAL", "origin": "Motor de política", "visible_to_client": False},
            "recommended_decision": "Mantener regla actual y pedir auditoría.",
            "metadata_json": {"demo_local": True},
            "created_at": now,
        },
        {
            "id": "HC-MED-001",
            "title": "Evidencia incompleta en alerta de prompt",
            "description": "La alerta tiene señales parciales y no debe presentarse como certeza.",
            "severity": "medium",
            "status": "needs_more_evidence",
            "proposed_action": "Solicitar más evidencia antes de cerrar.",
            "action_type": "more_evidence",
            "source_agent": "Monitoreo avanzado",
            "target_system": "Prompt Firewall demo",
            "client_name": "Cliente Centro Demo",
            "risk_score": 61,
            "confidence_score": 0.52,
            "evidence_json": {"data_state": "DEMO_LOCAL", "origin": "Monitoreo avanzado", "visible_to_client": True},
            "recommended_decision": "No aprobar todavía.",
            "metadata_json": {"demo_local": True},
            "created_at": now,
        },
        {
            "id": "HC-MED-002",
            "title": "Reporte ejecutivo mensual preparado",
            "description": "Reporte listo como muestra local; no contiene telemetría productiva.",
            "severity": "medium",
            "status": "pending_review",
            "proposed_action": "Generar reporte ejecutivo de demostración.",
            "action_type": "executive_report",
            "source_agent": "Reporte ejecutivo",
            "target_system": "Cabina cliente demo",
            "client_name": "Cliente Sur Demo",
            "risk_score": 48,
            "confidence_score": 0.68,
            "evidence_json": {"data_state": "DEMO_LOCAL", "origin": "Reporte ejecutivo", "visible_to_client": True},
            "recommended_decision": "Revisar lenguaje antes de entregar.",
            "metadata_json": {"demo_local": True},
            "created_at": now,
        },
        {
            "id": "HC-INFO-001",
            "title": "Señal informativa agrupada",
            "description": "Evento agrupado sin impacto inmediato.",
            "severity": "info",
            "status": "pending_review",
            "proposed_action": "Mantener observación sin ruido.",
            "action_type": "observe",
            "source_agent": "Señales externas",
            "target_system": "Superficie demo",
            "client_name": "Cliente Centro Demo",
            "risk_score": 18,
            "confidence_score": 0.64,
            "evidence_json": {"data_state": "DEMO_LOCAL", "origin": "Señales externas", "visible_to_client": True},
            "recommended_decision": "No molestar al cliente; incluir en historial.",
            "metadata_json": {"demo_local": True},
            "created_at": now,
        },
        {
            "id": "HC-BLOCK-001",
            "title": "Acción sensible bloqueada",
            "description": "Solicitud de acción irreversible bloqueada por política.",
            "severity": "critical",
            "status": "blocked",
            "proposed_action": BLOCKED_ACTION_MESSAGE,
            "action_type": "irreversible_action",
            "source_agent": "Motor de riesgo",
            "target_system": "Infraestructura demo",
            "client_name": "Cliente Norte Demo",
            "risk_score": 99,
            "confidence_score": 0.9,
            "evidence_json": {"data_state": "DEMO_LOCAL", "origin": "Motor de riesgo", "visible_to_client": True},
            "recommended_decision": "Mantener bloqueado.",
            "metadata_json": {"demo_local": True, "blocked_by_default": True},
            "created_at": now,
        },
    ]

def _pricing_seed_records():
    return [
        {
            "id": "plan_empresa",
            "name": "Plan Empresa",
            "monthly_price_pen": 199,
            "description": "Cabina cliente, alertas priorizadas y reportes ejecutivos básicos.",
            "features_json": ["monitoreo defensivo base", "alertas priorizadas", "cabina cliente", "reportes ejecutivos básicos"],
        },
        {
            "id": "plan_premium",
            "name": "Plan Premium",
            "monthly_price_pen": 499,
            "description": "Mayor profundidad de evidencia, decisiones humanas e historial avanzado.",
            "features_json": ["todo empresa", "mayor profundidad de evidencia", "decisiones humanas", "historial avanzado", "reportes premium"],
        },
        {
            "id": "plan_corporativo",
            "name": "Plan Corporativo",
            "monthly_price_pen": 999,
            "description": "Desde S/999 al mes para múltiples activos, gobierno de riesgo y prioridad alta.",
            "features_json": ["todo premium", "múltiples activos/clientes", "gobierno de riesgo", "prioridad alta", "capa admin/CEO ampliada"],
        },
    ]

def _ensure_human_cabin_seed():
    db = SessionLocal()
    try:
        if db.query(HumanReviewRequestModel).count() == 0:
            for record in _human_cabin_seed_records():
                db.add(HumanReviewRequestModel(
                    id=record["id"],
                    title=record["title"],
                    description=record["description"],
                    severity=record["severity"],
                    status=record["status"],
                    proposed_action=record["proposed_action"],
                    action_type=record["action_type"],
                    source_agent=_safe_source_agent(record["source_agent"]),
                    target_system=record["target_system"],
                    client_name=record["client_name"],
                    risk_score=record["risk_score"],
                    confidence_score=record["confidence_score"],
                    evidence_json=json.dumps(record["evidence_json"], ensure_ascii=False),
                    recommended_decision=record["recommended_decision"],
                    created_at=record["created_at"],
                    expires_at=record["created_at"] + timedelta(days=7),
                    metadata_json=json.dumps(record["metadata_json"], ensure_ascii=False),
                ))
            db.commit()
        if db.query(SentinelaPricingPlanModel).count() == 0:
            for record in _pricing_seed_records():
                db.add(SentinelaPricingPlanModel(
                    id=record["id"],
                    name=record["name"],
                    monthly_price_pen=record["monthly_price_pen"],
                    description=record["description"],
                    features_json=json.dumps(record["features_json"], ensure_ascii=False),
                    is_active=True,
                ))
            db.commit()
        if db.query(SentinelaClientSecuritySummaryModel).count() == 0:
            db.add(SentinelaClientSecuritySummaryModel(
                id="client-demo-norte",
                client_id="client-demo-norte",
                client_name="Cliente Norte Demo",
                plan="Premium",
                protection_status="Vigilado",
                global_risk="critical",
                active_incidents=1,
                pending_decisions=2,
                last_scan_at=datetime.utcnow(),
                last_report_at=datetime.utcnow(),
                metadata_json=json.dumps({"data_state": "DEMO_LOCAL", "subscription_status": "demo_local_no_payment"}, ensure_ascii=False),
            ))
            db.add(SentinelaClientSecuritySummaryModel(
                id="client-demo-sur",
                client_id="client-demo-sur",
                client_name="Cliente Sur Demo",
                plan="Empresa",
                protection_status="Presionado",
                global_risk="high",
                active_incidents=2,
                pending_decisions=1,
                last_scan_at=datetime.utcnow(),
                last_report_at=datetime.utcnow(),
                metadata_json=json.dumps({"data_state": "DEMO_LOCAL", "subscription_status": "demo_local_no_payment"}, ensure_ascii=False),
            ))
            db.add(SentinelaClientSecuritySummaryModel(
                id="client-demo-centro",
                client_id="client-demo-centro",
                client_name="Cliente Centro Demo",
                plan="Corporativo",
                protection_status="Vigilado",
                global_risk="medium",
                active_incidents=0,
                pending_decisions=1,
                last_scan_at=datetime.utcnow(),
                last_report_at=datetime.utcnow(),
                metadata_json=json.dumps({"data_state": "DEMO_LOCAL", "subscription_status": "demo_local_no_payment"}, ensure_ascii=False),
            ))
            db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def _serialize_human_request(row: HumanReviewRequestModel) -> dict:
    return {
        "id": row.id,
        "title": row.title,
        "description": row.description,
        "severity": row.severity,
        "status": row.status,
        "proposed_action": row.proposed_action,
        "action_type": row.action_type,
        "source_agent": _safe_source_agent(row.source_agent),
        "target_system": row.target_system,
        "client_name": row.client_name,
        "risk_score": row.risk_score,
        "confidence_score": row.confidence_score,
        "evidence": _json_loads(row.evidence_json, {}),
        "recommended_decision": row.recommended_decision,
        "reviewer_id": row.reviewer_id,
        "reviewer_notes": row.reviewer_notes,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "reviewed_at": row.reviewed_at.isoformat() if row.reviewed_at else None,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "metadata": _json_loads(row.metadata_json, {}),
    }

def _serialize_human_audit(row: HumanReviewAuditEventModel) -> dict:
    return {
        "id": row.id,
        "review_request_id": row.review_request_id,
        "actor": row.actor,
        "action": row.action,
        "previous_status": row.previous_status,
        "new_status": row.new_status,
        "notes": row.notes,
        "severity": row.severity,
        "target_system": row.target_system,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "metadata": _json_loads(row.metadata_json, {}),
    }

def _serialize_client_summary(row: SentinelaClientSecuritySummaryModel) -> dict:
    return {
        "id": row.id,
        "client_id": row.client_id,
        "client_name": row.client_name,
        "plan": row.plan,
        "protection_status": row.protection_status,
        "global_risk": row.global_risk,
        "active_incidents": row.active_incidents,
        "pending_decisions": row.pending_decisions,
        "last_scan_at": row.last_scan_at.isoformat() if row.last_scan_at else None,
        "last_report_at": row.last_report_at.isoformat() if row.last_report_at else None,
        "metadata": _json_loads(row.metadata_json, {}),
    }

def _serialize_pricing(row: SentinelaPricingPlanModel) -> dict:
    price_label = "desde S/999/mes" if row.id == "plan_corporativo" else f"S/{row.monthly_price_pen}/mes"
    return {
        "id": row.id,
        "name": row.name,
        "monthly_price_pen": row.monthly_price_pen,
        "price_label": price_label,
        "description": row.description,
        "features": _json_loads(row.features_json, []),
        "is_active": row.is_active,
        "payment_status": "prepared_no_checkout",
    }

def _ordered_human_requests(db, only_client_visible: bool = False):
    rows = db.query(HumanReviewRequestModel).all()
    items = [_serialize_human_request(row) for row in rows]
    if only_client_visible:
        items = [item for item in items if item.get("evidence", {}).get("visible_to_client") is True]
    return sorted(
        items,
        key=lambda item: (
            -SEVERITY_WEIGHT.get(str(item.get("severity", "")).lower(), 0),
            -float(item.get("risk_score") or 0),
            str(item.get("created_at") or ""),
        ),
    )

def _human_cabin_summary_payload(db) -> dict:
    requests = _ordered_human_requests(db)
    critical = [item for item in requests if item["severity"] == "critical"]
    pending = [item for item in requests if item["status"] in {"pending_review", "needs_more_evidence", "escalated"}]
    blocked = [item for item in requests if item["status"] == "blocked"]
    clients = [_serialize_client_summary(row) for row in db.query(SentinelaClientSecuritySummaryModel).all()]
    plans = [_serialize_pricing(row) for row in db.query(SentinelaPricingPlanModel).filter(SentinelaPricingPlanModel.is_active == True).all()]
    audit_count = db.query(HumanReviewAuditEventModel).count()
    return {
        "mode": "DEMO_LOCAL",
        "source": "SENTINELA_HUMAN_CABIN_SYNTHESIS_DRAFT",
        "protection_status": "Vigilado",
        "global_risk": "critical" if critical else "medium",
        "risk_temperature": "CRITICAL" if critical else "PRESSURED",
        "plan_current": "Premium demo/local",
        "subscription_status": "demo_local_no_payment",
        "active_incidents": len([item for item in requests if item["status"] not in {"closed", "cancelled"}]),
        "pending_decisions": len(pending),
        "blocked_actions": len(blocked),
        "system_confidence": 74,
        "average_response_minutes": 11,
        "top_priority": requests[0] if requests else None,
        "requests": requests,
        "clients": clients,
        "plans": plans,
        "audit_events_count": audit_count,
        "safe_public_source_labels": [
            "Inteligencia de amenazas",
            "Motor de riesgo",
            "Monitoreo avanzado",
            "Señales externas",
            "Análisis interno",
        ],
        "blocked_action_message": BLOCKED_ACTION_MESSAGE,
        "client_visibility_policy": {
            "protected_internal_sources_exposed": False,
            "admin_public_access": False,
            "ceo_public_access": False,
            "full_free_trial": False,
            "real_payment_enabled": False,
        },
    }

def _record_human_audit(db, request_row: HumanReviewRequestModel, actor: str, action: str, previous_status: str, new_status: str, notes: str | None = None):
    event = HumanReviewAuditEventModel(
        id=f"HCA-{str(uuid.uuid4())[:8].upper()}",
        review_request_id=request_row.id,
        actor=actor,
        action=action,
        previous_status=previous_status,
        new_status=new_status,
        notes=notes or "",
        severity=request_row.severity,
        target_system=request_row.target_system,
        created_at=datetime.utcnow(),
        metadata_json=json.dumps({"data_state": "DEMO_LOCAL", "audit_trail": True}, ensure_ascii=False),
    )
    db.add(event)
    return event

def _apply_human_review_action(request_id: str, current_user, new_status: str, action: str, notes: str | None = None) -> dict:
    _ensure_human_cabin_seed()
    db = SessionLocal()
    try:
        row = db.query(HumanReviewRequestModel).filter(HumanReviewRequestModel.id == request_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Human review request not found")
        previous = row.status
        if row.status == "blocked" and action != "block_sensitive_action":
            new_status = "blocked"
            notes = notes or BLOCKED_ACTION_MESSAGE
        row.status = new_status
        row.reviewer_id = getattr(current_user, "username", "unknown")
        row.reviewer_notes = notes or ""
        row.reviewed_at = datetime.utcnow()
        _record_human_audit(db, row, row.reviewer_id, action, previous, row.status, notes)
        db.commit()
        db.refresh(row)
        return {"request": _serialize_human_request(row), "audit_registered": True}
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"human cabin action failed: {exc}")
    finally:
        db.close()

@app.get("/api/v1/human-cabin/summary")
async def get_human_cabin_summary(current_user=Depends(get_current_user)):
    _ensure_human_cabin_seed()
    db = SessionLocal()
    try:
        return _human_cabin_summary_payload(db)
    finally:
        db.close()

@app.get("/api/v1/human-cabin/requests")
async def get_human_cabin_requests(current_user=Depends(get_current_user)):
    _ensure_human_cabin_seed()
    db = SessionLocal()
    try:
        return _ordered_human_requests(db)
    finally:
        db.close()

@app.get("/api/v1/human-cabin/requests/{request_id}")
async def get_human_cabin_request(request_id: str, current_user=Depends(get_current_user)):
    _ensure_human_cabin_seed()
    db = SessionLocal()
    try:
        row = db.query(HumanReviewRequestModel).filter(HumanReviewRequestModel.id == request_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Human review request not found")
        return _serialize_human_request(row)
    finally:
        db.close()

@app.post("/api/v1/human-cabin/requests")
async def create_human_cabin_request(payload: dict, current_user=Depends(get_current_user)):
    _ensure_human_cabin_seed()
    action_type = str(payload.get("action_type", "human_review"))
    proposed_action = str(payload.get("proposed_action", "Revisión humana requerida."))
    status_value = "blocked" if _is_sensitive_human_action(action_type, proposed_action) else str(payload.get("status", "pending_review"))
    if status_value == "executed":
        status_value = "pending_review"
    db = SessionLocal()
    try:
        request_id = payload.get("id") or f"HC-{str(uuid.uuid4())[:8].upper()}"
        row = HumanReviewRequestModel(
            id=request_id,
            title=str(payload.get("title", "Solicitud de revisión humana")),
            description=str(payload.get("description", "Solicitud local preparada para revisión humana.")),
            severity=str(payload.get("severity", "medium")).lower(),
            status=status_value,
            proposed_action=BLOCKED_ACTION_MESSAGE if status_value == "blocked" else proposed_action,
            action_type=action_type,
            source_agent=_safe_source_agent(payload.get("source_agent")),
            target_system=str(payload.get("target_system", "Sistema demo")),
            client_name=str(payload.get("client_name", "Cliente Demo")),
            risk_score=float(payload.get("risk_score", 50)),
            confidence_score=float(payload.get("confidence_score", 0.5)),
            evidence_json=json.dumps(payload.get("evidence", {"data_state": "DEMO_LOCAL"}), ensure_ascii=False),
            recommended_decision=str(payload.get("recommended_decision", "Revisar antes de avanzar.")),
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=7),
            metadata_json=json.dumps({"demo_local": True, "created_by": getattr(current_user, "username", "unknown")}, ensure_ascii=False),
        )
        db.add(row)
        _record_human_audit(db, row, getattr(current_user, "username", "unknown"), "create", "none", row.status, "Solicitud creada localmente.")
        db.commit()
        db.refresh(row)
        return _serialize_human_request(row)
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"human cabin create failed: {exc}")
    finally:
        db.close()

@app.post("/api/v1/human-cabin/requests/{request_id}/approve")
async def approve_human_cabin_request(request_id: str, payload: dict | None = None, current_user=Depends(get_current_user)):
    return _apply_human_review_action(request_id, current_user, "approved", "approve", (payload or {}).get("notes") if payload else None)

@app.post("/api/v1/human-cabin/requests/{request_id}/reject")
async def reject_human_cabin_request(request_id: str, payload: dict | None = None, current_user=Depends(get_current_user)):
    return _apply_human_review_action(request_id, current_user, "rejected", "reject", (payload or {}).get("notes") if payload else None)

@app.post("/api/v1/human-cabin/requests/{request_id}/pause")
async def pause_human_cabin_request(request_id: str, payload: dict | None = None, current_user=Depends(get_current_user)):
    return _apply_human_review_action(request_id, current_user, "paused", "pause", (payload or {}).get("notes") if payload else None)

@app.post("/api/v1/human-cabin/requests/{request_id}/more-evidence")
async def more_evidence_human_cabin_request(request_id: str, payload: dict | None = None, current_user=Depends(get_current_user)):
    return _apply_human_review_action(request_id, current_user, "needs_more_evidence", "more_evidence", (payload or {}).get("notes") if payload else None)

@app.post("/api/v1/human-cabin/requests/{request_id}/escalate")
async def escalate_human_cabin_request(request_id: str, payload: dict | None = None, current_user=Depends(get_current_user)):
    return _apply_human_review_action(request_id, current_user, "escalated", "escalate", (payload or {}).get("notes") if payload else None)

@app.post("/api/v1/human-cabin/requests/{request_id}/false-positive")
async def false_positive_human_cabin_request(request_id: str, payload: dict | None = None, current_user=Depends(get_current_user)):
    return _apply_human_review_action(request_id, current_user, "rejected", "false_positive", (payload or {}).get("notes") if payload else None)

@app.post("/api/v1/human-cabin/requests/{request_id}/close")
async def close_human_cabin_request(request_id: str, payload: dict | None = None, current_user=Depends(get_current_user)):
    return _apply_human_review_action(request_id, current_user, "cancelled", "close_incident", (payload or {}).get("notes") if payload else None)

@app.post("/api/v1/human-cabin/requests/{request_id}/accept-risk")
async def accept_risk_human_cabin_request(request_id: str, payload: dict | None = None, current_user=Depends(get_current_user)):
    return _apply_human_review_action(request_id, current_user, "approved", "accept_risk", (payload or {}).get("notes") if payload else None)

@app.post("/api/v1/human-cabin/requests/{request_id}/block-sensitive-action")
async def block_sensitive_human_cabin_request(request_id: str, payload: dict | None = None, current_user=Depends(get_current_user)):
    return _apply_human_review_action(request_id, current_user, "blocked", "block_sensitive_action", (payload or {}).get("notes") if payload else BLOCKED_ACTION_MESSAGE)

@app.post("/api/v1/human-cabin/requests/{request_id}/executive-report")
async def executive_report_human_cabin_request(request_id: str, payload: dict | None = None, current_user=Depends(get_current_user)):
    return _apply_human_review_action(request_id, current_user, "pending_review", "executive_report", (payload or {}).get("notes") if payload else "Reporte ejecutivo generado en modo demo/local.")

@app.get("/api/v1/human-cabin/audit")
async def get_human_cabin_audit(current_user=Depends(get_current_user)):
    _ensure_human_cabin_seed()
    db = SessionLocal()
    try:
        rows = db.query(HumanReviewAuditEventModel).order_by(HumanReviewAuditEventModel.created_at.desc()).limit(100).all()
        return [_serialize_human_audit(row) for row in rows]
    finally:
        db.close()

@app.get("/api/v1/human-cabin/pricing")
async def get_human_cabin_pricing(current_user=Depends(get_current_user)):
    _ensure_human_cabin_seed()
    db = SessionLocal()
    try:
        return [_serialize_pricing(row) for row in db.query(SentinelaPricingPlanModel).filter(SentinelaPricingPlanModel.is_active == True).all()]
    finally:
        db.close()

@app.get("/api/v1/human-cabin/client-view")
async def get_human_cabin_client_view(current_user=Depends(get_current_user)):
    _ensure_human_cabin_seed()
    db = SessionLocal()
    try:
        summary = _human_cabin_summary_payload(db)
        return {
            "mode": summary["mode"],
            "summary": {
                "protection_status": summary["protection_status"],
                "global_risk": summary["global_risk"],
                "risk_temperature": summary["risk_temperature"],
                "plan_current": summary["plan_current"],
                "subscription_status": summary["subscription_status"],
                "active_incidents": summary["active_incidents"],
                "pending_decisions": summary["pending_decisions"],
                "blocked_actions": summary["blocked_actions"],
            },
            "requests": _ordered_human_requests(db, only_client_visible=True),
            "plans": summary["plans"],
            "visibility_policy": summary["client_visibility_policy"],
        }
    finally:
        db.close()

@app.get("/api/v1/human-cabin/admin-view")
async def get_human_cabin_admin_view(current_user=Depends(get_current_user)):
    _ensure_human_cabin_seed()
    db = SessionLocal()
    try:
        summary = _human_cabin_summary_payload(db)
        return {
            "mode": summary["mode"],
            "queue": summary["requests"],
            "audit_events_count": summary["audit_events_count"],
            "allowed_actions": ["approve", "reject", "pause", "more_evidence", "escalate", "false_positive", "close_incident", "accept_risk", "block_sensitive_action", "executive_report"],
            "blocked_actions": list(sorted(BLOCKED_HUMAN_ACTION_TYPES)),
            "blocked_action_message": BLOCKED_ACTION_MESSAGE,
        }
    finally:
        db.close()

@app.get("/api/v1/human-cabin/ceo-view")
async def get_human_cabin_ceo_view(current_user=Depends(get_current_user)):
    _ensure_human_cabin_seed()
    db = SessionLocal()
    try:
        summary = _human_cabin_summary_payload(db)
        return {
            "mode": summary["mode"],
            "strategic_state": "Protección premium preparada localmente",
            "critical_decisions": [item for item in summary["requests"] if item["severity"] == "critical"],
            "missing_evidence": [item for item in summary["requests"] if item["status"] == "needs_more_evidence"],
            "requires_final_override": [item for item in summary["requests"] if item["status"] in {"blocked", "escalated"}],
            "internal_relationships_protected": True,
            "public_client_source_names": summary["safe_public_source_labels"],
        }
    finally:
        db.close()

@app.get("/api/v1/stats/db")
async def get_db_stats(current_user=Depends(get_current_user)):
    return get_stats()

# â”€â”€ Health (pÃºblico) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.post("/api/v1/admin/reset")
async def reset_admin(current_user=Depends(get_admin_user)):
    from core.database import SessionLocal
    from core.auth import UserModel, create_user
    admin_username = os.environ.get("ADMIN_USERNAME", "daniel")
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@centinela.local")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not admin_password:
        raise HTTPException(status_code=503, detail="ADMIN_PASSWORD must be configured before admin reset")
    db = SessionLocal()
    try:
        db.query(UserModel).filter(UserModel.username == admin_username).delete()
        db.commit()
    finally:
        db.close()
    create_user(admin_username, admin_email, admin_password, is_admin=True)
    return {"status": "admin reset ok", "username": admin_username}
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
def _health_db_stats() -> tuple[dict, str | None]:
    if SERVERLESS_MODE and not _env_flag("CENTINELA_HEALTH_CHECK_DB"):
        return {}, "serverless_db_probe_skipped"
    try:
        return get_stats(), None
    except Exception as exc:
        logger.warning("health DB probe failed: %s", exc)
        return {}, "db_probe_failed"

def _health_payload() -> dict:
    db_stats, health_note = _health_db_stats()
    db_connected = bool(db_stats)
    return {
        "status": "OPERATIONAL" if db_connected else ("degraded" if SERVERLESS_MODE else "DEGRADED"),
        "mode": "persistent" if db_connected else "ram_only",
        "engine": "CENTINELA Core v2.0",
        "runtime_version": RUNTIME_VERSION,
        "timestamp": datetime.utcnow().isoformat(),
        "database": "CONNECTED" if db_connected else "unavailable",
        "health_note": health_note,
        "serverless_mode": SERVERLESS_MODE,
        "provenance": public_provenance(),
        "engines": {
            "pipeline": "ONLINE",
            "risk_engine": "ONLINE",
            "threat_detection": "ONLINE",
            "correlation_engine": "ONLINE",
            "policy_engine": "ONLINE",
            "response_engine": "ONLINE",
            "observability_engine": "ONLINE",
            "agent_security": "ONLINE",
            "operational_intelligence": "ONLINE",
            "historical_memory": "ONLINE",
            "phase3_foundations": "ONLINE",
            "phase4_resilience": "ONLINE",
            "phase5_ecosystem": "ONLINE",
            "phase6_adversarial": "ONLINE",
            "phase7_governance": "ONLINE",
            "threat_memory": "ONLINE",
            "postgresql": "ONLINE" if db_stats else "PENDING",
        }
    }

@app.get("/api/v1/health")
async def health():
    return _health_payload()

@app.get("/api/v1/provenance")
async def provenance():
    return public_provenance()
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
    



