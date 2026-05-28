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

PROVENANCE_BRANCH = os.environ.get("RENDER_GIT_BRANCH") or _local_git_value(["branch", "--show-current"], "main")
PROVENANCE_COMMIT = (
    os.environ.get("RENDER_GIT_COMMIT")
    or os.environ.get("GIT_COMMIT")
    or _local_git_value(["rev-parse", "HEAD"], "unknown")
)
PROVENANCE_BUILD_TIMESTAMP = os.environ.get("BUILD_TIMESTAMP", "2026-05-27T06:09:24-05:00")
PROVENANCE_DEPLOYMENT_TARGET = os.environ.get(
    "DEPLOYMENT_TARGET",
    "Render backend: https://centinela-backend-kzwk.onrender.com",
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
            "dirty": True,
            "change_count": 1,
            "deploy_relevant_dirty": True,
            "deploy_relevant_change_count": 1,
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
    backend_match = bool(runtime_commit and backend.get("commit") == runtime_commit)
    frontend_match = False
    dirty_count = int(frontend.get("deploy_relevant_change_count", 0) or 0) + int(backend.get("deploy_relevant_change_count", 0) or 0)

    if not runtime_commit:
        source_live_state = "UNKNOWN"
    elif dirty_count > 0:
        source_live_state = "LOCAL_CHANGES_NOT_DEPLOYED"
    elif backend_match and frontend_match:
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
def _health_payload() -> dict:
    db_stats = get_stats()
    return {
        "status": "OPERATIONAL",
        "engine": "CENTINELA Core v2.0",
        "runtime_version": RUNTIME_VERSION,
        "timestamp": datetime.utcnow().isoformat(),
        "database": "CONNECTED" if db_stats else "RAM_ONLY",
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
    



