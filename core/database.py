import os
import json
from sqlalchemy import create_engine, Column, String, Float, Integer, Boolean, Text, DateTime, func, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta

def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").lower() in {"1", "true", "yes", "on"}

SERVERLESS_MODE = _env_flag("SERVERLESS_MODE") or _env_flag("VERCEL")
DEFAULT_DATABASE_URL = "sqlite:////tmp/centinela.db" if SERVERLESS_MODE else "sqlite:///./centinela.db"
DATABASE_URL_CANDIDATES = (
    "DATABASE_URL",
    "DATABASE_POSTGRES_URL",
    "DATABASE_POSTGRES_PRISMA_URL",
    "DATABASE_URL_UNPOOLED",
    "DATABASE_POSTGRES_URL_NON_POOLING",
    "POSTGRES_URL",
    "POSTGRES_PRISMA_URL",
    "POSTGRES_URL_NON_POOLING",
)

def _normalize_database_url(url: str) -> str:
    normalized = url.strip().strip('"').strip("'")
    if normalized.startswith("postgres://"):
        normalized = normalized.replace("postgres://", "postgresql://", 1)
    if normalized.startswith("postgresql://") and "neon.tech" in normalized.lower() and "sslmode=" not in normalized.lower():
        separator = "&" if "?" in normalized else "?"
        normalized = f"{normalized}{separator}sslmode=require"
    return normalized

def _resolve_database_url() -> tuple[str, str | None]:
    for name in DATABASE_URL_CANDIDATES:
        value = os.environ.get(name)
        if value and value.strip():
            return _normalize_database_url(value), name
    return DEFAULT_DATABASE_URL, None

DATABASE_URL, DATABASE_URL_SOURCE = _resolve_database_url()
DATABASE_CONFIGURED = DATABASE_URL_SOURCE is not None

engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("postgresql://"):
    engine_kwargs["connect_args"] = {
        "connect_timeout": int(os.environ.get("DB_CONNECT_TIMEOUT", "2"))
    }

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class EventModel(Base):
    __tablename__ = "events"
    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    agent = Column(String, index=True)
    user_id = Column("user_id", String, index=True)
    model = Column(String)
    content = Column(Text)
    risk_score = Column(Float, default=0)
    risk_level = Column(String)
    threat_detected = Column(Boolean, default=False)
    threat_types = Column(String)
    policy_action = Column(String)
    raw = Column(Text)

class IncidentModel(Base):
    __tablename__ = "incidents"
    id = Column(String, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    severity = Column(String)
    agent = Column(String, index=True)
    user = Column(String)
    risk_score = Column(Float)
    threat_types = Column(String)
    policy_action = Column(String)
    status = Column(String, default="OPEN")
    event_id = Column(String)

class ThreatPatternModel(Base):
    __tablename__ = "threat_patterns"
    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(String, unique=True, index=True)
    threat_types = Column(String)
    agent = Column(String)
    risk_score = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)
    count = Column(Integer, default=1)

class NormalizedEventModel(Base):
    __tablename__ = "normalized_events"
    event_id = Column(String, primary_key=True)
    timestamp = Column(DateTime, index=True, default=datetime.utcnow)
    source = Column(String, index=True)
    severity = Column(String, index=True)
    category = Column(String, index=True)
    confidence = Column(String)
    classification = Column(String, index=True)
    signal_state = Column(String, index=True)
    origin_agent = Column(String, index=True)
    origin_user = Column(String, index=True)
    operational_impact = Column(Text)
    security_impact = Column(Text)
    raw = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

class HumanReviewRequestModel(Base):
    __tablename__ = "human_review_requests"
    id = Column(String, primary_key=True)
    title = Column(String, index=True)
    description = Column(Text)
    severity = Column(String, index=True)
    status = Column(String, index=True)
    proposed_action = Column(Text)
    action_type = Column(String, index=True)
    source_agent = Column(String, index=True)
    target_system = Column(String, index=True)
    client_name = Column(String, index=True)
    risk_score = Column(Float, default=0)
    confidence_score = Column(Float, default=0)
    evidence_json = Column(Text)
    recommended_decision = Column(Text)
    reviewer_id = Column(String, nullable=True)
    reviewer_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    reviewed_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    metadata_json = Column(Text)

class HumanReviewAuditEventModel(Base):
    __tablename__ = "human_review_audit_events"
    id = Column(String, primary_key=True)
    review_request_id = Column(String, index=True)
    actor = Column(String, index=True)
    action = Column(String, index=True)
    previous_status = Column(String)
    new_status = Column(String)
    notes = Column(Text)
    severity = Column(String, index=True)
    target_system = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    metadata_json = Column(Text)

class SentinelaClientSecuritySummaryModel(Base):
    __tablename__ = "sentinela_client_security_summary"
    id = Column(String, primary_key=True)
    client_id = Column(String, index=True)
    client_name = Column(String, index=True)
    plan = Column(String)
    protection_status = Column(String, index=True)
    global_risk = Column(String, index=True)
    active_incidents = Column(Integer, default=0)
    pending_decisions = Column(Integer, default=0)
    last_scan_at = Column(DateTime, nullable=True)
    last_report_at = Column(DateTime, nullable=True)
    metadata_json = Column(Text)

class SentinelaPricingPlanModel(Base):
    __tablename__ = "sentinela_pricing_plans"
    id = Column(String, primary_key=True)
    name = Column(String, unique=True, index=True)
    monthly_price_pen = Column(Integer)
    description = Column(Text)
    features_json = Column(Text)
    is_active = Column(Boolean, default=True)

def init_db() -> bool:
    try:
        Base.metadata.create_all(bind=engine)
        ensure_schema_compatibility()
        return True
    except Exception as e:
        print(f"init_db error: {e}")
        return False

def ensure_schema_compatibility():
    """Apply small idempotent migrations for pre-Phase schemas."""
    _ensure_events_user_id_column()

def _ensure_events_user_id_column():
    with engine.begin() as conn:
        inspector = inspect(conn)
        table_names = inspector.get_table_names()
        if "events" not in table_names:
            return

        columns = {column["name"] for column in inspector.get_columns("events")}
        if "user_id" in columns:
            return

        if "user" in columns:
            conn.execute(text('ALTER TABLE events RENAME COLUMN "user" TO user_id'))
        else:
            conn.execute(text("ALTER TABLE events ADD COLUMN user_id VARCHAR"))

        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_user_id ON events (user_id)"))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def database_url_configured() -> bool:
    return DATABASE_CONFIGURED

def probe_database() -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False

def save_event(event: dict):
    db = SessionLocal()
    try:
        existing = db.query(EventModel).filter(EventModel.id == event.get("id")).first()
        if existing:
            return
        record = EventModel(
            id=event.get("id", ""),
            timestamp=datetime.utcnow(),
            agent=event.get("agent", "unknown"),
            user_id=event.get("user", "unknown"),
            model=event.get("model", "unknown"),
            content=str(event.get("content", ""))[:2000],
            risk_score=event.get("risk", {}).get("score", 0) if isinstance(event.get("risk"), dict) else 0,
            risk_level=event.get("risk", {}).get("level", "") if isinstance(event.get("risk"), dict) else "",
            threat_detected=event.get("detection", {}).get("threat_detected", False) if isinstance(event.get("detection"), dict) else False,
            threat_types=json.dumps(event.get("detection", {}).get("threat_types", []) if isinstance(event.get("detection"), dict) else []),
            policy_action=event.get("policy", {}).get("action", "") if isinstance(event.get("policy"), dict) else "",
            raw=json.dumps(event)[:10000],
        )
        db.add(record)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"save_event error: {e}")
    finally:
        db.close()

def save_normalized_event(normalized: dict):
    if not isinstance(normalized, dict):
        return
    event_id = normalized.get("event_id")
    if not event_id or event_id == "unknown":
        return
    db = SessionLocal()
    try:
        existing = db.query(NormalizedEventModel).filter(NormalizedEventModel.event_id == event_id).first()
        if existing:
            return
        origin = normalized.get("origin") if isinstance(normalized.get("origin"), dict) else {}
        record = NormalizedEventModel(
            event_id=event_id,
            timestamp=_parse_datetime(normalized.get("timestamp")),
            source=normalized.get("source", "unknown"),
            severity=normalized.get("severity", "LOW"),
            category=normalized.get("category", "OPERATIONAL_EVENT"),
            confidence=normalized.get("confidence", "UNKNOWN"),
            classification=normalized.get("classification", "DEGRADED"),
            signal_state=normalized.get("signal_state", "low_confidence"),
            origin_agent=origin.get("agent", "unknown"),
            origin_user=origin.get("user", "unknown"),
            operational_impact=normalized.get("operational_impact", ""),
            security_impact=normalized.get("security_impact", ""),
            raw=json.dumps(normalized)[:12000],
        )
        db.add(record)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"save_normalized_event error: {e}")
    finally:
        db.close()

def delete_old_normalized_events(retention_days: int = 30):
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(days=retention_days)
        deleted = db.query(NormalizedEventModel).filter(NormalizedEventModel.timestamp < cutoff).delete()
        db.commit()
        return deleted
    except Exception as e:
        db.rollback()
        print(f"delete_old_normalized_events error: {e}")
        return 0
    finally:
        db.close()

def normalized_event_to_dict(row: NormalizedEventModel) -> dict:
    raw = _parse_json(row.raw)
    if isinstance(raw, dict):
        return raw
    return {
        "event_id": row.event_id,
        "source": row.source,
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "severity": row.severity,
        "category": row.category,
        "confidence": row.confidence,
        "origin": {
            "agent": row.origin_agent,
            "user": row.origin_user,
            "model": "unknown",
            "session_id": "unknown",
        },
        "operational_impact": row.operational_impact,
        "security_impact": row.security_impact,
        "classification": row.classification,
        "signal_state": row.signal_state,
        "evidence_basis": ["persisted_normalized_event"],
    }

def save_incident(incident: dict):
    db = SessionLocal()
    try:
        existing = db.query(IncidentModel).filter(IncidentModel.id == incident.get("id")).first()
        if existing:
            return
        record = IncidentModel(
            id=incident.get("id", ""),
            created_at=datetime.utcnow(),
            severity=incident.get("severity", ""),
            agent=incident.get("agent", ""),
            user=incident.get("user", ""),
            risk_score=incident.get("risk_score", 0),
            threat_types=json.dumps(incident.get("threat_types", [])),
            policy_action=incident.get("policy_action", ""),
            status=incident.get("status", "OPEN"),
            event_id=incident.get("event_id", ""),
        )
        db.add(record)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"save_incident error: {e}")
    finally:
        db.close()

def _parse_datetime(value):
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return datetime.utcnow()
    return datetime.utcnow()

def _parse_json(value):
    if not value:
        return None
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return None

def get_stats() -> dict:
    db = SessionLocal()
    try:
        total = db.query(func.count(EventModel.id)).scalar() or 0
        threats = db.query(func.count(EventModel.id)).filter(EventModel.threat_detected == True).scalar() or 0
        blocked = db.query(func.count(EventModel.id)).filter(EventModel.policy_action.in_(["BLOCK", "RESTRICT"])).scalar() or 0
        incidents = db.query(func.count(IncidentModel.id)).scalar() or 0
        return {
            "total_events": total,
            "threat_events": threats,
            "blocked_events": blocked,
            "total_incidents": incidents,
        }
    except Exception as e:
        print(f"get_stats error: {e}")
        return {}
    finally:
        db.close()
