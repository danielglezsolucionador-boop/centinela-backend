import os
from sqlalchemy import create_engine, text
from datetime import datetime
import json

DATABASE_URL = os.environ.get("DATABASE_URL")

engine = None
if DATABASE_URL:
    engine = create_engine(DATABASE_URL)

def init_db():
    if not engine:
        return
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS events (
                id VARCHAR PRIMARY KEY,
                type VARCHAR,
                timestamp TIMESTAMP,
                agent VARCHAR,
                user_id VARCHAR,
                content TEXT,
                risk_score FLOAT,
                risk_level VARCHAR,
                threat_detected BOOLEAN,
                threat_types JSONB,
                policy_action VARCHAR,
                raw JSONB,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS incidents (
                id VARCHAR PRIMARY KEY,
                created_at TIMESTAMP,
                severity VARCHAR,
                agent VARCHAR,
                user_id VARCHAR,
                risk_score FLOAT,
                threat_types JSONB,
                policy_action VARCHAR,
                status VARCHAR,
                event_id VARCHAR
            )
        """))
        conn.commit()

def save_event(event: dict):
    if not engine:
        return
    try:
        with engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO events (id, type, timestamp, agent, user_id, content, risk_score, risk_level, threat_detected, threat_types, policy_action, raw)
                VALUES (:id, :type, :timestamp, :agent, :user_id, :content, :risk_score, :risk_level, :threat_detected, :threat_types, :policy_action, :raw)
                ON CONFLICT (id) DO NOTHING
            """), {
                "id": event.get("id"),
                "type": event.get("type"),
                "timestamp": event.get("timestamp"),
                "agent": event.get("agent"),
                "user_id": event.get("user"),
                "content": event.get("content", "")[:2000],
                "risk_score": event.get("risk", {}).get("score", 0),
                "risk_level": event.get("risk", {}).get("level", ""),
                "threat_detected": event.get("detection", {}).get("threat_detected", False),
                "threat_types": json.dumps(event.get("detection", {}).get("threat_types", [])),
                "policy_action": event.get("policy", {}).get("action", ""),
                "raw": json.dumps(event),
            })
            conn.commit()
    except Exception as e:
        print(f"DB save error: {e}")

def save_incident(incident: dict):
    if not engine:
        return
    try:
        with engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO incidents (id, created_at, severity, agent, user_id, risk_score, threat_types, policy_action, status, event_id)
                VALUES (:id, :created_at, :severity, :agent, :user_id, :risk_score, :threat_types, :policy_action, :status, :event_id)
                ON CONFLICT (id) DO NOTHING
            """), {
                "id": incident.get("id"),
                "created_at": incident.get("created_at"),
                "severity": incident.get("severity"),
                "agent": incident.get("agent"),
                "user_id": incident.get("user"),
                "risk_score": incident.get("risk_score", 0),
                "threat_types": json.dumps(incident.get("threat_types", [])),
                "policy_action": incident.get("policy_action"),
                "status": incident.get("status"),
                "event_id": incident.get("event_id"),
            })
            conn.commit()
    except Exception as e:
        print(f"DB incident error: {e}")

def get_stats() -> dict:
    if not engine:
        return {}
    try:
        with engine.connect() as conn:
            total = conn.execute(text("SELECT COUNT(*) FROM events")).scalar()
            threats = conn.execute(text("SELECT COUNT(*) FROM events WHERE threat_detected = true")).scalar()
            blocked = conn.execute(text("SELECT COUNT(*) FROM events WHERE policy_action = 'BLOCK'")).scalar()
            incidents = conn.execute(text("SELECT COUNT(*) FROM incidents")).scalar()
            return {
                "total_events": total,
                "threat_events": threats,
                "blocked_events": blocked,
                "total_incidents": incidents,
            }
    except Exception as e:
        print(f"DB stats error: {e}")
        return {}