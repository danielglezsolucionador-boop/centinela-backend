import os
import json
from sqlalchemy import create_engine, Column, String, Float, Integer, Boolean, Text, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./centinela.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class EventModel(Base):
    __tablename__ = "events"
    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    agent = Column(String, index=True)
    user = Column(String, index=True)
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

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

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
            user=event.get("user", "unknown"),
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

def get_stats() -> dict:
    db = SessionLocal()
    try:
        total = db.query(func.count(EventModel.id)).scalar() or 0
        threats = db.query(func.count(EventModel.id)).filter(EventModel.threat_detected == True).scalar() or 0
        blocked = db.query(func.count(EventModel.id)).filter(EventModel.policy_action == "BLOCK").scalar() or 0
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