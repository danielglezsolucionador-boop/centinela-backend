import os
from sqlalchemy import create_engine, Column, String, Float, Integer, Boolean, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./centinela.db")

# Render uses postgres:// but SQLAlchemy needs postgresql://
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