import os
import uuid
import json
from datetime import datetime, timedelta
from collections import defaultdict
from core.database import SessionLocal, EventModel, IncidentModel, ThreatPatternModel, init_db

init_db()

class ThreatMemory:
    def __init__(self):
        self._agent_cache: dict = defaultdict(list)
        self._user_cache: dict = defaultdict(list)
        self._recent_cache: list = []
        self._cache_limit = 500

    def store(self, event: dict):
        agent = event.get("agent", "unknown").lower()
        user = event.get("user", "unknown")

        # Update in-memory cache
        self._agent_cache[agent].append(event)
        self._user_cache[user].append(event)
        self._recent_cache.append(event)
        if len(self._recent_cache) > self._cache_limit:
            self._recent_cache = self._recent_cache[-self._cache_limit:]

        # Persist to PostgreSQL
        db = SessionLocal()
        try:
            threat_types = event.get("detection", {}).get("threat_types", [])
            db_event = EventModel(
                id=event.get("id", str(uuid.uuid4())),
                timestamp=datetime.fromisoformat(event.get("timestamp", datetime.utcnow().isoformat())),
                agent=agent,
                user=user,
                model=event.get("model", "unknown"),
                content=event.get("content", "")[:2000],
                risk_score=event.get("risk", {}).get("score", 0),
                risk_level=event.get("risk", {}).get("level", "MINIMAL"),
                threat_detected=event.get("detection", {}).get("threat_detected", False),
                threat_types=",".join(threat_types),
                policy_action=event.get("policy", {}).get("action", "ALLOW"),
                raw=json.dumps(event)[:5000],
            )
            db.merge(db_event)

            # Store threat pattern
            if event.get("detection", {}).get("threat_detected"):
                fp = self._fingerprint(event)
                existing = db.query(ThreatPatternModel).filter_by(fingerprint=fp).first()
                if existing:
                    existing.count += 1
                else:
                    db.add(ThreatPatternModel(
                        fingerprint=fp,
                        threat_types=",".join(threat_types),
                        agent=agent,
                        risk_score=event.get("risk", {}).get("score", 0),
                    ))
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"DB store error: {e}")
        finally:
            db.close()

    def create_incident(self, event: dict) -> dict:
        severity = event.get("risk", {}).get("level", "MEDIUM")
        incident_id = f"INC-{str(uuid.uuid4())[:6].upper()}"
        incident = {
            "id": incident_id,
            "created_at": datetime.utcnow().isoformat(),
            "severity": severity,
            "agent": event.get("agent"),
            "user": event.get("user"),
            "risk_score": event.get("risk", {}).get("score", 0),
            "threat_types": event.get("detection", {}).get("threat_types", []),
            "policy_action": event.get("policy", {}).get("action"),
            "status": "OPEN",
            "event_id": event.get("id"),
        }

        db = SessionLocal()
        try:
            db.add(IncidentModel(
                id=incident_id,
                created_at=datetime.utcnow(),
                severity=severity,
                agent=event.get("agent"),
                user=event.get("user"),
                risk_score=event.get("risk", {}).get("score", 0),
                threat_types=",".join(event.get("detection", {}).get("threat_types", [])),
                policy_action=event.get("policy", {}).get("action"),
                status="OPEN",
                event_id=event.get("id"),
            ))
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"DB incident error: {e}")
        finally:
            db.close()

        return incident

    def get_agent_history(self, agent: str) -> list:
        if agent in self._agent_cache:
            return self._agent_cache[agent]
        db = SessionLocal()
        try:
            rows = db.query(EventModel).filter_by(agent=agent).order_by(EventModel.timestamp.desc()).limit(50).all()
            return [json.loads(r.raw) for r in rows if r.raw]
        except:
            return []
        finally:
            db.close()

    def get_user_history(self, user: str) -> list:
        if user in self._user_cache:
            return self._user_cache[user]
        db = SessionLocal()
        try:
            rows = db.query(EventModel).filter_by(user=user).order_by(EventModel.timestamp.desc()).limit(50).all()
            return [json.loads(r.raw) for r in rows if r.raw]
        except:
            return []
        finally:
            db.close()

    def get_recent_events(self, minutes: int = 5) -> list:
        return self._recent_cache[-100:]

    def get_incidents(self) -> list:
        db = SessionLocal()
        try:
            rows = db.query(IncidentModel).order_by(IncidentModel.created_at.desc()).limit(100).all()
            return [
                {
                    "id": r.id,
                    "created_at": r.created_at.isoformat(),
                    "severity": r.severity,
                    "agent": r.agent,
                    "user": r.user,
                    "risk_score": r.risk_score,
                    "threat_types": r.threat_types.split(",") if r.threat_types else [],
                    "policy_action": r.policy_action,
                    "status": r.status,
                    "event_id": r.event_id,
                }
                for r in rows
            ]
        except Exception as e:
            print(f"DB incidents error: {e}")
            return []
        finally:
            db.close()

    def get_summary(self) -> dict:
        db = SessionLocal()
        try:
            total = db.query(EventModel).count()
            threats = db.query(EventModel).filter_by(threat_detected=True).count()
            blocked = db.query(EventModel).filter_by(policy_action="BLOCK").count()
            incidents = db.query(IncidentModel).count()
            patterns = db.query(ThreatPatternModel).count()
            return {
                "total_events": total,
                "threat_events": threats,
                "blocked_events": blocked,
                "total_incidents": incidents,
                "unique_fingerprints": patterns,
                "agents_monitored": len(self._agent_cache),
                "users_tracked": len(self._user_cache),
                "threat_patterns": patterns,
            }
        except Exception as e:
            print(f"DB summary error: {e}")
            return {}
        finally:
            db.close()

    def _fingerprint(self, event: dict) -> str:
        content = event.get("content", "")
        threat_types = ",".join(sorted(event.get("detection", {}).get("threat_types", [])))
        agent = event.get("agent", "")
        words = sorted(set(content.lower().split()))[:10]
        return f"{agent}:{threat_types}:{':'.join(words)}"[:200]