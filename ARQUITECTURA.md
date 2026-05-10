# CENTINELA — Arquitectura Real Operacional
# Fecha: Mayo 2026

## STACK

- Backend: Python 3.14 + FastAPI + SQLAlchemy
- Deploy: Render (plan gratuito — se duerme 15min inactividad)
- DB: PostgreSQL 18 en Render (expira Mayo 31, 2026)
- Frontend: Next.js 14 + TypeScript + Tailwind
- Deploy Frontend: Vercel
- SDK: lib/centinela.ts en PLUMA

## URLs

- Backend: https://centinela-backend-kzwk.onrender.com
- Frontend: https://centinela-btdd.vercel.app
- Repo Backend: github.com/danielglezsolucionador-boop/centinela-backend
- Repo Frontend: github.com/danielglezsolucionador-boop/centinela
- Repo PLUMA: github.com/danielglezsolucionador-boop/pluma

## CREDENCIALES

- Admin: daniel / centinela24
- DB: variable DATABASE_URL en Render Environment

## FLUJO RUNTIME REAL

PLUMA --> sendPromptToCentinela() --> POST /api/v1/prompt/analyze
  --> process_full_pipeline(event)
      --> EventPipeline.process()
          --> RiskEngine.score()
          --> ThreatCorrelationEngine.correlate()
          --> ThreatMemory.store() [RAM]
      --> ThreatDetectionEngine.analyze() [regex + heurísticas]
      --> PolicyEngine.evaluate()
      --> ResponseEngine.respond()
      --> ObservabilityEngine.record_trace()
      --> AgentSecurityEngine.analyze_agent_behavior()
      --> save_event() --> PostgreSQL
      --> si threat_detected: save_incident() --> PostgreSQL
  --> return enriched result a PLUMA

## MOTORES ACTIVOS

- ThreatDetectionEngine: regex + scoring. Detecta PROMPT_INJECTION, JAILBREAK, DATA_EXFILTRATION, SYSTEM_EXTRACTION, ROLE_MANIPULATION
- PolicyEngine: políticas por agente. Acciones: BLOCK, RESTRICT, WARN, ALLOW
- RiskEngine: score dinámico 0-100 por agente y modelo
- ResponseEngine: playbooks por tipo de amenaza. Acciones: BLOCK_PROMPT, ISOLATE_AGENT, ALERT
- ThreatCorrelationEngine: correlación cross-agent en RAM
- ObservabilityEngine: trazas y métricas en RAM
- AgentSecurityEngine: behavioral drift detection en RAM
- ThreatMemory: cache RAM + persistencia PostgreSQL

## TABLAS POSTGRESQL

- events: id, timestamp, agent, user_id, model, content, risk_score, risk_level, threat_detected, threat_types, policy_action, raw
- incidents: id, created_at, severity, agent, user, risk_score, threat_types, policy_action, status, event_id
- users: id, email, username, hashed_password, is_active, is_admin, created_at
- threat_patterns: id, fingerprint, threat_types, agent, risk_score, timestamp, count

## ENDPOINTS PRINCIPALES

Públicos:
- GET /api/v1/health
- POST /api/v1/auth/login

Protegidos JWT:
- POST /api/v1/prompt/analyze [pipeline principal]
- POST /api/v1/event
- GET /api/v1/stats/db
- GET /api/v1/incidents
- GET /api/v1/threat-memory
- GET /api/v1/risk/ecosystem
- GET /api/v1/correlations/active
- GET /api/v1/detection/stats
- GET /api/v1/policy/all
- GET /api/v1/agents/map
- GET /api/v1/agents/anomalies
- GET /api/v1/observability/metrics
- WS /ws

Protegidos JWT Admin:
- POST /api/v1/admin/reset
- POST /api/v1/admin/migrate
- GET /api/v1/admin/db-columns
- POST /api/v1/admin/reset-db
- POST /api/v1/policy/update

## ESTADO REAL SISTEMA (Mayo 9, 2026)

- total_events: 194
- threat_events: 104
- blocked_events: 93
- total_incidents: 144
- Pipeline: 15/15 sin errores
- Logs: estructurados en Render
- CORS: restringido a dominios oficiales
- Admin endpoints: protegidos con JWT

## DEPENDENCIAS CRÍTICAS

- PostgreSQL Render: expira Mayo 31, 2026 — MIGRAR URGENTE
- Render plan gratis: cold start 50s tras 15min inactividad
- ThreatMemory RAM: se pierde en cada restart

## RIESGOS ACTUALES

1. PostgreSQL expira Mayo 31 — crítico
2. ThreatMemory en RAM — contexto operacional se pierde en restart
3. Render plan gratis — cold start afecta UX
4. No hay alertas automáticas externas (Sentry, PagerDuty)
5. No hay backups automáticos de DB

## CHECKLIST PRODUCCIÓN

[x] Auth JWT funcionando
[x] Rate limiting activo
[x] Pipeline end-to-end estable
[x] PostgreSQL persistiendo eventos e incidentes
[x] Logging estructurado en Render
[x] CORS restringido
[x] Admin endpoints protegidos
[x] SDK PLUMA funcionando
[x] Frontend conectado a datos reales
[ ] PostgreSQL migrado a plan pagado
[ ] ThreatMemory persistida fuera de RAM
[ ] Backups automáticos DB
[ ] Alertas externas (Sentry)
[ ] CORS allow_methods restringido
