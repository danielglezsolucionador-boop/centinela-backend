# CENTINELA - Arquitectura Real Operacional

Fecha: Mayo 2026

## Stack

- Backend: Python + FastAPI + SQLAlchemy
- Deploy backend: Render
- Database: PostgreSQL via `DATABASE_URL`
- Frontend: Next.js 14 + TypeScript + Tailwind
- Deploy frontend: Vercel

## URLs

- Backend: `https://centinela-backend.vercel.app`
- Frontend actual: `https://centinela-alpha.vercel.app`
- Frontend legacy permitido: `https://centinela-btdd.vercel.app`
- Repo Backend: `github.com/danielglezsolucionador-boop/centinela-backend`
- Repo Frontend: `github.com/danielglezsolucionador-boop/centinela`

## Credenciales

- Admin/runtime secrets: configurados exclusivamente por variables de entorno.
- Variables requeridas en produccion: `SECRET_KEY`, `ADMIN_PASSWORD`, `DATABASE_URL`.
- No guardar credenciales reales en codigo, documentacion, fixtures ni scripts.

## Flujo Runtime Real

`POST /api/v1/prompt/analyze`

1. `process_full_pipeline(event)`
2. `EventPipeline.process()`
3. `RiskEngine.score()`
4. `ThreatCorrelationEngine.correlate()`
5. `ThreatMemory.store()`
6. `ThreatDetectionEngine.analyze()`
7. `PolicyEngine.evaluate()`
8. `ResponseEngine.respond()`
9. `ObservabilityEngine.record_trace()`
10. Persistencia en base de datos
11. Broadcast WebSocket

## Motores Activos

- ThreatDetectionEngine
- PolicyEngine
- RiskEngine
- ResponseEngine
- ThreatCorrelationEngine
- ObservabilityEngine
- AgentSecurityEngine
- ThreatMemory

## Endpoints Principales

Publicos:

- `GET /api/v1/health`
- `POST /api/v1/auth/login`

Protegidos JWT:

- `POST /api/v1/event`
- `POST /api/v1/prompt/analyze`
- `GET /api/v1/stats/db`
- `GET /api/v1/incidents`
- `GET /api/v1/threat-memory`
- `GET /api/v1/risk/ecosystem`
- `GET /api/v1/correlations/active`
- `GET /api/v1/detection/stats`
- `GET /api/v1/policy/all`
- `GET /api/v1/agents/map`
- `GET /api/v1/agents/anomalies`
- `GET /api/v1/observability/metrics`

Protegidos JWT admin:

- `POST /api/v1/admin/reset`
- `POST /api/v1/admin/migrate`
- `GET /api/v1/admin/db-columns`
- `POST /api/v1/admin/reset-db`
- `POST /api/v1/policy/update`

## Seguridad Base

- JWT auth activo.
- Login rate-limited.
- CORS restringido a dominios oficiales.
- Admin endpoints protegidos por rol admin.
- Secretos solo por entorno.

## Riesgos Actuales

1. Confirmar metadata de Vercel y Render directamente en plataforma.
2. Confirmar redeploy live despues del push.
3. Agregar pruebas backend para health, CORS, auth y admin guards.
4. Mantener backups DB fuera del repositorio.
5. Evitar que `.env*`, DB local y caches entren al indice Git.
