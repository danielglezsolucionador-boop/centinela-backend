# CENTINELA - Production Ready

## Arquitectura Final
- Backend: FastAPI + Python en Render (plan gratuito)
- Frontend: Next.js 14 en Vercel
- DB: PostgreSQL en Render (expira Mayo 31 2026)
- Auth: JWT + bcrypt
- Rate limiting: slowapi 5/min en login

## Endpoints Reales
- POST /api/v1/auth/login - JWT auth, rate limited 5/min
- POST /api/v1/prompt/analyze - deteccion amenazas real
- GET /api/v1/stats/db - estadisticas PostgreSQL
- GET /api/v1/incidents - incidentes PostgreSQL
- GET /api/v1/risk/ecosystem - scores por agente
- GET /api/v1/policy/all - politicas por agente
- GET /api/v1/health - estado sistema

## Estado Real Produccion
- total_events: 303
- threat_events: 162
- blocked_events: 151
- total_incidents: 202
- detection_rate: 53%

## Riesgos Restantes
- PostgreSQL gratuito expira Mayo 31 2026 CRITICO
- Render plan gratuito cold start 50s
- Sin backups automaticos
- Sin monitoreo externo

## Limites Sistema
- Payload maximo: 10000 chars
- Rate limit login: 5/minute
- Cold start: hasta 50 segundos
- No concurrencia alta

## Checklist Deploy
1. Verificar DATABASE_URL en Render Environment
2. Verificar git push a main
3. Esperar deploy automatico Render
4. Validar GET /api/v1/health
5. Validar login con credenciales

## Checklist Backup
1. Obtener External Database URL de Render
2. pg_dump URL > backup_FECHA.sql
3. Guardar en lugar seguro
4. Frecuencia: semanal minimo

## Checklist Monitoreo
1. Revisar Render Logs diariamente
2. Verificar total_events creciendo
3. Verificar PostgreSQL no expirado
4. Deadline migracion: Mayo 31 2026
