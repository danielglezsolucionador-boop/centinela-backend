# SENTINELA Production Database Status Report

Fecha local de auditoria: 2026-06-11

## Resumen

CENTINELA backend Vercel esta vivo, pero la persistencia productiva no queda cerrada.

Produccion responde `/api/v1/health` con HTTP 200, pero mantiene `database=unavailable`, `mode=ram_only` y `health_note=serverless_db_probe_skipped`.

El repo backend quedo preparado para que, cuando exista `DATABASE_URL` en el entorno Vercel, `health` ejecute el probe de DB y pueda reportar `database=CONNECTED` y `mode=persistent`.

## Backend

- URL backend: https://centinela-backend.vercel.app
- Repo backend: `C:\Users\admin\Desktop\centinela-backend`
- Proyecto Vercel: `centinela-backend`
- Commit productivo observado antes del cambio: `4ba17ab77dff37e0990d1744b1b34cc3e2ff5d17`

## Backup

- Backup pre-cambio: `D:\ECOSYSTEM\BACKUPS\sentinela-vercel-database-production-prechange-20260611-202740.zip`
- Entradas en backup: 72
- Entradas prohibidas detectadas: 0
- Exclusiones aplicadas: `.env`, `.env.local`, `.vercel`, `.venv`, `venv`, `node_modules`, `dist`, `logs`, `cache`, `tokens`, `secrets`, `cookies`, `__pycache__`, `.pytest_cache`, `.git`

## Variables Vercel

`vercel env ls production` y `vercel env ls production --format json` no devolvieron nombres de variables.

Variables esperadas por la orden:

- `DATABASE_URL`: no confirmada en Vercel Production.
- `SECRET_KEY`: no confirmada en Vercel Production.
- `ADMIN_PASSWORD`: no confirmada en Vercel Production.
- `SERVERLESS_MODE=1`: no confirmada como variable Vercel; `api/index.py` la fuerza en runtime.
- `ENVIRONMENT=production`: no confirmada en Vercel Production.
- `CORS_ORIGINS=https://centinela-alpha.vercel.app`: no confirmada como variable Vercel; el origen ya esta hardcodeado en CORS.

## DATABASE_URL

- `DATABASE_URL` local existe en `.env.local`, pero apunta a un host Render PostgreSQL.
- Esa URL no fue cargada en Vercel porque la orden explicita dice: no volver a Render / Render queda descartado.
- No se encontro una `DATABASE_URL` alternativa no-Render en variables de entorno locales ni en archivos no secretos del repo.

Estado: FALTA DATABASE_URL PRODUCTIVA.

## DB Provider

- Productivo: pendiente de definir.
- Local detectado y descartado: Render PostgreSQL.
- Recomendado: PostgreSQL productivo no-Render, por ejemplo Neon, Supabase, Vercel Postgres/Marketplace compatible o Postgres administrado externo.

## Conexion DB

- Produccion actual: no conectada.
- Prueba local segura: el health probe nuevo fue validado con SQLite temporal y reporto `database=CONNECTED`, `mode=persistent`.
- No se conecto a una DB productiva no-Render porque no hay connection string disponible.

## Migraciones / Init

El backend usa SQLAlchemy `Base.metadata.create_all(bind=engine)` mediante `init_db()`, mas compatibilidad idempotente para `events.user_id`.

No se ejecutaron migraciones contra produccion porque falta `DATABASE_URL` productiva no-Render.

Cuando exista la DB productiva, la inicializacion segura debe importar `main` o `core.auth` antes de `init_db()` para que el modelo `users` quede registrado en `Base`.

## Tablas Esperadas Por Codigo

- `events`
- `incidents`
- `threat_patterns`
- `normalized_events`
- `human_review_requests`
- `human_review_audit_events`
- `sentinela_client_security_summary`
- `sentinela_pricing_plans`
- `users`

No hay tablas `forensics`, `policies` ni `agents` como modelos SQLAlchemy dedicados en el codigo actual.

## Health

Antes:

- URL: https://centinela-backend.vercel.app/api/v1/health
- HTTP: 200
- `status`: `degraded`
- `mode`: `ram_only`
- `database`: `unavailable`
- `health_note`: `serverless_db_probe_skipped`

Cambio aplicado:

- `main.py` ahora permite probe DB en serverless si `DATABASE_URL` existe.
- Si `DATABASE_URL` no existe, mantiene el comportamiento degradado y no bloqueante.

Despues en produccion:

- Pendiente de redeploy y de `DATABASE_URL` productiva.
- Sin `DATABASE_URL`, el resultado esperado sigue siendo `database=unavailable`.

## Endpoints Validados

Produccion actual:

- `/api/v1/health`: HTTP 200, DB unavailable.
- `/api/v1/provenance`: HTTP 200.
- `/api/v1/incidents`: HTTP 401 sin token.
- `/api/v1/policy/all`: HTTP 401 sin token.
- `/api/v1/agents/stats`: HTTP 401 sin token.
- `/api/v1/resilience/degraded-runtime`: HTTP 401 sin token.
- `/api/v1/governance/runtime-trust`: HTTP 401 sin token.
- `/api/v1/forensics`: HTTP 404, no existe.
- `/api/v1/policies`: HTTP 404, no existe.
- `/api/v1/agents/status`: HTTP 404, no existe.

## Auth

- Endpoints protegidos validan 401 controlado sin token.
- `users` depende de DB para login real.
- No se inicializo admin productivo porque no hay DB productiva ni `ADMIN_PASSWORD` confirmado.

## Tests

- `venv\Scripts\python.exe -m compileall . -q`: OK.
- `venv\Scripts\python.exe -m pytest -q`: pytest no instalado en el venv.
- `python -m pytest -q`: 6 passed, 12 warnings.
- Smoke local con `SERVERLESS_MODE=1` y `DATABASE_URL` temporal: health HTTP 200, `database=CONNECTED`, `mode=persistent`; provenance HTTP 200; protected endpoint HTTP 401.

## Frontend

- https://centinela-alpha.vercel.app: HTTP 200.
- https://centinela-alpha.vercel.app/human-cabin: HTTP 200.
- `Sentinela Habla`: visible en HTML/chunk de produccion.
- Render: no detectado en HTML/chunks de produccion revisados.
- Sombra: no detectado en HTML/chunks de produccion revisados.
- Acceso CEO publico: no detectado en HTML/chunks de produccion revisados.
- CORS backend para `https://centinela-alpha.vercel.app`: OK en preflight OPTIONS.

## Operativo

- Backend Vercel vivo.
- Provenance publico vivo.
- Frontend produccion vivo.
- Cabina Humana produccion viva.
- Auth protegido responde 401 sin token.
- Health queda listo para reconocer DB real cuando `DATABASE_URL` este presente.

## Sigue Local / Demo

- Persistencia productiva sigue pendiente.
- Cabina Humana mantiene modo demo/local hasta que haya DB productiva y politica comercial definitiva.
- Login/admin productivo sigue pendiente de secrets y DB real.

## Riesgos

- Sin `DATABASE_URL` productiva, los datos no persisten.
- Si se usa la URL local Render, se violaria la orden de no volver a Render.
- Si se activa `ENVIRONMENT=production` sin `SECRET_KEY`, el backend puede fallar al importar auth.
- Si se inicializa admin sin `ADMIN_PASSWORD` productivo, no debe crearse usuario por defecto.

## Proximos Pasos CEO

1. Crear o seleccionar PostgreSQL productivo no-Render.
2. Copiar connection string.
3. Agregarlo en Vercel Production como `DATABASE_URL`.
4. Confirmar `SECRET_KEY` y `ADMIN_PASSWORD` productivos sin imprimirlos.
5. Redeploy backend.
6. Ejecutar inicializacion idempotente de schema.
7. Validar que `/api/v1/health` ya no reporte `database=unavailable` ni `mode=ram_only`.
