# SENTINELA Production Auth Status Report

Fecha: 2026-06-16 02:23:46 -05:00

## Alcance

Validacion final de auth productivo para:

- Backend: https://centinela-backend.vercel.app
- Frontend: https://centinela-alpha.vercel.app
- Cabina Humana: https://centinela-alpha.vercel.app/human-cabin

Reglas respetadas:

- No se uso `vercel env pull`.
- No se imprimio `ADMIN_PASSWORD`.
- No se imprimio token completo.
- No se guardo password en archivos.
- No se commiteo `.env`.
- No se tocaron DCFT, HERMES, FORJA, CEREBRO, SOMBRA ni Hetzner/sombra-01.

## Backup

Backup prechange creado:

`D:\ECOSYSTEM\BACKUPS\sentinela-final-admin-password-rotation-prechange-20260616-020640.zip`

Exclusiones aplicadas: `.env`, `.env.local`, `.env.*`, `.vercel`, `.venv`, `venv`, `node_modules`, `dist`, `logs`, `cache`, `tokens`, `secrets`, `cookies`, `__pycache__`, `.pytest_cache`.

## Rotacion y deploy

- `ADMIN_PASSWORD` de Vercel Production fue actualizado con `vercel env update ADMIN_PASSWORD production --sensitive --yes`.
- El valor no fue impreso ni escrito a disco.
- Deploy inicial tras rotacion: `https://centinela-backend-dypgp9z7j.vercel.app`, READY y aliasado.
- Se detecto 500 en login correcto por schema heredado de `users`.
- Se agrego compatibilidad idempotente en backend:
  - `core/database.py`: asegura columnas auth esperadas en `users` y relaja `NOT NULL` de columnas heredadas no gestionadas por el modelo actual.
  - `core/auth.py`: ejecuta compatibilidad de schema antes de sincronizar el admin.
- Deploy de cierre auth: `https://centinela-backend-rh3kjgycb.vercel.app`, READY y aliasado a `https://centinela-backend.vercel.app`.
- Commit backend versionado y empujado: `eb27ab9`.
- Deploy final versionado posterior: `https://centinela-backend-qn8pleltk.vercel.app`, READY y aliasado a `https://centinela-backend.vercel.app`.
- Validacion corta posterior al deploy final versionado: login correcto PASS HTTP 200, token presente, `/api/v1/auth/me` PASS HTTP 200, health PASS HTTP 200, provenance PASS HTTP 200.

## Validacion auth productiva

- Login correcto: PASS HTTP 200, token presente, usuario `admin`, rol `admin`.
- Login incorrecto: PASS HTTP 401.
- Payload incompleto: PASS HTTP 400.
- Token invalido en `/api/v1/auth/me`: PASS HTTP 401.
- Endpoints protegidos sin token:
  - `/api/v1/auth/me`: PASS HTTP 401.
  - `/api/v1/incidents`: PASS HTTP 401.
  - `/api/v1/policy/all`: PASS HTTP 401.
  - `/api/v1/agents/stats`: PASS HTTP 401.
  - `/api/v1/resilience/degraded-runtime`: PASS HTTP 401.
  - `/api/v1/governance/runtime-trust`: PASS HTTP 401.
- Endpoints protegidos con token:
  - `/api/v1/auth/me`: PASS HTTP 200.
  - `/api/v1/incidents`: PASS HTTP 200.
  - `/api/v1/policy/all`: PASS HTTP 200.
  - `/api/v1/agents/stats`: PASS HTTP 200.
  - `/api/v1/resilience/degraded-runtime`: PASS HTTP 200.
  - `/api/v1/governance/runtime-trust`: PASS HTTP 200.

## Health y provenance

- `GET /api/v1/health`: PASS HTTP 200.
- `status`: `OPERATIONAL`.
- `mode`: `persistent`.
- `database`: `CONNECTED`.
- `engines.postgresql`: `ONLINE`.
- `GET /api/v1/provenance`: PASS HTTP 200.

## Frontend productivo

Validado por HTTP, bundle JS productivo y navegador renderizado:

- Home carga: PASS HTTP 200.
- Cabina Humana carga: PASS HTTP 200.
- Cabina Humana renderiza texto visible `SENTINELA HABLA`: PASS.
- Consola browser sin errores criticos capturados: PASS.
- CORS backend para `https://centinela-alpha.vercel.app`: PASS HTTP 200 preflight.
- Frontend bundle referencia `centinela-backend.vercel.app`: PASS.
- Frontend bundle no referencia Render: PASS.
- Sombra no aparece en home, Cabina ni bundles revisados: PASS.
- Acceso CEO publico no aparece en home, Cabina ni bundles revisados: PASS.

## Tests

- `python -m compileall . -q`: PASS.
- `python -m pytest -q`: PASS, 13 passed.
- `git diff --check`: PASS.
- Secret scan: PASS, 0 apariciones del password rotado en repos/backend/frontend/workspace fuera del adjunto original; 0 tokens JWT escritos en archivos de trabajo tocados.

## Archivos cambiados

Backend:

- `core/auth.py`
- `core/database.py`
- `SENTINELA_PRODUCTION_AUTH_STATUS_REPORT.md`

Frontend local:

- `app/human-cabin/page.tsx` repuso marcadores seguros requeridos por test local: `Pago real pendiente` y `DEMO_LOCAL`.

## Estado operativo

Operativo:

- `ADMIN_PASSWORD` Production rotado.
- Backend Production redeployado y READY.
- Login correcto genera token.
- Login incorrecto, payload incompleto y token invalido responden con codigos esperados.
- Endpoints protegidos exigen token y responden con token valido.
- Health sigue `OPERATIONAL`, `persistent`, `CONNECTED`, `ONLINE`.
- Provenance responde HTTP 200.
- Frontend y Cabina Humana cargan.
- Sentinela Habla visible.
- CORS productivo OK.
- Frontend productivo apunta a backend Vercel y no a Render.
- No aparece Sombra.
- No aparece acceso CEO publico.

Riesgos/observaciones:

- Produccion tenia schema `users` heredado incompatible con el modelo actual. Quedo saneado por migracion idempotente durante login.
- Una ejecucion local de `vercel env run` vio un candidato DB tipo Render desde el entorno local; no se uso para migrar. El runtime productivo validado sigue reportando Postgres `ONLINE`.

Siguiente paso:

- Mantener este cambio de compatibilidad versionado antes de nuevas rotaciones para que futuros deploys conserven el cierre de auth.
