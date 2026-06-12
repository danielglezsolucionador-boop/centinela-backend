# SENTINELA Production Auth Status Report

Fecha: 2026-06-12

## Alcance

Validacion y normalizacion del contrato productivo de auth para:

- Backend: https://centinela-backend.vercel.app
- Frontend: https://centinela-alpha.vercel.app
- Cabina Humana: https://centinela-alpha.vercel.app/human-cabin

No se tocaron DCFT, HERMES, FORJA, CEREBRO, SOMBRA, Hetzner/sombra-01 ni Render.
No se imprimieron passwords, hashes, tokens completos ni secretos.
No se ejecuto `vercel env pull`.

## Backup

Backup prechange creado:

`D:\ECOSYSTEM\BACKUPS\sentinela-auth-contract-fix-prechange-20260612-050720.zip`

Exclusiones aplicadas: `.env`, `.env.local`, `.vercel`, `.venv`, `node_modules`, `dist`, `logs`, `cache`, `tokens`, `secrets`, `cookies`, `__pycache__`, `.git`.

## Causa

El contrato HTTP ya exigia `username` y `password`, pero el default de admin en codigo era `daniel`.
La orden CEO fija el contrato oficial productivo en `username=admin` salvo que exista `ADMIN_USERNAME`.

## Contrato antes

`POST /api/v1/auth/login`:

- Body real: `username`, `password`.
- Payload incompleto: HTTP 400.
- Credenciales invalidas: HTTP 401.
- Default admin en codigo: `daniel`.
- Password validada contra hash en DB.

## Contrato final

`POST /api/v1/auth/login`:

```json
{
  "username": "admin",
  "password": "<ADMIN_PASSWORD>"
}
```

Reglas finales:

- `ADMIN_USERNAME` se acepta desde env si existe.
- Si `ADMIN_USERNAME` no existe, se usa `admin`.
- El login del admin configurado compara contra `ADMIN_PASSWORD` de env.
- El usuario admin se asegura/sincroniza en DB solo despues de password correcto.
- El token se firma con `SECRET_KEY`.
- La respuesta incluye `access_token`, `token`, `token_type=bearer`, `username`, `email`, `is_admin`, `role=admin`.
- Bearer token sigue validandose en endpoints protegidos.

## Script seguro

Creado:

`scripts/validate_production_auth.ps1`

El script:

- Requiere `ADMIN_PASSWORD` en env local.
- Usa `ADMIN_USERNAME` o default `admin`.
- No imprime password.
- No imprime token completo.
- Enmascara token.
- Prueba login correcto, login incorrecto, payload incompleto, token invalido, sin token, con token, health y provenance.
- Sale con `0` solo si todo pasa.

Ejecucion en esta shell:

- `ADMIN_PASSWORD`: ausente.
- Resultado: bloqueado limpiamente con `ADMIN_PASSWORD: missing`, exit code `2`.

## Validacion local

- `python -m compileall . -q`: PASS.
- `python -m pytest -q`: PASS, 12 passed.
- `git diff --check`: PASS.
- Secret scan: PASS con exclusiones y allowlist de placeholders locales `local-dev` / `change-me` / `test-secret`.

## Validacion productiva sin credenciales

Backend actual:

- `GET /api/v1/health`: HTTP 200.
- `GET /api/v1/provenance`: HTTP 200.
- `POST /api/v1/auth/login` incompleto: HTTP 400.
- `POST /api/v1/auth/login` password incorrecto: HTTP 401.
- `GET /api/v1/auth/me` token invalido: HTTP 401.

Endpoints protegidos sin token:

- `GET /api/v1/auth/me`: HTTP 401.
- `GET /api/v1/incidents`: HTTP 401.
- `GET /api/v1/policy/all`: HTTP 401.
- `GET /api/v1/agents/stats`: HTTP 401.
- `GET /api/v1/resilience/degraded-runtime`: HTTP 401.
- `GET /api/v1/governance/runtime-trust`: HTTP 401.

## Frontend productivo

- `https://centinela-alpha.vercel.app`: HTTP 200.
- `https://centinela-alpha.vercel.app/human-cabin`: HTTP 200.
- Sentinela Habla visible.
- Sombra no aparece.
- Acceso CEO publico no aparece.
- Render no aparece.
- Bundles JS revisados: 10.
- Assets JS con error: 0.
- Bundle frontend contiene `centinela-backend.vercel.app`.
- Bundle frontend no contiene Render.
- CORS health desde origin frontend: HTTP 200.
- `Access-Control-Allow-Origin`: `https://centinela-alpha.vercel.app`.

## Pendiente / Bloqueo

No se pudo ejecutar login correcto productivo ni endpoints con Bearer valido porque `ADMIN_PASSWORD` no esta disponible en la shell local.

La orden prohibe descargar secretos de Vercel y prohibe imprimir credenciales, por lo que esta es la unica parte bloqueada.

## Archivos cambiados por este fix

- `core/auth.py`
- `main.py`
- `tests/test_human_cabin.py`
- `tests/test_auth_contract.py`
- `scripts/validate_production_auth.ps1`
- `SENTINELA_PRODUCTION_AUTH_STATUS_REPORT.md`

## Estado operativo

Operativo:

- Contrato oficial normalizado en codigo.
- Auth admin por env definido.
- Bearer guards conservados.
- Tests locales del contrato PASS.
- Health/provenance productivos PASS.
- Negativos auth productivos PASS.
- Frontend productivo PASS.
- Cabina Humana productiva PASS.
- Sentinela Habla visible.
- CORS sin problema critico.
- Render descartado.
- Sombra no visible.
- Acceso CEO publico no visible.

Bloqueado:

- Login correcto productivo con token valido.
- `/auth/me` productivo con token valido.
- Endpoints protegidos productivos con token valido.

Motivo: falta `ADMIN_PASSWORD` en env local seguro.
