# CENTINELA - Backup PostgreSQL

## URGENTE: Expira Mayo 31 2026

## Backup
pg_dump DATABASE_URL > backup_FECHA.sql

## Restore
psql DATABASE_URL_NUEVA < backup_FECHA.sql

## Migracion
1. Nueva DB en Supabase o Render pagado
2. pg_dump DB actual
3. psql DB nueva
4. Cambiar DATABASE_URL en Render Environment
5. Redeploy
6. Validar con GET /api/v1/stats/db

## Frecuencia
- Semanal minimo
- Antes de cambios de schema
