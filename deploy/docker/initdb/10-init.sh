#!/usr/bin/env bash
# Runs ONCE, on first container init (empty data dir). Applies the app schema,
# then sets SCRAM passwords + the schema-usage grants the two least-privilege app
# roles need. Passwords come from the environment and are passed as psql vars
# (`:'var'`) so special characters are quoted safely.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f /schema.sql

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v ingest_pw="$INGEST_DB_PASSWORD" -v dashboard_pw="$DASHBOARD_DB_PASSWORD" <<'SQL'
ALTER ROLE app_ingest    WITH PASSWORD :'ingest_pw';
ALTER ROLE app_dashboard WITH PASSWORD :'dashboard_pw';
-- PG15+ locks down the public schema; the roles need USAGE to reach the tables
-- (table-level grants are already in schema.sql). CONNECT is granted to PUBLIC.
GRANT USAGE ON SCHEMA public TO app_ingest, app_dashboard;
SQL
