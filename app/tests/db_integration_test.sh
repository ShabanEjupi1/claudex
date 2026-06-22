#!/usr/bin/env bash
# DB integration test: applies app/db/schema.sql to a throwaway PostgreSQL
# cluster and verifies the least-privilege grants + the app's actual SQL.
#
# Requirements: a local PostgreSQL install. MUST NOT run as root (PostgreSQL
# refuses) — run as a normal user, or:  su postgres -c 'bash db_integration_test.sh'
#
# Usage: app/tests/db_integration_test.sh [path/to/schema.sql]
set -uo pipefail

SCHEMA_SRC="${1:-$(cd "$(dirname "$0")/../db" && pwd)/schema.sql}"
PGBIN="${PGBIN:-$(dirname "$(command -v initdb || echo /usr/lib/postgresql/16/bin/initdb)")}"
BASE="$(mktemp -d "${TMPDIR:-/tmp}/pgitest.XXXXXX")"
SOCK="$BASE/sock"; PGDATA="$BASE/data"; PORT="${PORT:-55432}"
mkdir -p "$SOCK"
export PGHOST="$SOCK" PGPORT="$PORT"
P="$PGBIN/psql"

cleanup() { "$PGBIN/pg_ctl" -D "$PGDATA" stop >/dev/null 2>&1 || true; rm -rf "$BASE"; }
trap cleanup EXIT

SCHEMA="$BASE/schema_run.sql"
SHARE="$($PGBIN/pg_config --sharedir)"
if [ -f "$SHARE/extension/pgcrypto.control" ]; then
  cp "$SCHEMA_SRC" "$SCHEMA"
else
  echo "[!] pgcrypto absent — stripping it for this test (optional in prod)"
  grep -v pgcrypto "$SCHEMA_SRC" > "$SCHEMA"
fi

"$PGBIN/initdb" -D "$PGDATA" --auth-local=trust --auth-host=trust -U postgres >/dev/null 2>&1
"$PGBIN/pg_ctl" -D "$PGDATA" -o "-k $SOCK -p $PORT -c listen_addresses=''" -l "$BASE/log" start >/dev/null 2>&1
for _ in $(seq 1 20); do "$P" -U postgres -d postgres -tAc 'select 1' >/dev/null 2>&1 && break; sleep 0.3; done

"$P" -U postgres -d postgres -c 'CREATE DATABASE audit;' >/dev/null
"$P" -U postgres -d audit -v ON_ERROR_STOP=1 -f "$SCHEMA" >/dev/null && echo "schema applied OK"

PASS=0; FAIL=0
check() { local d="$1" e="$2" sql="$3" role="$4" out r
  if out=$("$P" -U "$role" -d audit -v ON_ERROR_STOP=1 -tAc "$sql" 2>&1); then r=ok; else r=deny; fi
  if [ "$r" = "$e" ]; then echo "  PASS: $d"; PASS=$((PASS+1));
  else echo "  FAIL: $d (want $e got $r) :: $out"; FAIL=$((FAIL+1)); fi
}

INS="INSERT INTO findings (schema_version,source_collector,source_method,asset_hostname,asset_ip,asset_role,asset_zone,category,service_name,service_port,service_transport,cis_reference,cve,severity,status,evidence,detected_at,remediated_at) VALUES ('1.0','scanner-01','nmap','edge-rtr-01','10.10.10.1'::inet,'router','edge','legacy-protocol','telnet',23,'tcp','CIS Controls v8 4.8',ARRAY['CVE-1999-0619'],'high','open','TCP/23 open','2026-06-22T09:15:00Z'::timestamptz,NULL::timestamptz)"
READ="SELECT id, host(asset_ip), asset_zone, cve FROM findings WHERE asset_zone = ANY(ARRAY['edge']) ORDER BY detected_at DESC LIMIT 500"
AUD="INSERT INTO audit_log (actor,actor_role,action,client_ip,detail) VALUES ('alice','auditor','list_findings','10.10.10.5'::inet,'1 rows')"

check "app_ingest can INSERT a finding" ok "$INS" app_ingest
check "app_ingest CANNOT SELECT findings (write-only)" deny "SELECT count(*) FROM findings" app_ingest
check "app_dashboard can SELECT findings (zone filter)" ok "$READ" app_dashboard
check "app_dashboard can INSERT audit_log" ok "$AUD" app_dashboard
check "app_dashboard CANNOT INSERT findings (read-only)" deny "$INS" app_dashboard

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
