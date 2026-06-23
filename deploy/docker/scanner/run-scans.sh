#!/usr/bin/env bash
# Recurring background scanner. Scans each target in SCAN_TARGETS with nmap and
# pushes findings to the ingest API, then sleeps SCAN_INTERVAL_HOURS and repeats.
# Runs detached as its own container — you never wait on a scan.
set -uo pipefail

: "${SCAN_TARGETS:?set SCAN_TARGETS to space-separated CIDRs, e.g. '10.10.173.0/24 10.10.20.0/24'}"
: "${INGEST_HMAC_KEY:?set INGEST_HMAC_KEY}"
: "${INGEST_TOKEN:?set INGEST_TOKEN (plaintext collector token)}"

export INGEST_URL="${INGEST_URL:-http://127.0.0.1:8001/v1/findings}"
NMAP_ARGS="${NMAP_ARGS:--sS -sV -T4 --top-ports 1000 -Pn}"
INTERVAL_HOURS="${SCAN_INTERVAL_HOURS:-6}"
RUN_ON_START="${RUN_ON_START:-true}"

log() { echo "[$(date -u +%FT%TZ)] $*"; }

wait_for_ingest() {
  local health="${INGEST_URL%/v1/findings}/healthz"
  for _ in $(seq 1 30); do
    if curl -fsS -o /dev/null --max-time 5 "$health" 2>/dev/null; then return 0; fi
    log "waiting for ingest at $health ..."; sleep 5
  done
  log "WARN: ingest not reachable yet; scanning anyway"
}

scan_once() {
  wait_for_ingest
  for target in $SCAN_TARGETS; do
    local safe out
    safe="$(echo "$target" | tr -c 'A-Za-z0-9._-' '_')"
    out="/tmp/scan-${safe}.xml"
    log "scanning ${target} (${NMAP_ARGS})"
    # shellcheck disable=SC2086
    if nmap $NMAP_ARGS -oX "$out" "$target"; then
      python3 /srv/nmap_to_findings.py "$out" --zone "$target" --collector "scanner" \
        || log "push failed for ${target}"
    else
      log "nmap failed for ${target}"
    fi
  done
  log "scan cycle complete"
}

[ "$RUN_ON_START" = "true" ] && scan_once
while true; do
  log "sleeping ${INTERVAL_HOURS}h until next scan cycle"
  sleep "$(( INTERVAL_HOURS * 3600 ))"
  scan_once
done
