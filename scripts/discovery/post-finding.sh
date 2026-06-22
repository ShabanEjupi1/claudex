#!/usr/bin/env bash
# post-finding.sh — push a validated finding to the ingest API (Zone A -> Zone B).
#
# Security model:
#   * mTLS client certificate (network identity)
#   * short-lived, scoped, WRITE-ONLY bearer token (fetched from Vault, never hardcoded)
#   * HMAC-SHA256 over the exact bytes sent (tamper/replay detection at the ingest tier)
#
# This is a reference implementation — adapt the secret backend / endpoint to your stack.

set -euo pipefail

PAYLOAD="${1:?Usage: post-finding.sh <finding.json>}"
INGEST_URL="${INGEST_URL:-https://ingest.internal:8443/v1/findings}"

CLIENT_CERT="${CLIENT_CERT:-/etc/pki/collector.crt}"
CLIENT_KEY="${CLIENT_KEY:-/etc/pki/collector.key}"
CA_CERT="${CA_CERT:-/etc/pki/internal-ca.crt}"

command -v curl   >/dev/null || { echo "curl not found"   >&2; exit 1; }
command -v vault  >/dev/null || { echo "vault not found"  >&2; exit 1; }
command -v openssl>/dev/null || { echo "openssl not found">&2; exit 1; }
[ -f "$PAYLOAD" ] || { echo "payload not found: $PAYLOAD" >&2; exit 1; }

# Short-lived, scoped, write-only token + HMAC key from the secrets manager.
TOKEN="$(vault kv get -field=token    secret/audit/ingest)"
HMAC_KEY="$(vault kv get -field=hmac_key secret/audit/ingest)"

# Sign the exact bytes we are about to send.
SIG="$(openssl dgst -sha256 -hmac "$HMAC_KEY" -binary < "$PAYLOAD" | xxd -p -c256)"

curl --fail --silent --show-error \
     --tlsv1.3 \
     --cert "$CLIENT_CERT" --key "$CLIENT_KEY" --cacert "$CA_CERT" \
     -H "Authorization: Bearer ${TOKEN}" \
     -H "X-Signature: sha256=${SIG}" \
     -H "Content-Type: application/json" \
     --data-binary "@${PAYLOAD}" \
     "$INGEST_URL"
