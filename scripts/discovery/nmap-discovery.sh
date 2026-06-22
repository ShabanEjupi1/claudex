#!/usr/bin/env bash
# nmap-discovery.sh — Phase 3 active discovery for the network audit workflow.
# Produces TCP + UDP service inventories and crypto-posture data for diffing
# against the CIS baseline.
#
# AUTHORIZATION: run ONLY within an approved, change-controlled scan window.
# Active scans (especially -p- and -sU) can disrupt fragile legacy devices.

set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 <targets|targets-file> [output-dir]
  e.g. $0 10.10.0.0/16
       $0 targets.txt ./audit-output/run1
Output is written as nmap .nmap/.gnmap/.xml triples (git-ignored).
EOF
  exit 1
}

TARGETS="${1:-}"
OUTDIR="${2:-./audit-output/$(date +%Y%m%d-%H%M%S)}"

[ -z "$TARGETS" ] && usage
command -v nmap >/dev/null || { echo "nmap not found in PATH" >&2; exit 1; }

mkdir -p "$OUTDIR"

# Use -iL if a file was given, otherwise treat the argument as a literal spec.
if [ -f "$TARGETS" ]; then TGT=(-iL "$TARGETS"); else TGT=("$TARGETS"); fi

echo "[*] TCP service/version sweep (open ports only)…"
nmap -sS -sV -p- --open -T3 --script banner \
     -oA "$OUTDIR/tcp-services" "${TGT[@]}"

echo "[*] UDP sweep + SNMP info for high-value mgmt services…"
nmap -sU -sV --open -T3 -p 69,123,161,162,514 \
     --script "snmp-info,snmp-sysdescr" \
     -oA "$OUTDIR/udp-services" "${TGT[@]}"

echo "[*] Legacy/insecure service + crypto-posture checks…"
nmap -sS --open -T3 -p 21,23,79,80,512,513,514,7,9,13,19,443,22 \
     --script "ssl-enum-ciphers,ssh2-enum-algos" \
     -oA "$OUTDIR/legacy-checks" "${TGT[@]}"

echo "[+] Done. Results in $OUTDIR"
echo "    Next: convert XML -> findings JSON (schemas/ingest-finding.schema.json)"
echo "    then push via scripts/discovery/post-finding.sh"
