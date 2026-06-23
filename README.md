# Internal Network Security Audit & Reporting Workflow

A version-controlled workflow for auditing internal network infrastructure,
reducing attack surface by retiring legacy/unencrypted services, and securely
feeding the findings into the internal reporting dashboard at **`10.10.173.22`**.

This repo is the *workflow as code*: runbook, discovery tooling, a read-only
CIS audit playbook, the ingest data contract, and the dashboard hardening
checklist. It is intentionally tool-agnostic where it can be, and opinionated
where security demands it.

## Architecture — three trust zones, one-way data flow

The governing principle: **the exposed dashboard tier must never hold standing
credentials that reach into network devices.** Data flows from higher-trust
collection toward lower-trust presentation, never the reverse.

```
 ZONE A: Collection (mgmt VLAN)      ZONE B: Data Tier            ZONE C: Presentation
 ┌──────────────────────────┐  push ┌──────────────────┐  read   ┌─────────────────────┐
 │ Scanners / collectors     │ ───►  │ Hardened store    │ ◄────   │ Dashboard / web UI   │
 │ (nmap, Nessus, CIS-CAT,   │ mTLS  │ (broker + DB,     │  RO     │ 10.10.173.22         │
 │  Oxidized, Ansible)       │       │  encrypted)       │         │ (RBAC, SSO, MFA)     │
 └──────────────────────────┘       └──────────────────┘         └─────────────────────┘
        most privileged                  crown jewels                  most exposed
```

## Repository layout

| Path | Purpose |
|---|---|
| `docs/network-audit-runbook.md` | The end-to-end runbook (phases 0–7). Start here. |
| `docs/dashboard-hardening-checklist.md` | Section 3 — securing the `10.10.173.22` host. |
| `scripts/discovery/nmap-discovery.sh` | Active TCP/UDP + crypto-posture discovery. |
| `scripts/discovery/post-finding.sh` | Example collector push (mTLS + token + HMAC). |
| `ansible/cis-network-audit.yml` | Read-only CIS posture audit for Cisco IOS. |
| `ansible/inventory.example.ini` | Sample inventory (use a read-only AAA account). |
| `schemas/ingest-finding.schema.json` | The ingest data contract (JSON Schema 2020-12). |
| `examples/finding.example.json` | A sample finding that validates against the schema. |
| `app/` | The dashboard application: write-only ingest API + RBAC read UI (FastAPI + PostgreSQL). |
| `deploy/ansible/` | Active-passive HA deployment for the two ProLiant nodes (keepalived VIP, nginx mTLS, monitoring). |
| `deploy/CLOUDFLARE-TUNNEL.md` | **Recommended** way to reach the dashboard from outside — outbound-only tunnel, no inbound ports. |
| `deploy/PUBLIC-EXPOSURE.md` | Alternative: raw public `:443` via router port-forward (single WAN IP). Higher attack surface. |

## Quick start

```bash
# 1. Discover (only within an approved, change-controlled scan window)
scripts/discovery/nmap-discovery.sh 10.10.0.0/16

# 2. Audit device configs against CIS (read-only)
ansible-galaxy collection install cisco.ios
ansible-playbook -i ansible/inventory.ini ansible/cis-network-audit.yml

# 3. Validate a finding against the contract, then push it
python -m jsonschema -i examples/finding.example.json schemas/ingest-finding.schema.json
scripts/discovery/post-finding.sh examples/finding.example.json
```

> **Do not commit scan output.** It contains sensitive infrastructure and
> vulnerability data. `audit-output/` and key material are git-ignored.
