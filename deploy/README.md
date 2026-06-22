# Deployment — Audit Platform (active-passive, 2× ProLiant)

Deploys the ingest API + RBAC dashboard + monitoring across
**10.10.173.22 (primary/MASTER)** and **10.10.173.23 (standby/BACKUP)** behind a
floating keepalived VIP. Run this **from inside your network** — a control host
that can SSH to both nodes. (It cannot be run from the cloud session that
generated it; that environment blocks private destination IPs.)

## ⚠️ First, rotate the shared credentials

The `customs` / `customs` password was disclosed in chat — **rotate it now** and
do not reuse it. This automation deliberately uses **SSH key auth only** and the
`hardening` role **disables password authentication** entirely. Set a dedicated
key-based admin account (`audit_admin` in the inventory) before running.

## Prerequisites

- Control node with `ansible-core` (2.15+) and the collections in `requirements.yml`.
- SSH key access to both nodes as a sudo-capable user (see `inventory/hosts.ini`).
- **TLS material** placed on each node from your internal CA:
  - `{{ tls_cert }}` / `{{ tls_key }}` (server cert for nginx + PostgreSQL)
  - `{{ ingest_client_ca }}` (CA that signs collector client certs, for mTLS)
- An **OIDC client** registered at your IdP for the dashboard (issuer, client id/secret),
  with `groups` and `zones` claims mapped for RBAC.
- Internet or an **internal PyPI mirror** reachable from the nodes (for `pip`),
  and EPEL/Grafana repos for the monitoring stack.
- A free IP for the **VIP** (`vip_address`, default `10.10.173.20`).

## Turnkey path (minimal manual steps)

```bash
# 1. set the two node IPs + your SSH key
$EDITOR deploy/ansible/inventory/hosts.ini

# 2. bootstrap: installs collections, generates+encrypts all secrets, optionally
#    generates a self-signed internal CA, and syntax-checks. (Does NOT deploy.)
GEN_SELF_SIGNED=1 deploy/bootstrap.sh      # omit the flag if you use enterprise PKI

# 3. set the one value bootstrap can't invent — your IdP's client secret
cd deploy/ansible && ansible-vault edit group_vars/vault.yml

# 4. apply (the only command that touches the servers)
ansible-playbook site.yml --ask-vault-pass --check   # dry run
ansible-playbook site.yml --ask-vault-pass           # apply
```

`bootstrap.sh` writes secrets to `group_vars/vault.yml` (git-ignored, encrypted)
and, with `GEN_SELF_SIGNED=1`, certs to `files/tls/` (git-ignored) which the
`tls` role distributes to the nodes automatically.

## Manual path (enterprise PKI / explicit control)

```bash
cd deploy/ansible
ansible-galaxy collection install -r requirements.yml

cp group_vars/vault.example.yml group_vars/vault.yml
#   ... fill with strong random values: openssl rand -base64 32
ansible-vault encrypt group_vars/vault.yml

# Pre-place enterprise-CA certs at the node paths in group_vars/all.yml,
# then the 'tls' role is a no-op.
$EDITOR group_vars/all.yml inventory/hosts.ini

ansible-playbook --syntax-check site.yml
ansible-playbook site.yml --ask-vault-pass --check    # dry run
ansible-playbook site.yml --ask-vault-pass            # apply
```

## What gets deployed

| Layer | Detail |
|---|---|
| Hardening | CIS-aligned sshd (key-only), firewalld default-deny + per-service allows, sysctl, auditd, fail2ban |
| Database | PostgreSQL with TLS + SCRAM; write-only `app_ingest` and read `app_dashboard` roles; streaming replication primary→standby |
| App | `audit-ingest` (127.0.0.1:8001) and `audit-dashboard` (127.0.0.1:8002) as sandboxed systemd/gunicorn services |
| Web | nginx TLS 1.2/1.3; dashboard on 443 (admin subnet only); ingest on 8443 (mTLS, collector subnet only) |
| HA | keepalived VIP, active-passive; VIP follows the node whose dashboard passes its health check |
| Monitoring | node_exporter on both nodes; Prometheus + Grafana on the primary |

## Failover behavior

- **App/web/VIP:** automatic. If the active node's dashboard health check fails,
  VRRP priority drops and the VIP moves to the standby.
- **Database:** the standby is a streaming replica (read-only). Promotion to
  primary on failover is **not** automated here — run `pg_ctl promote` (or wire
  up **Patroni/repmgr** for managed automatic DB failover). This tradeoff is
  called out in `roles/postgres/tasks/main.yml`.

## Verify after deploy

```bash
# from an admin host in the allowed subnet
curl -kI https://<vip_address>/            # dashboard responds (redirects to /login)
# from a collector host with a client cert
scripts/discovery/post-finding.sh examples/finding.example.json
# on the primary
sudo -u postgres psql audit -c '\dp findings'   # confirm least-privilege grants
```

## Security notes

- Secrets only ever exist in `group_vars/vault.yml` (encrypted) and in a
  root-owned `0640` env file on the nodes — never in the repo.
- The exposed web tier holds **no** credentials into the device network; it only
  reads its own database (the directionality from the audit runbook).
- Treat the dashboard host as Tier-0: see `docs/dashboard-hardening-checklist.md`.
