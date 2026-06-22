#!/usr/bin/env bash
# Turnkey bootstrap for the audit platform.
#
# Run from a control host that can SSH (key-based) to both ProLiant nodes.
# It reduces your manual work to:
#   1. set the two node IPs + your SSH key in ansible/inventory/hosts.ini
#   2. run this script
#   3. set the OIDC client secret (one value from your IdP)
#   4. run the printed apply command
#
# It does NOT auto-deploy: production changes should be reviewed via --check first.
set -euo pipefail
cd "$(dirname "$0")/ansible"

command -v ansible-playbook >/dev/null || { echo "ERROR: install ansible-core first"; exit 1; }
command -v openssl >/dev/null || { echo "ERROR: openssl is required"; exit 1; }

echo "[*] Installing required collections"
ansible-galaxy collection install -r requirements.yml

VAULT=group_vars/vault.yml
if [ ! -f "$VAULT" ]; then
  echo "[*] Generating strong random secrets -> $VAULT"
  gen() { openssl rand -base64 32 | tr -d '\n'; }
  vrrp() { openssl rand -base64 12 | tr -dc 'A-Za-z0-9' | cut -c1-8; }  # VRRP pass <= 8 chars
  cat > "$VAULT" <<EOF
vault_pg_ingest_password: "$(gen)"
vault_pg_dashboard_password: "$(gen)"
vault_pg_replication_password: "$(gen)"
vault_ingest_token: "$(gen)"
vault_ingest_hmac_key: "$(gen)"
vault_session_secret: "$(gen)"
vault_oidc_client_secret: "REPLACE_WITH_OIDC_CLIENT_SECRET"
vault_keepalived_auth_pass: "$(vrrp)"
EOF
  echo "[*] Encrypting the vault (you will choose a vault password)"
  ansible-vault encrypt "$VAULT"
  echo "    -> set the OIDC client secret from your IdP:  ansible-vault edit $VAULT"
else
  echo "[*] $VAULT already exists — leaving it untouched"
fi

# Optional: self-signed internal PKI for an internal-only deploy.
# Skip if you manage certs via enterprise PKI (pre-place them at the node paths
# in group_vars/all.yml). Enable with: GEN_SELF_SIGNED=1 ./bootstrap.sh
TLSDIR=files/tls
if [ "${GEN_SELF_SIGNED:-0}" = "1" ] && [ ! -f "$TLSDIR/audit.crt" ]; then
  echo "[*] Generating a self-signed internal CA + server/collector certs -> ansible/$TLSDIR"
  mkdir -p "$TLSDIR"; ( cd "$TLSDIR"
    openssl req -x509 -newkey rsa:4096 -nodes -keyout ca.key -out ca.crt -days 1825 \
      -subj "/CN=Audit Internal CA"
    openssl req -newkey rsa:2048 -nodes -keyout audit.key -out audit.csr \
      -subj "/CN=dashboard.internal" \
      -addext "subjectAltName=DNS:dashboard.internal,DNS:ingest.internal"
    openssl x509 -req -in audit.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -out audit.crt -days 825 -copy_extensions copy
    cp ca.crt collector-ca.crt   # this CA also signs collector client certs
    rm -f audit.csr )
  echo "    -> the 'tls' role will distribute these to the nodes automatically"
fi

echo "[*] Syntax check"
ansible-playbook --syntax-check site.yml

cat <<'NEXT'

[+] Bootstrap complete. Review, then apply (this is the only command that
    touches the servers):

      cd deploy/ansible
      ansible-playbook site.yml --ask-vault-pass --check   # dry run
      ansible-playbook site.yml --ask-vault-pass           # apply

NEXT
