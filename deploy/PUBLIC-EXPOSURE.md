# Exposing the dashboard to the public internet (single WAN IP, on-prem)

This supplements `deploy/README.md`. It covers the case where:

- both ProLiant nodes sit on **one private LAN** you control, and
- they reach the internet through **one NAT router with a single public (WAN) IP**, and
- you want the **dashboard reachable from the public internet**.

> The two nodes sharing one public IP is normal NAT behaviour, not a fault. The
> keepalived VIP (`10.10.173.20`) is the single LAN entry point; you publish *that*
> to the internet with a port-forward. Failover is unaffected — the router always
> forwards to the VIP, which keepalived moves to the healthy node.

```
Internet ─► Router (WAN IP, :443)  ──DNAT──►  10.10.173.20:443 (VIP)
                                                      │
                              LAN 10.10.173.0/24      ▼
                              proliant-1(.22) ◄─VIP─► proliant-2(.23)
```

## ⚠️ Security reality check (read before proceeding)

The app is designed as **internal Tier-0**. Normally the dashboard is reachable
*only* from `allowed_admin_cidr` (nginx `allow/deny` + firewalld). Public exposure
removes that network control, so your security then rests on **OIDC auth + TLS +
rate limiting**. Before exposing:

1. **Your OIDC IdP must be publicly reachable.** The login redirect happens in the
   user's browser, so `oidc_issuer` cannot be an `idp.internal` address that only
   the LAN can resolve/reach. Move the IdP to a public hostname (or front it the
   same way), or public users cannot authenticate.
2. **Do NOT expose ingest (`:8443`).** Collectors are internal and use mTLS. Only
   forward `:443`. Leave `allowed_collector_cidr` as a private subnet.
3. Consider whether a **VPN / Cloudflare Tunnel / WireGuard** is acceptable instead
   of raw public exposure — it keeps the original threat model intact and is the
   recommended option for a security-audit dashboard. Public 443 is documented here
   because you asked for it; the VPN path is in the last section.

---

## Step 1 — Router: port-forward + NAT loopback

On your edge router/firewall:

- **DNAT / port-forward:** `TCP <WAN_IP>:443  ->  10.10.173.20:443`
- **Do not** forward `:8443` (ingest) or `:22` (SSH) from the internet.
- Enable **NAT loopback / hairpin NAT** so admins *inside* the LAN can also reach
  the public hostname. Without it, internal browsers resolving the public DNS name
  will fail to connect.
- If the router can, restrict the forward to known source countries/IPs, or put a
  WAF in front. Every bit of source narrowing you keep is a bit of the original
  control you keep.

## Step 2 — Public DNS

Create an `A` record for the dashboard hostname pointing at your **WAN IP**:

```
dashboard.example.com.  300  IN  A  <WAN_IP>
```

Then set the server name in `deploy/ansible/group_vars/all.yml`:

```yaml
dashboard_server_name: dashboard.example.com
```

## Step 3 — Real TLS certificate (Let's Encrypt, DNS-01)

Self-signed certs break for public browsers. Use **DNS-01** (not HTTP-01) because
you are behind NAT and have two nodes — DNS-01 needs no inbound port 80 and issues
a cert usable on whichever node holds the VIP.

On the **primary** (or a control host with your DNS provider's API token):

```bash
# example: Cloudflare DNS plugin; pick the plugin for your DNS provider
sudo dnf install -y certbot python3-certbot-dns-cloudflare
sudo certbot certonly \
  --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cf.ini \
  -d dashboard.example.com \
  --deploy-hook /usr/local/bin/audit-cert-deploy.sh
```

Point the Ansible TLS paths at the issued cert (`group_vars/all.yml`):

```yaml
tls_cert: /etc/letsencrypt/live/dashboard.example.com/fullchain.pem
tls_key:  /etc/letsencrypt/live/dashboard.example.com/privkey.pem
```

Because this is **active-passive**, the cert must exist on **both** nodes. Use a
deploy hook that copies the renewed cert to the peer and reloads nginx there:

```bash
# /usr/local/bin/audit-cert-deploy.sh  (root, 0750)
#!/usr/bin/env bash
set -euo pipefail
PEER=10.10.173.23   # the standby
D=/etc/letsencrypt/live/dashboard.example.com
rsync -a --rsync-path="sudo rsync" "$D/" "audit_admin@${PEER}:${D}/"
ssh "audit_admin@${PEER}" 'sudo systemctl reload nginx'
systemctl reload nginx
```

(For enterprise PKI instead of Let's Encrypt, just place a publicly-trusted cert at
those paths — the `tls` role becomes a no-op, as documented in `deploy/README.md`.)

## Step 4 — Let nginx + firewalld accept public traffic

Right now the dashboard is locked to `allowed_admin_cidr`. Introduce a switch so
public exposure is explicit and revertible.

`group_vars/all.yml`:

```yaml
# When true, the dashboard server block + firewalld accept any source on 443.
# Security then depends on OIDC + TLS + rate limiting (see below). Default false.
dashboard_public: false
```

`roles/nginx/templates/dashboard.conf.j2` — replace the hard `allow/deny` block:

```jinja
{% if dashboard_public %}
    # PUBLIC: any source may reach TLS; access control is OIDC + rate limit.
    limit_req zone=dash burst=20 nodelay;
{% else %}
    # Internal: only the admin/jump-host subnet may reach the dashboard.
    allow {{ allowed_admin_cidr }};
    deny  all;
{% endif %}
```

Add the rate-limit zone once, at `http` scope (e.g. a new
`roles/nginx/templates/ratelimit.conf.j2` dropped into `/etc/nginx/conf.d/`):

```nginx
limit_req_zone $binary_remote_addr zone=dash:10m rate=10r/s;
```

`roles/nginx/tasks/main.yml` — make the 443 firewalld rule conditional:

```yaml
- name: Allow dashboard (443) from the admin subnet
  ansible.posix.firewalld:
    rich_rule: "rule family=ipv4 source address={{ allowed_admin_cidr }} port port=443 protocol=tcp accept"
    permanent: true
    immediate: true
    state: enabled
  when: not dashboard_public

- name: Allow dashboard (443) from anywhere (public exposure)
  ansible.posix.firewalld:
    port: 443/tcp
    permanent: true
    immediate: true
    state: enabled
  when: dashboard_public
```

> Keep the ingest (`:8443`) rule untouched — it stays collector-subnet only.

## Step 5 — OIDC for a public origin

In the vault / rendered env file:

```
OIDC_REDIRECT_URL=https://dashboard.example.com/auth/callback
```

and `group_vars/all.yml` `oidc_issuer` must be a hostname the **public browser**
can resolve and reach. Register the new redirect URL at your IdP. Confirm the
`groups`/`zones` claims still map for RBAC.

## Step 6 — Harden the now-public web tier

- **fail2ban web jail** for nginx auth/4xx floods (mirror the existing sshd jail in
  `roles/hardening/tasks/main.yml`).
- Keep **HSTS** (already set) and the TLS 1.2/1.3-only policy (already set).
- Consider a **WAF / Cloudflare proxy** in front for bot filtering and to hide the
  WAN IP.
- Watch `audit-dashboard` and nginx logs in the existing Prometheus/Grafana stack;
  alert on auth failure spikes.

---

## Apply

From a control host on the LAN that can SSH to both nodes (this cannot run from a
cloud session — private destination IPs are blocked there):

```bash
cd deploy/ansible
ansible-playbook site.yml --ask-vault-pass --check   # dry run, review the diff
ansible-playbook site.yml --ask-vault-pass           # apply
```

Verify:

```bash
# from the public internet (not your LAN):
curl -I https://dashboard.example.com/        # 200/302 to /login, valid public cert
# from a collector host on the LAN (unchanged):
scripts/discovery/post-finding.sh examples/finding.example.json
# confirm ingest is NOT reachable from outside:
curl -k --max-time 5 https://<WAN_IP>:8443/   # must time out / refuse
```

---

## Strongly recommended alternative: don't expose 443 at all

For a security-audit dashboard, the lowest-risk way to get "reachable from outside"
is to **not** open a public port:

- **WireGuard / VPN:** admins VPN into the LAN, then hit the VIP exactly as the
  internal design intends. Zero public attack surface; no changes to nginx/firewalld.
- **Cloudflare Tunnel (or similar):** a `cloudflared` daemon on the primary makes an
  **outbound** connection to the edge, so you forward **no** router ports and never
  expose the WAN IP. Put Cloudflare Access (SSO/MFA) in front for auth.

Either keeps the original threat model intact. Use Steps 1–6 only if a raw public
endpoint is a hard requirement.
