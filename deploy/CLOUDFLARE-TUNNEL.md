# Public access via Cloudflare Tunnel (recommended)

Gives the dashboard a public URL (e.g. **`audit.spacecode.tech`**) **without opening
any inbound port, forwarding anything on your router, or exposing your WAN IP**.
`cloudflared` runs on both ProLiant nodes and dials *out* to Cloudflare; Cloudflare's
edge terminates TLS, runs the WAF, and enforces SSO/MFA via **Cloudflare Access**
before traffic ever reaches your LAN. This keeps the app's internal-only threat model
intact.

```
            user ──HTTPS──► Cloudflare edge ──(SSO via Access)──┐
                                                                │  outbound-only
                              ┌─── cloudflared (proliant-1) ◄────┤  tunnel (no
                              │                                   │  inbound ports)
   localhost:8002 dashboard ◄─┤                                   │
                              └─── cloudflared (proliant-2) ◄─────┘
                two connectors, one tunnel  → Cloudflare auto-fails-over between them
```

Ingest (`:8443`, collectors, mTLS) is **never** tunneled — it stays internal.

This repo uses the **remotely-managed (token)** tunnel style: you create the tunnel
and its public hostname in the Cloudflare dashboard, and the only thing Ansible needs
is the connector **token**. Public-hostname routing lives in the dashboard, not in a
local `config.yml`.

## How this maps to the repo

| Piece | Where |
|---|---|
| `cloudflared` role (install, token env file, hardened systemd unit) | `deploy/ansible/roles/cloudflared/` |
| Enable switch + public hostname + protocol | `group_vars/all.yml` (`cloudflare_*`) |
| Connector **token** (secret) | `group_vars/vault.yml` (`vault_cf_tunnel_token`) |
| Wired into the play (default-off) | `site.yml` (`when: cloudflare_tunnel_enabled`) |

While `cloudflare_tunnel_enabled: false` the role does nothing — applying the
playbook is safe today.

## Prerequisites

- A **Cloudflare account** with **`spacecode.tech` onboarded as a zone** (its
  nameservers pointed at Cloudflare), and **Zero Trust** enabled.

## Step 1 — Create the tunnel + name the public hostname (Cloudflare dashboard)

**Zero Trust → Networks → Tunnels → Create a tunnel → Cloudflared:**

1. Name it (e.g. `audit`) and **save the connector token** it shows you
   (`cloudflared service install <TOKEN>`). That token goes into vault in Step 2 —
   keep it secret.
2. On the tunnel's **Public Hostname** tab → **Add a public hostname**:
   - Subdomain `audit`, Domain `spacecode.tech`
   - Service: **`http://localhost:8002`** (the dashboard app on each node)
3. Saving auto-creates the DNS record
   `audit.spacecode.tech  CNAME  <TUNNEL_ID>.cfargotunnel.com` (proxied).

> Running the same token on both nodes makes **two connectors on one tunnel** —
> Cloudflare load-balances and fails over between them automatically.

## Step 2 — Put the values into Ansible

`group_vars/all.yml`:

```yaml
cloudflare_tunnel_enabled: true
cloudflare_public_hostname: audit.spacecode.tech
# cloudflare_tunnel_protocol: http2   # only if your egress blocks UDP/7844 (QUIC)
```

`group_vars/vault.yml` (edit encrypted) — paste the connector token from Step 1:

```yaml
vault_cf_tunnel_token: 'eyJhIjoi...'    # the long base64 string
```

```bash
cd deploy/ansible && ansible-vault edit group_vars/vault.yml
```

## Step 3 — Make the app's OIDC match the public origin

Users now arrive on `https://audit.spacecode.tech`, so the app's OIDC redirect must
use that origin (it's rendered from `dashboard_server_name` in
`roles/app/templates/app.env.j2`). Set, in `group_vars/all.yml`:

```yaml
dashboard_server_name: audit.spacecode.tech
```

Then **register `https://audit.spacecode.tech/auth/callback`** as a redirect URI at
your IdP.

> ⚠️ **IdP reachability — the thing that actually trips people up.** The OIDC login
> redirect happens in the *user's browser*. If `oidc_issuer` is an internal address
> (`https://idp.internal/...`) external users can't reach, they can't complete login
> even through the tunnel. Pick one:
> - Use a **public IdP** (Entra ID / Okta / Google / a publicly-reachable Keycloak), or
> - Publish your IdP through **its own Cloudflare Tunnel** hostname, or
> - Let **Cloudflare Access** be the gate (it federates to your IdP at the edge).
>   Note the app still needs the `groups`/`zones` claims for RBAC, so option 1 or 2
>   is cleanest.

## Step 4 — Put Cloudflare Access (SSO/MFA) in front

**Zero Trust → Access → Applications → Add → Self-hosted:**

- Application domain: `audit.spacecode.tech`
- Identity provider: your IdP (or a one-time PIN to start)
- Policy: `Allow` only your audit team (by email domain / IdP group), require MFA.

Requests are authenticated at Cloudflare's edge *before* being forwarded down the
tunnel — defense in depth on top of the app's own RBAC.

## Step 5 — Deploy

From a LAN control host that can SSH to both nodes:

```bash
cd deploy/ansible
ansible-playbook site.yml --ask-vault-pass --check    # review the diff
ansible-playbook site.yml --ask-vault-pass            # apply
```

## Verify

```bash
# On each node: connector is up and registered.
sudo systemctl status cloudflared
sudo journalctl -u cloudflared -n 30      # look for "Registered tunnel connection"

# Cloudflare Zero Trust → Networks → Tunnels: the tunnel shows TWO healthy
# connectors (one per node) = HA is live.

# From OUTSIDE your network: the hostname loads, presents the Access login,
# then the dashboard, with a valid public Cloudflare cert.
curl -I https://audit.spacecode.tech/

# Confirm nothing new is exposed inbound — these must still fail from the internet:
curl --max-time 5 https://<WAN_IP>/        # no inbound 443 forwarded
curl --max-time 5 https://<WAN_IP>:8443/   # ingest still internal-only
```

## Rotating a disclosed token

The token embeds the tunnel secret. If it leaks (e.g. pasted into a chat), rotate it:
**Zero Trust → Networks → Tunnels →** your tunnel **→ Refresh token** (or delete and
recreate the tunnel), update `vault_cf_tunnel_token`, and re-run the playbook.

## Failover behavior

- **Connector loss:** if one node (or its `cloudflared`) dies, Cloudflare routes all
  traffic through the surviving connector automatically — no VIP move needed for the
  public path. With both up, Cloudflare load-balances across them.
- **Database:** unchanged from `deploy/README.md` — the standby is a read replica, so
  its local dashboard serves reads fine; promotion on primary loss is still manual
  (or wire up Patroni/repmgr).
- The keepalived VIP + nginx path remains for **internal admins on the LAN** as a
  break-glass route; the tunnel is the public path.

## Egress notes (the only network requirement)

`cloudflared` needs **outbound** access to Cloudflare on **UDP/7844** (QUIC, default)
and **TCP/7844 + 443**. firewalld filters inbound only, so no rule is needed — but if
your perimeter blocks outbound UDP, set `cloudflare_tunnel_protocol: http2` to fall
back to TCP. No inbound rules, no port-forward, ever.
