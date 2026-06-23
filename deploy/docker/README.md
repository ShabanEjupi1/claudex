# Containerised deploy (Ubuntu + Docker)

Runs the audit platform as containers **alongside your existing Docker stack**,
exposed through the **host Cloudflare Tunnel** (`audit.spacecode.tech`). It makes
**no** host-level changes — no firewall edits, no sshd changes, no system nginx —
so it won't disturb your live sites. This is the supported path for these servers
(the `deploy/ansible/` HA design targets dedicated RHEL nodes, not these).

## What runs

| Service | Image | Port | Notes |
|---|---|---|---|
| `db` | `postgres:16` | not published | schema + least-privilege roles created on first init |
| `dashboard` | built from repo | `127.0.0.1:8002` | the read UI; what the tunnel points at |
| `ingest` | built from repo | `127.0.0.1:8001` | write-only API; needs an mTLS front (see below) |

Verified end-to-end: image builds, both apps import, the DB initialises with the
write-only/read roles (`app_ingest=INSERT only`, `app_dashboard=SELECT only`), and
the dashboard serves `/healthz` + redirects unauthenticated users to `/login`.

## Deploy

On the server (get the repo there first — `git clone` or copy):

```bash
cd deploy/docker
cp .env.example .env        # then fill it in (see below)
docker compose up -d --build
curl -s localhost:8002/healthz     # -> {"status":"ok"}
```

### Fill in `.env`
Generate secrets with `openssl rand -base64 32`. The **OIDC** block is required for
login (see caveat). Token hash: `printf '%s' "$TOKEN" | sha256sum`.

## Point the tunnel at it

On your **`kcus-host`** tunnel (the host one, not the spacecode/web tunnel), add a
public hostname:

- `audit.spacecode.tech` → Service **HTTP** → `http://localhost:8002`

The host `cloudflared` reaches the published `127.0.0.1:8002`. Then add a
**Cloudflare Access** policy on `audit.spacecode.tech` (your team + MFA).

## Two things to know

1. **OIDC is required to log in.** `/healthz` works without it, but `/login` needs a
   real IdP whose issuer is reachable **both** from the dashboard container
   (server-side metadata/token exchange) **and** the user's browser (redirect). An
   internal-only IdP won't work for users coming in over the tunnel. Use a public
   IdP (Entra/Okta/Google/Auth0) or a publicly-reachable Keycloak, and register
   `https://audit.spacecode.tech/auth/callback` as a redirect URI.
2. **Ingest rejects everything until it has an mTLS front.** The API requires the
   `X-SSL-Client-Verify: SUCCESS` header that an mTLS-terminating nginx sets for
   verified collector certs. Until you add that proxy, `ingest` runs but accepts no
   data — and it must **never** be exposed on the tunnel. The dashboard is the part
   that goes public.

## Loading data (the dashboard starts empty — by design)

The dashboard only displays findings that collectors **push in**; it does not
scan. To populate it from your network with nmap:

```bash
# 0. one-time: pick a collector token, store its hash in .env, restart ingest
TOKEN=$(openssl rand -hex 32)
sed -i "s#^INGEST_TOKEN_SHA256=.*#INGEST_TOKEN_SHA256=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)#" .env
docker compose up -d ingest

# 1. scan (SYN+UDP+version+OS needs root; -sT works unprivileged)
sudo nmap -sS -sU -sV -O -Pn -oX scan.xml 10.10.173.0/24

# 2. convert + push (INGEST_HMAC_KEY is the value from .env)
export INGEST_URL=http://127.0.0.1:8001/v1/findings
export INGEST_TOKEN=$TOKEN
export INGEST_HMAC_KEY=$(grep ^INGEST_HMAC_KEY= .env | cut -d= -f2-)
python3 ../../scripts/discovery/nmap_to_findings.py scan.xml --zone core --collector "$(hostname)"
```

Each open port becomes a finding; cleartext/legacy services (telnet, FTP, SNMP
v1/2c, HTTP mgmt, r-services…) are flagged at higher severity, the rest are
informational `open-port`s. Use `--dry-run` to preview without sending. Refresh
the dashboard and the findings appear. Re-run per subnet/zone as needed.

> Ingest is published on `127.0.0.1:8001` only — run the scan/push from the host,
> and never put ingest on the public tunnel.

### Automated background scanning (no waiting)

Instead of running nmap by hand, enable the **scanner** service — a separate
container that scans your subnets on a schedule and auto-pushes findings. It runs
detached, so you never wait on a scan. It's intentionally *not* part of the
read-only dashboard tier (it holds the ingest token and initiates scans).

In `.env` set:
```
INGEST_TOKEN=<the plaintext collector token>     # the API hashes it itself
SCAN_TARGETS=10.10.173.0/24 10.10.20.0/24         # your subnets
NMAP_ARGS=-sS -sV -T4 --top-ports 1000 -Pn        # tune speed/coverage
SCAN_INTERVAL_HOURS=6
```
Then start it (opt-in profile):
```bash
docker compose --profile scanner up -d --build
docker compose logs -f scanner      # watch scan cycles
```
It scans each target, pushes findings, sleeps `SCAN_INTERVAL_HOURS`, repeats —
findings just appear on the dashboard. Uses host networking + `NET_RAW` so `-sS`
works against the LAN. Stop it with `docker compose --profile scanner down` (or
just `docker compose stop scanner`).

## Operations

```bash
docker compose ps                 # status + health
docker compose logs -f dashboard  # logs
docker compose pull && docker compose up -d --build   # update
docker compose down               # stop (keeps the pgdata volume)
```

DB data lives in the `pgdata` volume; the schema/roles are created only on first
init (empty volume). To re-run init, `docker compose down -v` (⚠️ destroys data).
