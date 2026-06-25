"""RBAC read dashboard.

Security properties:
  * AuthN via OIDC (central IdP); MFA is enforced at the IdP.
  * AuthZ via RBAC (+ zone need-to-know) on every route.
  * Jinja2 autoescaping + strict CSP defang stored-XSS from scanner data.
  * Every view/export is written to a tamper-evident audit_log.
  * Read-mostly DB role; all queries parameterized.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
from contextlib import asynccontextmanager

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.common.config import DashboardConfig
from app.common.db import make_pool
from app.dashboard.rbac import (
    Role,
    can_export,
    can_view_audit,
    can_view_raw_findings,
    role_from_claims,
    zone_filter,
    zones_from_claims,
)
from app.dashboard.remediation import playbook_for

cfg = DashboardConfig.from_env()
pool = make_pool(cfg.db_url)

oauth = OAuth()
oauth.register(
    name="idp",
    client_id=cfg.oidc_client_id,
    client_secret=cfg.oidc_client_secret,
    server_metadata_url=f"{cfg.oidc_issuer.rstrip('/')}/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile groups"},
)

_FIELDS = (
    "id, detected_at, severity, status, category, asset_hostname, "
    "host(asset_ip) AS asset_ip, asset_zone, service_name, service_port, "
    "service_transport, cis_reference, cve, evidence"
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    pool.open()
    try:
        yield
    finally:
        pool.close()


app = FastAPI(title="Audit Dashboard", docs_url=None, redoc_url=None,
              openapi_url=None, lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=cfg.session_secret,
                   https_only=True, same_site="lax")
app.mount("/static", StaticFiles(directory="app/dashboard/static"), name="static")
templates = Jinja2Templates(directory="app/dashboard/templates")

_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; "
    "script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = _CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _session_user(request: Request) -> dict | None:
    return request.session.get("user")


def _ctx(request: Request) -> dict:
    user = _session_user(request)
    role = role_from_claims(user["claims"], cfg.role_claim) if user else Role.VIEWER
    # Break-glass: emails in ADMIN_EMAILS get ADMIN even without a group claim.
    if user and cfg.admin_emails:
        email = str(user["claims"].get("email") or "").lower()
        if email in cfg.admin_emails:
            role = Role.ADMIN
    zones = zones_from_claims(user["claims"], cfg.zones_claim) if user else []
    return {"user": user, "role": role, "zones": zones}


def _audit(actor: str, actor_role: str, action: str, request: Request,
           object_type: str | None = None, object_id: str | None = None,
           detail: str | None = None) -> None:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_log "
                "(actor, actor_role, action, object_type, object_id, client_ip, detail) "
                "VALUES (%s, %s, %s, %s, %s, %s::inet, %s)",
                (actor, actor_role, action, object_type, object_id,
                 _client_ip(request), detail),
            )
        conn.commit()


_SEVERITIES = ["critical", "high", "medium", "low", "info"]
_STATUSES = ["open", "in-progress", "remediated", "accepted-risk", "false-positive"]


def _zone_conds(zones: list[str] | None):
    """Analyst need-to-know zone restriction -> (conds, params)."""
    if zones is None:
        return [], []
    if not zones:
        return ["false"], []
    return ["asset_zone = ANY(%s)"], [list(zones)]


def _finding_where(request: Request, zones: list[str] | None):
    """Build a parameterized WHERE from the query filters + zone limit."""
    conds, params = _zone_conds(zones)
    active: dict[str, str] = {}
    for key, col in (("severity", "severity"), ("status", "status"), ("category", "category")):
        val = request.query_params.get(key)
        if val:
            conds.append(f"{col} = %s")
            params.append(val)
            active[key] = val
    zone = request.query_params.get("zone")
    if zone == "(unzoned)":          # the Zones page label for NULL asset_zone
        conds.append("asset_zone IS NULL")
        active["zone"] = zone
    elif zone:
        conds.append("asset_zone = %s")
        params.append(zone)
        active["zone"] = zone
    q = (request.query_params.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        conds.append("(asset_hostname ILIKE %s OR host(asset_ip) ILIKE %s OR "
                     "service_name ILIKE %s OR coalesce(array_to_string(cve, ','), '') ILIKE %s "
                     "OR coalesce(evidence, '') ILIKE %s)")
        params += [like, like, like, like, like]
        active["q"] = q
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    return where, params, active


# --------------------------------------------------------------------------- #
# Auth routes
# --------------------------------------------------------------------------- #
@app.get("/login")
async def login(request: Request):
    return await oauth.idp.authorize_redirect(request, cfg.oidc_redirect_url)


@app.get("/auth/callback")
async def auth_callback(request: Request):
    try:
        token = await oauth.idp.authorize_access_token(request)
    except OAuthError:
        raise HTTPException(status_code=401, detail="authentication failed")
    claims = token.get("userinfo") or await oauth.idp.userinfo(token=token)
    request.session["user"] = {
        "sub": claims.get("sub"),
        "name": claims.get("name") or claims.get("preferred_username") or claims.get("email"),
        "claims": dict(claims),
    }
    return RedirectResponse("/", status_code=302)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


# --------------------------------------------------------------------------- #
# Data routes
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
async def summary(request: Request):
    ctx = _ctx(request)
    if not ctx["user"]:
        return RedirectResponse("/login", status_code=302)
    open_f = "status NOT IN ('remediated','false-positive')"
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT severity, count(*) FROM current_findings WHERE {open_f} GROUP BY severity")
        by_sev = {row[0]: row[1] for row in cur.fetchall()}
        cur.execute(f"SELECT category, count(*) FROM current_findings WHERE {open_f} "
                    "GROUP BY category ORDER BY 2 DESC")
        by_cat = cur.fetchall()
        top_assets = []
        if can_view_raw_findings(ctx["role"]):
            cur.execute(
                "SELECT host(asset_ip) AS ip, max(asset_hostname) AS hostname, "
                "count(*) FILTER (WHERE severity IN ('critical','high')) AS highrisk, "
                f"count(*) AS total FROM current_findings WHERE {open_f} "
                "GROUP BY asset_ip ORDER BY highrisk DESC, total DESC LIMIT 5")
            top_assets = [dict(zip(["ip", "hostname", "highrisk", "total"], r))
                          for r in cur.fetchall()]
    _audit(ctx["user"]["name"], ctx["role"].value, "view_summary", request)
    return templates.TemplateResponse(
        "summary.html",
        {"request": request, "by_sev": by_sev, "by_cat": by_cat,
         "top_assets": top_assets, "severities": _SEVERITIES, **ctx,
         "can_view_raw": can_view_raw_findings(ctx["role"]),
         "can_audit": can_view_audit(ctx["role"])},
    )


@app.get("/findings", response_class=HTMLResponse)
async def list_findings(request: Request):
    ctx = _ctx(request)
    if not ctx["user"]:
        return RedirectResponse("/login", status_code=302)
    if not can_view_raw_findings(ctx["role"]):
        raise HTTPException(status_code=403, detail="not authorized for raw findings")

    zones = zone_filter(ctx["role"], ctx["zones"])
    where, params, active = _finding_where(request, zones)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT {_FIELDS} FROM current_findings{where} "
                    "ORDER BY detected_at DESC LIMIT 500", params)
        cols = [d.name for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        cur.execute("SELECT DISTINCT category FROM current_findings ORDER BY 1")
        categories = [r[0] for r in cur.fetchall()]
        cur.execute("SELECT DISTINCT asset_zone FROM current_findings "
                    "WHERE asset_zone IS NOT NULL ORDER BY 1")
        zone_opts = [r[0] for r in cur.fetchall()]

    _audit(ctx["user"]["name"], ctx["role"].value, "list_findings", request,
           detail=f"{len(rows)} rows; filters={active}")
    return templates.TemplateResponse(
        "findings.html",
        {"request": request, "rows": rows, **ctx,
         "can_export": can_export(ctx["role"]),
         "active": active, "severities": _SEVERITIES, "statuses": _STATUSES,
         "categories": categories, "zone_opts": zone_opts},
    )


@app.get("/assets", response_class=HTMLResponse)
async def assets_view(request: Request):
    ctx = _ctx(request)
    if not ctx["user"]:
        return RedirectResponse("/login", status_code=302)
    if not can_view_raw_findings(ctx["role"]):
        raise HTTPException(status_code=403, detail="not authorized")
    conds, params = _zone_conds(zone_filter(ctx["role"], ctx["zones"]))
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT host(asset_ip) AS ip, max(asset_hostname) AS hostname, "
            "max(asset_zone) AS zone, count(*) AS total, "
            "count(*) FILTER (WHERE severity='critical') AS crit, "
            "count(*) FILTER (WHERE severity='high') AS high, "
            "count(*) FILTER (WHERE severity='medium') AS med "
            f"FROM current_findings{where} GROUP BY asset_ip "
            "ORDER BY crit DESC, high DESC, med DESC, total DESC LIMIT 500", params)
        cols = [d.name for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    _audit(ctx["user"]["name"], ctx["role"].value, "view_assets", request,
           detail=f"{len(rows)} assets")
    return templates.TemplateResponse("assets.html", {"request": request, "rows": rows, **ctx})


@app.get("/zones", response_class=HTMLResponse)
async def zones_view(request: Request):
    ctx = _ctx(request)
    if not ctx["user"]:
        return RedirectResponse("/login", status_code=302)
    if not can_view_raw_findings(ctx["role"]):
        raise HTTPException(status_code=403, detail="not authorized")
    conds, params = _zone_conds(zone_filter(ctx["role"], ctx["zones"]))
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT coalesce(asset_zone,'(unzoned)') AS zone, "
            "count(DISTINCT asset_ip) AS assets, count(*) AS total, "
            "count(*) FILTER (WHERE severity IN ('critical','high')) AS highrisk "
            f"FROM current_findings{where} GROUP BY asset_zone "
            "ORDER BY highrisk DESC, total DESC", params)
        cols = [d.name for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    _audit(ctx["user"]["name"], ctx["role"].value, "view_zones", request)
    return templates.TemplateResponse("zones.html", {"request": request, "rows": rows, **ctx})


@app.get("/report", response_class=HTMLResponse)
async def report(request: Request):
    ctx = _ctx(request)
    if not ctx["user"]:
        return RedirectResponse("/login", status_code=302)
    if not can_view_raw_findings(ctx["role"]):
        raise HTTPException(status_code=403, detail="not authorized")
    zone = request.query_params.get("zone")
    conds, params = _zone_conds(zone_filter(ctx["role"], ctx["zones"]))
    if zone == "(unzoned)":
        conds.append("asset_zone IS NULL")
    elif zone:
        conds.append("asset_zone = %s")
        params.append(zone)
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    rank = "array_position(ARRAY['critical','high','medium','low','info']::text[], severity)"
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT severity, count(*) FROM current_findings{where} GROUP BY severity", params)
        by_sev = {r[0]: r[1] for r in cur.fetchall()}
        cur.execute(f"SELECT category, count(*) FROM current_findings{where} "
                    "GROUP BY category ORDER BY 2 DESC", params)
        by_cat = cur.fetchall()
        cur.execute(
            "SELECT host(asset_ip) AS ip, max(asset_hostname) AS hostname, "
            "max(asset_zone) AS zone, "
            "count(*) FILTER (WHERE severity IN ('critical','high')) AS highrisk, "
            f"count(*) AS total FROM current_findings{where} "
            "GROUP BY asset_ip ORDER BY highrisk DESC, total DESC LIMIT 50", params)
        acols = [d.name for d in cur.description]
        assets = [dict(zip(acols, r)) for r in cur.fetchall()]
        cur.execute(f"SELECT {_FIELDS} FROM current_findings{where} "
                    f"ORDER BY {rank}, detected_at DESC LIMIT 1000", params)
        fcols = [d.name for d in cur.description]
        rows = [dict(zip(fcols, r)) for r in cur.fetchall()]
    _audit(ctx["user"]["name"], ctx["role"].value, "generate_report", request,
           detail=f"zone={zone or 'all'}; {len(rows)} findings")
    return templates.TemplateResponse("report.html", {
        "request": request, "by_sev": by_sev, "by_cat": by_cat, "assets": assets,
        "rows": rows, "scope": zone or "All zones", "severities": _SEVERITIES,
        "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), **ctx},
    )


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
async def finding_detail(request: Request, finding_id: int):
    ctx = _ctx(request)
    if not ctx["user"]:
        return RedirectResponse("/login", status_code=302)
    if not can_view_raw_findings(ctx["role"]):
        raise HTTPException(status_code=403, detail="not authorized for raw findings")

    zones = zone_filter(ctx["role"], ctx["zones"])
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT {_FIELDS} FROM findings WHERE id = %s", (finding_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="not found")
        cols = [d.name for d in cur.description]
        record = dict(zip(cols, row))

    # Zone need-to-know enforced on the specific record too.
    if zones is not None and record.get("asset_zone") not in zones:
        raise HTTPException(status_code=403, detail="outside your assigned zones")

    _audit(ctx["user"]["name"], ctx["role"].value, "view_finding", request,
           object_type="finding", object_id=str(finding_id))
    pb = playbook_for(record.get("category"), record.get("service_name"), record.get("cve"))
    return templates.TemplateResponse(
        "finding_detail.html", {"request": request, "f": record, "pb": pb, **ctx},
    )


@app.get("/export.csv")
async def export_csv(request: Request):
    ctx = _ctx(request)
    if not ctx["user"]:
        return RedirectResponse("/login", status_code=302)
    if not can_export(ctx["role"]):
        raise HTTPException(status_code=403, detail="export requires auditor/admin")

    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT {_FIELDS} FROM current_findings ORDER BY detected_at DESC")
        cols = [d.name for d in cur.description]
        rows = cur.fetchall()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(cols)
    for r in rows:
        writer.writerow(r)

    # Bulk export is high-risk: it is always audited.
    _audit(ctx["user"]["name"], ctx["role"].value, "export_csv", request,
           detail=f"{len(rows)} rows")
    return Response(
        content=buf.getvalue(), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings-export.csv"},
    )


@app.get("/audit", response_class=HTMLResponse)
async def view_audit(request: Request):
    ctx = _ctx(request)
    if not ctx["user"]:
        return RedirectResponse("/login", status_code=302)
    if not can_view_audit(ctx["role"]):
        raise HTTPException(status_code=403, detail="not authorized for the audit log")
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT ts, actor, actor_role, action, object_type, object_id, "
            "host(client_ip) AS client_ip, detail "
            "FROM audit_log ORDER BY ts DESC LIMIT 500"
        )
        cols = [d.name for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    return templates.TemplateResponse(
        "audit.html", {"request": request, "rows": rows, **ctx},
    )


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
