"""Write-only ingest API (Zone A -> Zone B).

Defence in depth on every request, in order:
  1. mTLS — nginx verifies the client certificate and passes the result.
  2. Bearer token — compared as a SHA-256, constant-time.
  3. HMAC — over the exact raw body (tamper/replay detection).
  4. JSON Schema — the anti-poisoning boundary.
  5. Persist via the WRITE-ONLY 'app_ingest' role, parameterized.

There are deliberately no read routes here.
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from app.common.config import IngestConfig
from app.common.db import make_pool
from app.common.security import verify_bearer_token, verify_hmac
from app.common.validation import validate_finding

cfg = IngestConfig.from_env()
pool = make_pool(cfg.db_url)

INSERT_SQL = """
INSERT INTO findings (
    schema_version, source_collector, source_method,
    asset_hostname, asset_ip, asset_role, asset_zone,
    category, service_name, service_port, service_transport,
    cis_reference, cve, severity, status, evidence,
    detected_at, remediated_at
) VALUES (
    %(schema_version)s, %(source_collector)s, %(source_method)s,
    %(asset_hostname)s, %(asset_ip)s::inet, %(asset_role)s, %(asset_zone)s,
    %(category)s, %(service_name)s, %(service_port)s, %(service_transport)s,
    %(cis_reference)s, %(cve)s, %(severity)s, %(status)s, %(evidence)s,
    %(detected_at)s::timestamptz, %(remediated_at)s::timestamptz
);
"""


@asynccontextmanager
async def lifespan(_: FastAPI):
    pool.open()
    try:
        yield
    finally:
        pool.close()


app = FastAPI(
    title="Audit Ingest API",
    docs_url=None, redoc_url=None, openapi_url=None,  # no schema/docs exposure
    lifespan=lifespan,
)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


def _flatten(payload: dict) -> dict:
    svc = payload.get("service") or {}
    return {
        "schema_version": payload["schema_version"],
        "source_collector": payload["source"]["collector"],
        "source_method": payload["source"]["method"],
        "asset_hostname": payload["asset"].get("hostname"),
        "asset_ip": payload["asset"]["ip"],
        "asset_role": payload["asset"].get("role"),
        "asset_zone": payload["asset"].get("zone"),
        "category": payload["category"],
        "service_name": svc.get("name"),
        "service_port": svc.get("port"),
        "service_transport": svc.get("transport"),
        "cis_reference": payload.get("cis_reference"),
        "cve": payload.get("cve"),
        "severity": payload["severity"],
        "status": payload["status"],
        "evidence": payload.get("evidence"),
        "detected_at": payload["detected_at"],
        "remediated_at": payload.get("remediated_at"),
    }


@app.post("/v1/findings", status_code=201)
async def ingest_finding(
    request: Request,
    authorization: str | None = Header(default=None),
    x_signature: str | None = Header(default=None),
    x_ssl_client_verify: str | None = Header(default=None),
):
    # 1) mTLS result from nginx (enforced unless INGEST_REQUIRE_MTLS=false).
    if cfg.require_mtls and x_ssl_client_verify != "SUCCESS":
        raise HTTPException(status_code=401, detail="client certificate not verified")

    # 2) Bearer token (hash compare, constant time).
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if not verify_bearer_token(token, cfg.token_sha256):
        raise HTTPException(status_code=401, detail="invalid token")

    # 3) HMAC over the exact raw body.
    raw = await request.body()
    if not verify_hmac(cfg.hmac_key, raw, x_signature or ""):
        raise HTTPException(status_code=401, detail="invalid body signature")

    # 4) Parse + schema-validate.
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="invalid JSON")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="expected a JSON object")
    errors = validate_finding(payload, cfg.schema_path)
    if errors:
        return JSONResponse(
            status_code=422,
            content={"detail": "schema validation failed", "errors": errors},
        )

    # 5) Persist (write-only role; no RETURNING so INSERT is the only grant needed).
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(INSERT_SQL, _flatten(payload))
        conn.commit()
    return {"status": "accepted"}
