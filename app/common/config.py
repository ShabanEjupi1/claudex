"""Configuration loaded strictly from environment variables.

No secret has a default. Secrets are injected at runtime by the deployment
(systemd ``EnvironmentFile`` populated from Vault / ansible-vault) — never
hardcoded and never committed.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _req(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"missing required environment variable: {name}")
    return val


@dataclass(frozen=True)
class IngestConfig:
    db_url: str          # DSN for the WRITE-ONLY 'app_ingest' role
    token_sha256: str    # sha256(hex) of the expected bearer token
    hmac_key: str        # shared key for the X-Signature body HMAC
    schema_path: str     # path to ingest-finding.schema.json

    @classmethod
    def from_env(cls) -> "IngestConfig":
        return cls(
            db_url=_req("INGEST_DB_URL"),
            token_sha256=_req("INGEST_TOKEN_SHA256").strip().lower(),
            hmac_key=_req("INGEST_HMAC_KEY"),
            schema_path=os.environ.get(
                "SCHEMA_PATH", "schemas/ingest-finding.schema.json"
            ),
        )


@dataclass(frozen=True)
class DashboardConfig:
    db_url: str             # DSN for the READ-mostly 'app_dashboard' role
    session_secret: str
    oidc_issuer: str
    oidc_client_id: str
    oidc_client_secret: str
    oidc_redirect_url: str
    role_claim: str
    zones_claim: str

    @classmethod
    def from_env(cls) -> "DashboardConfig":
        return cls(
            db_url=_req("DASHBOARD_DB_URL"),
            session_secret=_req("SESSION_SECRET"),
            oidc_issuer=_req("OIDC_ISSUER"),
            oidc_client_id=_req("OIDC_CLIENT_ID"),
            oidc_client_secret=_req("OIDC_CLIENT_SECRET"),
            oidc_redirect_url=_req("OIDC_REDIRECT_URL"),
            role_claim=os.environ.get("OIDC_ROLE_CLAIM", "groups"),
            zones_claim=os.environ.get("OIDC_ZONES_CLAIM", "zones"),
        )
