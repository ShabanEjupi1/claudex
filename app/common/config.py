"""Configuration loaded strictly from environment variables.

No secret has a default. Secrets are injected at runtime by the deployment
(systemd ``EnvironmentFile`` populated from Vault / ansible-vault) — never
hardcoded and never committed.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass


def _req(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"missing required environment variable: {name}")
    return val


def _ingest_token_sha256() -> str:
    """Accept either the precomputed hash (INGEST_TOKEN_SHA256) or the plaintext
    token (INGEST_TOKEN), so the API and collectors can share one value."""
    pre = os.environ.get("INGEST_TOKEN_SHA256")
    if pre:
        return pre.strip().lower()
    token = os.environ.get("INGEST_TOKEN")
    if token:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
    raise RuntimeError("set INGEST_TOKEN (plaintext) or INGEST_TOKEN_SHA256")


@dataclass(frozen=True)
class IngestConfig:
    db_url: str          # DSN for the WRITE-ONLY 'app_ingest' role
    token_sha256: str    # sha256(hex) of the expected bearer token
    hmac_key: str        # shared key for the X-Signature body HMAC
    schema_path: str     # path to ingest-finding.schema.json
    require_mtls: bool    # enforce the nginx-set mTLS header (set false for internal-only ingest)

    @classmethod
    def from_env(cls) -> "IngestConfig":
        return cls(
            db_url=_req("INGEST_DB_URL"),
            token_sha256=_ingest_token_sha256(),
            hmac_key=_req("INGEST_HMAC_KEY"),
            schema_path=os.environ.get(
                "SCHEMA_PATH", "schemas/ingest-finding.schema.json"
            ),
            # When there is no mTLS-terminating proxy in front (e.g. the Docker
            # deploy), set INGEST_REQUIRE_MTLS=false. Bearer token + HMAC still apply.
            require_mtls=os.environ.get("INGEST_REQUIRE_MTLS", "true").strip().lower()
            not in ("false", "0", "no"),
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
    admin_emails: frozenset[str]  # emails granted ADMIN regardless of group claim

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
            # Optional break-glass: comma-separated emails always treated as ADMIN.
            # Useful for single-owner deployments without IdP group provisioning.
            admin_emails=frozenset(
                e.strip().lower()
                for e in os.environ.get("ADMIN_EMAILS", "").split(",")
                if e.strip()
            ),
        )
