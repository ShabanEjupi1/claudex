-- Audit dashboard schema (PostgreSQL 13+). Apply as the database owner/admin.
--
-- Least privilege is enforced at the database layer:
--   * app_ingest    -> INSERT on findings ONLY (write-only collector path)
--   * app_dashboard -> SELECT on findings + append/read audit_log (read path)
--
-- Encryption at rest: enable full-disk/tablespace encryption (LUKS) and/or use
-- pgcrypto for column-level protection of the most sensitive fields.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS findings (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    schema_version    TEXT        NOT NULL,
    source_collector  TEXT        NOT NULL,
    source_method     TEXT        NOT NULL,
    asset_hostname    TEXT,
    asset_ip          INET        NOT NULL,
    asset_role        TEXT,
    asset_zone        TEXT,
    category          TEXT        NOT NULL,
    service_name      TEXT,
    service_port      INTEGER     CHECK (service_port BETWEEN 0 AND 65535),
    service_transport TEXT        CHECK (service_transport IN ('tcp', 'udp')),
    cis_reference     TEXT,
    cve               TEXT[],
    severity          TEXT        NOT NULL
                      CHECK (severity IN ('info','low','medium','high','critical')),
    status            TEXT        NOT NULL
                      CHECK (status IN ('open','in-progress','remediated','accepted-risk','false-positive')),
    evidence          TEXT,
    detected_at       TIMESTAMPTZ NOT NULL,
    remediated_at     TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_findings_zone   ON findings (asset_zone);
CREATE INDEX IF NOT EXISTS idx_findings_sev    ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings (status);

CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       TEXT        NOT NULL,
    actor_role  TEXT,
    action      TEXT        NOT NULL,
    object_type TEXT,
    object_id   TEXT,
    client_ip   INET,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts    ON audit_log (ts);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log (actor);

-- Login roles. Authenticate with client certificates or SCRAM; set credentials
-- out-of-band via your secrets manager, e.g.:
--   ALTER ROLE app_ingest    WITH PASSWORD :'ingest_pw';
--   ALTER ROLE app_dashboard WITH PASSWORD :'dashboard_pw';
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_ingest') THEN
        CREATE ROLE app_ingest LOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_dashboard') THEN
        CREATE ROLE app_dashboard LOGIN;
    END IF;
END$$;

-- WRITE-ONLY ingest: INSERT findings, nothing else. No SELECT, no UPDATE/DELETE.
GRANT INSERT ON findings TO app_ingest;

-- Dashboard: read findings; append + read its own audit trail.
GRANT SELECT          ON findings  TO app_dashboard;
GRANT SELECT, INSERT  ON audit_log TO app_dashboard;

-- Optional defence in depth: enforce zone need-to-know inside the DB with RLS.
-- ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY zone_scope ON findings FOR SELECT TO app_dashboard
--   USING (asset_zone = ANY (current_setting('app.zones', true)::text[]));
