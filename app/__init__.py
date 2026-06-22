"""Internal network audit dashboard application.

Two independently deployable services share this package:
  * ``app.ingest``     — write-only API that validates and persists findings.
  * ``app.dashboard``  — RBAC read UI for analysts/auditors/admins.

The write and read paths use *different* PostgreSQL roles (least privilege);
see ``app/db/schema.sql``.
"""
