"""PostgreSQL connection pool helper (psycopg 3).

Connections use TLS to the database (``sslmode=verify-full`` is recommended in
the DSN). The pool is opened during the app lifespan and closed on shutdown.
"""
from __future__ import annotations

from psycopg_pool import ConnectionPool


def make_pool(conninfo: str, *, min_size: int = 1, max_size: int = 8) -> ConnectionPool:
    # open=False: the caller opens the pool inside the app lifespan handler.
    return ConnectionPool(conninfo, min_size=min_size, max_size=max_size, open=False)
