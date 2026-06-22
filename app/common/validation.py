"""Schema validation — the anti-poisoning boundary.

Every finding is validated against ``schemas/ingest-finding.schema.json`` before
it is allowed near the database. Scanner output is untrusted input.
"""
from __future__ import annotations

import functools
import json

from jsonschema import Draft202012Validator


@functools.lru_cache(maxsize=4)
def _validator(schema_path: str) -> Draft202012Validator:
    with open(schema_path, "r", encoding="utf-8") as fh:
        schema = json.load(fh)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate_finding(payload: dict, schema_path: str) -> list[str]:
    """Return a list of human-readable errors. Empty list == valid."""
    validator = _validator(schema_path)
    return [
        f"{'/'.join(map(str, err.path)) or '(root)'}: {err.message}"
        for err in validator.iter_errors(payload)
    ]
