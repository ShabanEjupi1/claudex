"""Schema-validation tests against the shared ingest contract."""
import json

from app.common.validation import validate_finding

SCHEMA = "schemas/ingest-finding.schema.json"
EXAMPLE = "examples/finding.example.json"


def _example():
    with open(EXAMPLE, encoding="utf-8") as fh:
        return json.load(fh)


def test_example_is_valid():
    assert validate_finding(_example(), SCHEMA) == []


def test_missing_required_field_fails():
    payload = _example()
    del payload["severity"]
    assert validate_finding(payload, SCHEMA)  # non-empty -> invalid


def test_bad_enum_value_fails():
    payload = _example()
    payload["severity"] = "catastrophic"
    errors = validate_finding(payload, SCHEMA)
    assert any("severity" in e for e in errors)


def test_unexpected_field_rejected():
    payload = _example()
    payload["injected"] = "<script>alert(1)</script>"
    assert validate_finding(payload, SCHEMA)  # additionalProperties: false
