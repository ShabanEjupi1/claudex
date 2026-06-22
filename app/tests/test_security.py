"""Unit tests for the ingest verification helpers (stdlib only)."""
import hashlib

from app.common.security import compute_hmac, verify_bearer_token, verify_hmac


def test_hmac_roundtrip():
    key, body = "k3y", b'{"a":1}'
    sig = "sha256=" + compute_hmac(key, body)
    assert verify_hmac(key, body, sig)


def test_hmac_detects_tamper():
    key = "k3y"
    sig = "sha256=" + compute_hmac(key, b'{"a":1}')
    assert not verify_hmac(key, b'{"a":2}', sig)  # body changed


def test_hmac_rejects_malformed_header():
    assert not verify_hmac("k", b"x", "")
    assert not verify_hmac("k", b"x", "md5=deadbeef")


def test_bearer_token():
    token = "s3cret-token"
    digest = hashlib.sha256(token.encode()).hexdigest()
    assert verify_bearer_token(token, digest)
    assert not verify_bearer_token("wrong", digest)
    assert not verify_bearer_token("", digest)
