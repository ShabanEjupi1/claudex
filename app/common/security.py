"""Constant-time verification helpers for the ingest path.

The bearer token is never stored in plaintext — only its SHA-256 is configured,
and comparison is constant-time. The HMAC is computed over the *exact* request
body bytes so any tampering in transit is detected at the boundary.
"""
from __future__ import annotations

import hashlib
import hmac


def verify_bearer_token(presented: str, expected_sha256_hex: str) -> bool:
    if not presented or not expected_sha256_hex:
        return False
    digest = hashlib.sha256(presented.encode("utf-8")).hexdigest()
    return hmac.compare_digest(digest, expected_sha256_hex)


def compute_hmac(key: str, body: bytes) -> str:
    return hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()


def verify_hmac(key: str, body: bytes, signature_header: str) -> bool:
    """Validate an ``X-Signature: sha256=<hex>`` header against the body."""
    if not signature_header:
        return False
    prefix, _, hexsig = signature_header.partition("=")
    if prefix.strip().lower() != "sha256" or not hexsig:
        return False
    expected = compute_hmac(key, body)
    return hmac.compare_digest(expected, hexsig.strip())
