"""Verify short-lived GitHub Actions OIDC tokens for the PulseFlow worker.

The scheduled workflow never stores a long-lived production secret.  Only the
workflow committed on ``main`` in the configured repository can call the
worker, and GitHub's rotating signing keys are verified before claims are used.
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


ISSUER = "https://token.actions.githubusercontent.com"
DISCOVERY_URL = ISSUER + "/.well-known/openid-configuration"
DEFAULT_REPOSITORY = "heitorlealsilva-crypto/pulseflow-saas"
WORKFLOW_PATH = ".github/workflows/pulseflow-worker.yml"
AUDIENCE = "pulseflow-worker"
MAX_TOKEN_BYTES = 16_384
_CACHE: dict[str, object] = {"expires": 0.0, "refresh_after": 0.0,
                             "jwks_uri": "", "keys": []}


def _decode_segment(value: str) -> bytes:
    if not value or len(value) > MAX_TOKEN_BYTES:
        raise ValueError("invalid jwt segment")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _json_segment(value: str) -> dict:
    decoded = json.loads(_decode_segment(value))
    if not isinstance(decoded, dict):
        raise ValueError("invalid jwt object")
    return decoded


def _fetch_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=5) as response:
        raw = response.read(256_001)
    if len(raw) > 256_000:
        raise ValueError("oidc response too large")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("invalid oidc response")
    return value


def _keys(now: float, force: bool = False) -> list[dict]:
    if (force and now < float(_CACHE.get("refresh_after", 0))
            and isinstance(_CACHE["keys"], list) and _CACHE["keys"]):
        return _CACHE["keys"]  # type: ignore[return-value]
    if not force and now < float(_CACHE["expires"]) and isinstance(_CACHE["keys"], list):
        return _CACHE["keys"]  # type: ignore[return-value]
    discovery = _fetch_json(DISCOVERY_URL)
    if discovery.get("issuer") != ISSUER:
        raise ValueError("unexpected oidc issuer")
    jwks_uri = discovery.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri.startswith(ISSUER + "/"):
        raise ValueError("unexpected jwks uri")
    jwks = _fetch_json(jwks_uri)
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("missing signing keys")
    # An untrusted unknown ``kid`` can request at most one refresh per minute
    # in a warm function. This prevents a public endpoint from amplifying
    # arbitrary JWTs into repeated GitHub discovery/JWKS traffic.
    _CACHE.update(expires=now + 3600, refresh_after=now + 60,
                  jwks_uri=jwks_uri, keys=keys)
    return keys


def _audience_matches(value: object) -> bool:
    return value == AUDIENCE or isinstance(value, list) and AUDIENCE in value


def verify_token(token: str, now: float | None = None, keys: list[dict] | None = None) -> bool:
    """Return True only for the dedicated workflow on the main branch."""
    try:
        if not isinstance(token, str) or not 1 <= len(token.encode()) <= MAX_TOKEN_BYTES:
            return False
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        header, claims = _json_segment(encoded_header), _json_segment(encoded_payload)
        if header.get("alg") != "RS256" or header.get("typ") not in {"JWT", None}:
            return False
        kid = header.get("kid")
        if not isinstance(kid, str) or not 1 <= len(kid) <= 256:
            return False
        repository = os.getenv("PULSEFLOW_GITHUB_REPOSITORY", DEFAULT_REPOSITORY).strip()
        expected_workflow = f"{repository}/{WORKFLOW_PATH}@refs/heads/main"
        now = time.time() if now is None else now
        exp, nbf, issued = float(claims.get("exp", 0)), float(claims.get("nbf", 0)), float(claims.get("iat", 0))
        claims_allowed = bool(
            claims.get("iss") == ISSUER
            and _audience_matches(claims.get("aud"))
            and claims.get("repository") == repository
            and claims.get("workflow_ref") == expected_workflow
            and claims.get("ref") == "refs/heads/main"
            and claims.get("ref_type") == "branch"
            and claims.get("event_name") in {"schedule", "workflow_dispatch"}
            and isinstance(claims.get("sub"), str)
            and claims["sub"].startswith(f"repo:{repository}:")
            and exp >= now - 30
            and nbf <= now + 30
            and now - 900 <= issued <= now + 30
        )
        if not claims_allowed:
            return False
        available_keys = keys if keys is not None else _keys(now)
        key = next((item for item in available_keys
                    if isinstance(item, dict) and item.get("kid") == kid
                    and item.get("kty") == "RSA" and item.get("use") in {"sig", None}), None)
        # GitHub may rotate signing keys while a warm function still has the
        # previous JWKS cached. Refresh once on an unknown kid before failing.
        if not key and keys is None:
            available_keys = _keys(now, force=True)
            key = next((item for item in available_keys
                        if isinstance(item, dict) and item.get("kid") == kid
                        and item.get("kty") == "RSA" and item.get("use") in {"sig", None}), None)
        if not key:
            return False
        modulus = int.from_bytes(_decode_segment(str(key.get("n") or "")), "big")
        exponent = int.from_bytes(_decode_segment(str(key.get("e") or "")), "big")
        public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        public_key.verify(_decode_segment(encoded_signature),
                          f"{encoded_header}.{encoded_payload}".encode(),
                          padding.PKCS1v15(), hashes.SHA256())

        return True
    except (ValueError, TypeError, KeyError, InvalidSignature, urllib.error.URLError, TimeoutError, OSError):
        return False


def authorized(headers) -> bool:
    supplied = str(headers.get("Authorization", ""))
    if not supplied.startswith("Bearer "):
        return False
    return verify_token(supplied[7:].strip())
