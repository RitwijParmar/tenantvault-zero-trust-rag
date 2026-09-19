from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from uuid import UUID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class AuthenticationError(ValueError):
    """Raised for any invalid or expired caller credential."""


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True)
class Principal:
    tenant_id: UUID
    subject: str
    scopes: frozenset[str]

    def can(self, scope: str) -> bool:
        return scope in self.scopes


class TokenAuthority:
    """Small HS256 verifier used for the self-contained demo.

    In production this interface is replaced with an OIDC/JWKS verifier. The
    important invariant is unchanged: tenant_id comes from an authenticated
    claim, never from a request body, URL, or browser-selected header.
    """

    def __init__(self, secret: str, issuer: str = "tenantvault-demo") -> None:
        self._key = secret.encode()
        self._issuer = issuer

    def mint(self, tenant_id: UUID, subject: str, scopes: set[str], ttl_seconds: int = 3600) -> str:
        header = _b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
        payload = _b64encode(
            json.dumps(
                {
                    "iss": self._issuer,
                    "aud": "tenantvault-api",
                    "sub": subject,
                    "tenant_id": str(tenant_id),
                    "scope": " ".join(sorted(scopes)),
                    "exp": int(time.time()) + ttl_seconds,
                },
                separators=(",", ":"),
            ).encode()
        )
        signature = _b64encode(hmac.new(self._key, f"{header}.{payload}".encode(), hashlib.sha256).digest())
        return f"{header}.{payload}.{signature}"

    def verify(self, token: str) -> Principal:
        try:
            header, payload, signature = token.split(".")
            expected = hmac.new(self._key, f"{header}.{payload}".encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, _b64decode(signature)):
                raise AuthenticationError("signature mismatch")
            claims = json.loads(_b64decode(payload))
            if claims.get("iss") != self._issuer or claims.get("aud") != "tenantvault-api":
                raise AuthenticationError("unexpected token issuer or audience")
            if int(claims["exp"]) <= time.time():
                raise AuthenticationError("token expired")
            return Principal(UUID(claims["tenant_id"]), str(claims["sub"]), frozenset(claims.get("scope", "").split()))
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            if isinstance(error, AuthenticationError):
                raise
            raise AuthenticationError("malformed credential") from error


class TenantCipher:
    """Envelope-style, tenant-bound AES-GCM encryption for source chunks."""

    def __init__(self, root_secret: str) -> None:
        self._root = root_secret.encode()

    def _key(self, tenant_id: UUID) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=f"tenantvault/chunk/{tenant_id}".encode()
        ).derive(self._root)

    def encrypt(self, tenant_id: UUID, plaintext: str) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        return nonce, AESGCM(self._key(tenant_id)).encrypt(nonce, plaintext.encode(), str(tenant_id).encode())

    def decrypt(self, tenant_id: UUID, nonce: bytes, ciphertext: bytes) -> str:
        return AESGCM(self._key(tenant_id)).decrypt(nonce, ciphertext, str(tenant_id).encode()).decode()


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
