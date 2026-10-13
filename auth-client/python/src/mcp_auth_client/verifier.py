import asyncio
import ipaddress
import json
import time
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlparse

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

MAX_JWKS_BYTES = 1 << 20


class TokenVerificationError(ValueError):
    """Raised for any invalid inbound MCP access token."""


class InsufficientScopeError(TokenVerificationError):
    """The token is valid, but it does not carry every required scope.

    The ``: scope`` suffix matches the Go verifier so an HTTP layer can answer
    403 ``insufficient_scope`` instead of treating the token as broken.
    """

    def __init__(self, required_scopes: frozenset[str]) -> None:
        self.required_scopes = required_scopes
        super().__init__("JWT does not contain all required scopes: scope")


@dataclass(frozen=True, slots=True)
class TokenClaims:
    subject: str
    issuer: str
    audience: str | list[str]
    scopes: frozenset[str]
    claims: dict[str, Any]


class JWTVerifier:
    def __init__(
        self,
        jwks_uri: str,
        issuer: str,
        audience: str,
        required_scopes: set[str] | frozenset[str] = frozenset(),
        algorithms: tuple[str, ...] = ("RS256",),
        http_client: httpx.AsyncClient | None = None,
        jwks_ttl: float = 300.0,
        ssrf_safe: bool = True,
        clock_skew: float = 60.0,
        http_timeout: float = 10.0,
        jwks_min_fetch: float = 30.0,
        unknown_key_ttl: float = 30.0,
        token_types: tuple[str, ...] = ("JWT", "at+jwt"),
        require_type: bool = False,
    ) -> None:
        """``token_types`` lists the accepted JOSE ``typ`` values. ``require_type`` rejects
        tokens with no ``typ``, so a verifier for a non-access token type (for example
        ``credential-access+jwt``) cannot be satisfied by an untyped JWT.
        """
        if not token_types:
            raise ValueError("at least one JWT type must be allowlisted")
        if not algorithms:
            raise ValueError("at least one JWT algorithm must be allowlisted")
        if any(algorithm not in {"RS256", "RS384", "RS512"} for algorithm in algorithms):
            raise ValueError("only RSA SHA-2 algorithms are supported by the default verifier")
        if clock_skew < 0:
            raise ValueError("clock_skew must be non-negative")
        if http_timeout <= 0:
            raise ValueError("http_timeout must be positive")
        if jwks_min_fetch < 0 or unknown_key_ttl < 0:
            raise ValueError("JWKS cache intervals must be non-negative")
        self.jwks_uri, self.issuer, self.audience = jwks_uri, issuer, audience
        self.required_scopes = frozenset(required_scopes)
        self.algorithms = algorithms
        self.token_types = token_types
        self.require_type = require_type
        self._http_client = http_client
        self._jwks_ttl = jwks_ttl
        self.ssrf_safe = ssrf_safe
        self._clock_skew = clock_skew
        self._http_timeout = http_timeout
        self._jwks_min_fetch = jwks_min_fetch
        self._unknown_key_ttl = unknown_key_ttl
        self._jwks: dict[str, Any] = {}
        self._jwks_loaded_at = 0.0
        self._last_refresh = 0.0
        self._unknown_kids: dict[str, float] = {}
        self._jwks_lock = asyncio.Lock()

    @classmethod
    def from_jwks(cls, jwks: dict[str, object], **kwargs: object) -> "JWTVerifier":
        verifier = cls(jwks_uri="in-memory://jwks", **kwargs)  # type: ignore[arg-type]
        verifier._set_jwks(jwks)
        return verifier

    async def verify(self, token: str) -> TokenClaims:
        try:
            header = jwt.get_unverified_header(token)
            algorithm = header.get("alg")
            kid = header.get("kid")
            typ = header.get("typ")
            if not isinstance(algorithm, str) or algorithm not in self.algorithms:
                raise TokenVerificationError("JWT algorithm is not allowlisted")
            # A present typ must be a string. Guarding on isinstance let a
            # number, list, or object through unchecked, because none of them
            # is one of the two allowed values.
            if typ is None and self.require_type:
                raise TokenVerificationError("JWT type is missing")
            if typ is not None and (not isinstance(typ, str) or typ not in self.token_types):
                raise TokenVerificationError("JWT type is not allowed")
            if not isinstance(kid, str):
                raise TokenVerificationError("JWT kid is missing")
            jwk = await self._ensure_key(kid)
            if jwk is None:
                raise TokenVerificationError("JWT signing key was not found")
            key = RSAAlgorithm.from_jwk(json.dumps(jwk))
            claims = jwt.decode(
                token,
                key=cast(Any, key),
                algorithms=list(self.algorithms),
                issuer=self.issuer,
                audience=self.audience,
                leeway=self._clock_skew,
                options={"require": ["exp", "iss", "sub", "aud"]},
            )
            scopes = frozenset(str(claims.get("scope", "")).split())
            if not self.required_scopes.issubset(scopes):
                raise InsufficientScopeError(self.required_scopes)
            audience = claims["aud"]
            if not isinstance(audience, (str, list)):
                raise TokenVerificationError("JWT audience has an invalid type")
            return TokenClaims(str(claims["sub"]), str(claims["iss"]), audience, scopes, claims)
        except TokenVerificationError:
            raise
        except (jwt.PyJWTError, TypeError, ValueError, KeyError) as exc:
            raise TokenVerificationError("invalid JWT") from exc

    async def _ensure_key(self, kid: str) -> dict[str, Any] | None:
        if self.jwks_uri.startswith("in-memory://"):
            if not self._jwks:
                raise TokenVerificationError("in-memory JWKS was not configured")
            return cast(dict[str, Any] | None, self._jwks.get(kid))
        now = time.time()
        key = self._jwks.get(kid)
        fresh = bool(self._jwks) and now - self._jwks_loaded_at < self._jwks_ttl
        if isinstance(key, dict) and fresh:
            return key
        if self._recent_miss(kid, now):
            return None
        async with self._jwks_lock:
            now = time.time()
            key = self._jwks.get(kid)
            fresh = bool(self._jwks) and now - self._jwks_loaded_at < self._jwks_ttl
            if isinstance(key, dict) and fresh:
                return key
            if self._last_refresh and now - self._last_refresh < self._jwks_min_fetch:
                # Throttled. A key already in the cache still verifies the
                # signature, so serve it rather than rejecting a valid token:
                # returning None here reported "signing key was not found" for
                # a kid sitting in self._jwks whenever jwks_ttl was shorter
                # than jwks_min_fetch. Only a genuinely absent kid fails.
                return key if isinstance(key, dict) else None
            await self._fetch_jwks()
            found = self._jwks.get(kid)
            if isinstance(found, dict):
                self._unknown_kids.pop(kid, None)
                return found
            self._unknown_kids[kid] = time.time()
            return None

    def _recent_miss(self, kid: str, now: float) -> bool:
        missed = self._unknown_kids.get(kid)
        if missed is None:
            return False
        return (
            now - missed < self._unknown_key_ttl and now - self._last_refresh < self._jwks_min_fetch
        )

    async def _fetch_jwks(self) -> None:
        self._validate_jwks_uri()
        owns_client = self._http_client is None
        timeout = httpx.Timeout(self._http_timeout)
        client = self._http_client or httpx.AsyncClient(timeout=timeout)
        try:
            response = await client.get(
                self.jwks_uri,
                headers={"Accept": "application/json"},
                timeout=timeout,
            )
            response.raise_for_status()
            body = await self._read_limited(response)
            self._set_jwks(json.loads(body))
        except TokenVerificationError:
            raise
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise TokenVerificationError("unable to load JWKS") from exc
        finally:
            if owns_client:
                await client.aclose()

    async def _read_limited(self, response: httpx.Response) -> bytes:
        declared = response.headers.get("Content-Length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError as exc:
                raise TokenVerificationError("unable to load JWKS") from exc
            if length > MAX_JWKS_BYTES:
                raise TokenVerificationError("JWKS response is too large")
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > MAX_JWKS_BYTES:
                raise TokenVerificationError("JWKS response is too large")
            chunks.append(chunk)
        return b"".join(chunks)

    def _validate_jwks_uri(self) -> None:
        parsed = urlparse(self.jwks_uri)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise TokenVerificationError("JWKS URI must be an absolute HTTP(S) URL")
        if not self.ssrf_safe:
            return
        if parsed.username or parsed.password:
            raise TokenVerificationError("JWKS URI must not contain credentials")
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise TokenVerificationError("SSRF-safe JWKS loading requires HTTPS")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            return
        if not address.is_loopback:
            raise TokenVerificationError("SSRF-safe JWKS loading rejects non-loopback IP addresses")

    def _set_jwks(self, data: object) -> None:
        if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
            raise TokenVerificationError("JWKS response is invalid")
        self._jwks = {
            str(item["kid"]): item
            for item in data["keys"]
            if isinstance(item, dict) and isinstance(item.get("kid"), str)
        }
        now = time.time()
        self._jwks_loaded_at = now
        self._last_refresh = now
