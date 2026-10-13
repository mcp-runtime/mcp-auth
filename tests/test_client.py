import asyncio
import json
import time
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp_auth_client import (
    ExchangedToken,
    JWTVerifier,
    OAuthState,
    RemoteAuthProvider,
    TokenExchangeError,
    TokenVerificationError,
    authorize_bearer,
    unauthorized_headers,
)
from mcp_auth_client.cache import BoundedTokenCache
from mcp_auth_client.challenge import parse_www_authenticate
from mcp_auth_client.integration import scope_policy
from mcp_auth_client.models import AuthorizationServerConfig


def key_pair() -> tuple[rsa.RSAPrivateKey, dict[str, object]]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_numbers()

    def b64(value: int) -> str:
        return jwt.utils.base64url_encode(
            value.to_bytes((value.bit_length() + 7) // 8, "big")
        ).decode()

    return private, {
        "kty": "RSA",
        "kid": "test",
        "alg": "RS256",
        "use": "sig",
        "n": b64(public.n),
        "e": b64(public.e),
    }


@pytest.mark.asyncio
async def test_jwt_signature_issuer_audience_expiry_and_scopes() -> None:
    private, jwk = key_pair()
    token = jwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "https://mcp.example.com",
            "exp": time.time() + 300,
            "scope": "tools:read",
        },
        private,
        algorithm="RS256",
        headers={"kid": "test"},
    )
    verifier = JWTVerifier.from_jwks(
        {"keys": [jwk]},
        issuer="https://auth.example.com",
        audience="https://mcp.example.com",
        required_scopes={"tools:read"},
    )
    claims = await verifier.verify(token)
    assert claims.subject == "user"
    with pytest.raises(TokenVerificationError):
        await JWTVerifier.from_jwks(
            {"keys": [jwk]}, issuer="https://wrong.example.com", audience="https://mcp.example.com"
        ).verify(token)
    with pytest.raises(TokenVerificationError):
        await JWTVerifier.from_jwks(
            {"keys": [jwk]}, issuer="https://auth.example.com", audience="https://other.example.com"
        ).verify(token)


@pytest.mark.asyncio
async def test_expiry_algorithm_and_missing_scope_rejected() -> None:
    private, jwk = key_pair()
    expired = jwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "https://mcp.example.com",
            "exp": time.time() - 120,
        },
        private,
        algorithm="RS256",
        headers={"kid": "test"},
    )
    verifier = JWTVerifier.from_jwks(
        {"keys": [jwk]},
        issuer="https://auth.example.com",
        audience="https://mcp.example.com",
        required_scopes={"tools:read"},
    )
    with pytest.raises(TokenVerificationError):
        await verifier.verify(expired)
    unsigned = jwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "https://mcp.example.com",
            "exp": time.time() + 300,
        },
        key="",
        algorithm="none",
        headers={"kid": "test"},
    )
    with pytest.raises(TokenVerificationError):
        await verifier.verify(unsigned)


def test_challenge_and_metadata_config() -> None:
    header = unauthorized_headers(
        "https://mcp.example.com/.well-known/oauth-protected-resource", {"tools:read"}
    )["WWW-Authenticate"]
    challenge = parse_www_authenticate(header)
    assert challenge.resource_metadata.endswith("oauth-protected-resource")
    config = AuthorizationServerConfig.from_metadata(
        {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
        }
    )
    assert config.issuer == "https://auth.example.com"


def test_bounded_cache_expiry_and_limit() -> None:
    cache = BoundedTokenCache(max_entries=1, expiry_margin=1)
    cache.put("a", "one", time.time() + 100)
    cache.put("b", "two", time.time() + 100)
    assert cache.get("a") is None
    assert cache.get("b") == "two"
    cache.put("expired", "no", time.time() + 0.1)
    assert cache.get("expired") is None


def test_state_nonce_and_pkce_validation() -> None:
    state = OAuthState.generate()
    assert len(state.code_challenge) > 20
    state.validate_callback(state.state, state.nonce)
    with pytest.raises(ValueError, match="state"):
        state.validate_callback("wrong", state.nonce)
    with pytest.raises(ValueError, match="nonce"):
        state.validate_callback(state.state, "wrong")
    state.validate_callback(
        state.state,
        returned_issuer="https://auth.example.com",
        expected_issuer="https://auth.example.com",
        issuer_parameter_supported=True,
    )
    with pytest.raises(ValueError, match="issuer"):
        state.validate_callback(
            state.state,
            expected_issuer="https://auth.example.com",
            issuer_parameter_supported=True,
        )


@pytest.mark.asyncio
async def test_insufficient_scope_is_forbidden() -> None:
    private, jwk = key_pair()
    token = jwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "https://mcp.example.com",
            "exp": time.time() + 300,
            "scope": "catalog:read",
        },
        private,
        algorithm="RS256",
        headers={"kid": "test"},
    )
    verifier = JWTVerifier.from_jwks(
        {"keys": [jwk]},
        issuer="https://auth.example.com",
        audience="https://mcp.example.com",
        required_scopes={"catalog:read", "sql:read"},
    )
    metadata = "https://mcp.example.com/.well-known/oauth-protected-resource"
    decision = await authorize_bearer(verifier, f"Bearer {token}", metadata)
    assert decision.status == 403
    header = decision.headers["WWW-Authenticate"]
    assert 'error="insufficient_scope"' in header
    assert 'scope="catalog:read sql:read"' in header

    wide_catalogue, gate = ["catalog:read", "sql:read"], frozenset()
    enforced, advertised = scope_policy(wide_catalogue, gate)
    assert enforced == frozenset()
    assert advertised == ["catalog:read", "sql:read"]
    open_verifier = JWTVerifier.from_jwks(
        {"keys": [jwk]},
        issuer="https://auth.example.com",
        audience="https://mcp.example.com",
        required_scopes=enforced,
    )
    allowed = await authorize_bearer(open_verifier, f"Bearer {token}", metadata)
    assert allowed.status == 200
    provider = RemoteAuthProvider(
        token_verifier=open_verifier,
        authorization_servers=["https://auth.example.com"],
        base_url="https://mcp.example.com",
        scopes_supported=advertised,
    )
    plan = provider.fastmcp_construction()
    assert plan["verifier_required_scopes"] == []
    assert plan["provider_required_scopes"] == []
    assert plan["scopes_supported"] == ["catalog:read", "sql:read"]


def test_py_typed_marker_is_packaged() -> None:
    root = Path(__file__).resolve().parents[1]
    marker = root / "auth-client/python/src/mcp_auth_client/py.typed"
    assert marker.is_file()
    for project in (root / "pyproject.toml", root / "auth-client/python/pyproject.toml"):
        text = project.read_text()
        assert "py.typed" in text
        assert 'mcp_auth_client = ["py.typed"]' in text


def test_promoted_integration_helpers_are_public() -> None:
    assert ExchangedToken("token").access_token == "token"
    assert str(TokenExchangeError("invalid_target")) == "invalid_target"


@pytest.mark.asyncio
async def test_ssrf_safe_jwks_policy_rejects_private_network_url() -> None:
    private, _ = key_pair()
    token = jwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "https://mcp.example.com",
            "exp": time.time() + 300,
        },
        private,
        algorithm="RS256",
        headers={"kid": "test"},
    )
    verifier = JWTVerifier(
        "http://10.0.0.1/jwks", "https://auth.example.com", "https://mcp.example.com"
    )
    with pytest.raises(TokenVerificationError, match="SSRF"):
        await verifier.verify(token)


@pytest.mark.asyncio
async def test_unknown_kid_does_not_refetch_jwks() -> None:
    private, jwk = key_pair()
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"keys": [jwk]})

    token = jwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "https://mcp.example.com",
            "exp": time.time() + 300,
        },
        private,
        algorithm="RS256",
        headers={"kid": "missing"},
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        verifier = JWTVerifier(
            "https://auth.example.com/jwks",
            "https://auth.example.com",
            "https://mcp.example.com",
            http_client=client,
        )
        for _ in range(5):
            with pytest.raises(TokenVerificationError):
                await verifier.verify(token)
    assert calls == 1


@pytest.mark.asyncio
async def test_jwks_load_is_single_flight() -> None:
    private, jwk = key_pair()
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.2)
        return httpx.Response(200, json={"keys": [jwk]})

    token = jwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "https://mcp.example.com",
            "exp": time.time() + 300,
        },
        private,
        algorithm="RS256",
        headers={"kid": "test"},
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        verifier = JWTVerifier(
            "https://auth.example.com/jwks",
            "https://auth.example.com",
            "https://mcp.example.com",
            http_client=client,
        )
        first, second = await asyncio.gather(verifier.verify(token), verifier.verify(token))
    assert first.subject == second.subject == "user"
    assert calls == 1


@pytest.mark.asyncio
async def test_jwks_body_over_one_mib_is_rejected() -> None:
    private, jwk = key_pair()
    body = json.dumps({"keys": [jwk], "pad": "a" * (1 << 20)}).encode()
    assert len(body) > 1 << 20
    token = jwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "https://mcp.example.com",
            "exp": time.time() + 300,
        },
        private,
        algorithm="RS256",
        headers={"kid": "test"},
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        verifier = JWTVerifier(
            "https://auth.example.com/jwks",
            "https://auth.example.com",
            "https://mcp.example.com",
            http_client=client,
        )
        with pytest.raises(TokenVerificationError, match="too large"):
            await verifier.verify(token)


@pytest.mark.asyncio
async def test_jwks_request_uses_explicit_timeout() -> None:
    private, jwk = key_pair()
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["timeout"] = request.extensions.get("timeout")
        return httpx.Response(200, json={"keys": [jwk]})

    token = jwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "https://mcp.example.com",
            "exp": time.time() + 300,
        },
        private,
        algorithm="RS256",
        headers={"kid": "test"},
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        verifier = JWTVerifier(
            "https://auth.example.com/jwks",
            "https://auth.example.com",
            "https://mcp.example.com",
            http_client=client,
            http_timeout=10,
        )
        await verifier.verify(token)
    timeout = seen["timeout"]
    assert isinstance(timeout, dict)
    assert timeout["read"] == 10


@pytest.mark.asyncio
async def test_stale_jwks_still_verifies_while_refetch_is_throttled() -> None:
    """A cached key outlives its TTL rather than failing inside the throttle window.

    jwks_min_fetch throttles refetches. When it returned None a kid already in
    the cache was reported as "signing key was not found", so every token was
    rejected for the gap between jwks_ttl and jwks_min_fetch.
    """
    private, jwk = key_pair()
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"keys": [jwk]})

    token = jwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "https://mcp.example.com",
            "exp": time.time() + 300,
        },
        private,
        algorithm="RS256",
        headers={"kid": jwk["kid"], "typ": "at+jwt"},
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        verifier = JWTVerifier(
            "https://auth.example.com/jwks",
            "https://auth.example.com",
            "https://mcp.example.com",
            http_client=client,
            jwks_ttl=0.01,
            jwks_min_fetch=30.0,
        )
        assert (await verifier.verify(token)).subject == "user"
        await asyncio.sleep(0.05)
        assert (await verifier.verify(token)).subject == "user"
    assert calls == 1


def _typed_token(private: rsa.RSAPrivateKey, typ: str | None) -> str:
    headers: dict[str, object] = {"kid": "test"}
    if typ is not None:
        headers["typ"] = typ
    return jwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": "user",
            "aud": "gateway",
            "exp": time.time() + 300,
            "scope": "tools:read",
        },
        private,
        algorithm="RS256",
        headers=headers,
    )


@pytest.mark.asyncio
async def test_verifier_token_types_and_require_type() -> None:
    private, jwk = key_pair()

    def verifier(**kwargs: object) -> JWTVerifier:
        return JWTVerifier.from_jwks(
            {"keys": [jwk]}, issuer="https://auth.example.com", audience="gateway", **kwargs
        )

    assertion = _typed_token(private, "credential-access+jwt")
    with pytest.raises(TokenVerificationError):
        await verifier().verify(assertion)  # default allowlist is JWT / at+jwt
    claims = await verifier(token_types=("credential-access+jwt",), require_type=True).verify(
        assertion
    )
    assert claims.subject == "user"
    with pytest.raises(TokenVerificationError):
        await verifier(token_types=("credential-access+jwt",)).verify(
            _typed_token(private, "at+jwt")
        )
    with pytest.raises(TokenVerificationError):
        await verifier(token_types=("credential-access+jwt",), require_type=True).verify(
            _typed_token(private, None)
        )
    assert (await verifier().verify(_typed_token(private, None))).subject == "user"
    with pytest.raises(ValueError):
        verifier(token_types=())
