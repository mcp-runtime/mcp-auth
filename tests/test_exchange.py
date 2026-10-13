import hashlib

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp_auth_client import ExchangeError, PrivateKeyJWTClientAuth, TokenExchangeClient
from mcp_auth_client.token_exchange import ACCESS_TOKEN_TYPE, _exchange_cache_key


@pytest.mark.asyncio
async def test_token_exchange_success_and_cache() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.url.path == "/token"
        return httpx.Response(
            200,
            json={
                "access_token": "downstream-token",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "data:read",
            },
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://auth.example.com"
    ) as client:
        async with TokenExchangeClient(
            "https://auth.example.com/token", http_client=client
        ) as exchange:
            first = await exchange.exchange(
                "mcp-client-token", "https://api.example.com", {"data:read"}
            )
            second = await exchange.exchange(
                "mcp-client-token", "https://api.example.com", {"data:read"}
            )
    assert first.access_token == second.access_token
    assert first.audience == "https://api.example.com"
    assert calls == 1


def test_private_key_jwt_assertion() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    auth = PrivateKeyJWTClientAuth("client", pem, "key-1", "https://auth.example.com/token")
    assertion = auth.assertion("https://auth.example.com/token")
    claims = jwt.decode(
        assertion, key.public_key(), algorithms=["RS256"], audience="https://auth.example.com/token"
    )
    assert claims["sub"] == "client"


def test_token_endpoint_requires_https_unless_opted_out() -> None:
    with pytest.raises(ValueError, match="https"):
        TokenExchangeClient("http://127.0.0.1/token")
    TokenExchangeClient("http://127.0.0.1/token", allow_insecure=True)
    TokenExchangeClient("https://auth.example.com/token")


def test_exchange_cache_key_hashes_token_audience_and_scopes() -> None:
    key = _exchange_cache_key("subject-token", "https://api.example.com", {"b", "a"})
    assert key == hashlib.sha256(b"subject-token\0https://api.example.com\0a b").hexdigest()
    assert "subject-token" not in key


ASSERTION_TYPE = "urn:mcp-auth:token-type:credential-access-assertion"


@pytest.mark.asyncio
async def test_requested_token_type_is_sent_and_cached_separately() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        form = dict(item.split("=", 1) for item in request.content.decode().split("&"))
        requested.append(form["requested_token_type"])
        return httpx.Response(
            200, json={"access_token": "assertion", "token_type": "N_A", "expires_in": 60}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        async with TokenExchangeClient(
            "https://auth.example.com/token",
            http_client=http,
            requested_token_type=ASSERTION_TYPE,
        ) as exchange:
            token = await exchange.exchange("subject", "https://mcp.example.com/mcp")
            await exchange.exchange("subject", "https://mcp.example.com/mcp")
            await exchange.exchange("subject", "https://mcp.example.com/mcp", use_cache=False)
    assert token.token_type == "N_A"
    assert (
        requested == ["urn%3Amcp-auth%3Atoken-type%3Acredential-access-assertion"] * 2
    )  # second call hit the cache, third bypassed it


def test_cache_key_depends_on_requested_token_type() -> None:
    default = _exchange_cache_key("s", "a", frozenset({"x"}))
    assert default == _exchange_cache_key("s", "a", frozenset({"x"}), ACCESS_TOKEN_TYPE)
    assert default != _exchange_cache_key("s", "a", frozenset({"x"}), ASSERTION_TYPE)


@pytest.mark.asyncio
async def test_exchange_error_carries_only_the_status() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "insufficient_scope", "secret": "do-not-leak"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        async with TokenExchangeClient(
            "https://auth.example.com/token", http_client=http
        ) as exchange:
            with pytest.raises(ExchangeError) as raised:
                await exchange.exchange("subject", "https://mcp.example.com/mcp")
    assert raised.value.status == 403
    assert "do-not-leak" not in str(raised.value)
    assert isinstance(raised.value, httpx.HTTPStatusError)
