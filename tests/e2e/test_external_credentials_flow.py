"""Black-box credential-access assertion flow against a locally built auth server."""

import json
import os
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp_auth_client import OAuthState, PrivateKeyJWTClientAuth, authorization_url
from test_mcp_oauth_flow import _free_port, _wait_for_ready

pytestmark = pytest.mark.e2e

ASSERTION_TYPE = "urn:mcp-auth:token-type:credential-access-assertion"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
CALLBACK = "http://127.0.0.1:39001/callback"
READ_RESOURCE = "http://127.0.0.1:9/read"
WRITE_RESOURCE = "http://127.0.0.1:9/write"


@dataclass
class Gateway:
    auth: PrivateKeyJWTClientAuth
    resource: str


@dataclass
class Stack:
    url: str
    read: Gateway  # requires tools:read on READ_RESOURCE
    write: Gateway  # requires tools:write on WRITE_RESOURCE

    @property
    def token_endpoint(self) -> str:
        return self.url + "/token"


def _key_pair() -> tuple[bytes, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, public.decode()


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    tmp_path = tmp_path_factory.mktemp("external-credentials")
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    read_private, read_public = _key_pair()
    write_private, write_public = _key_pair()
    credentials = tmp_path / "external-credentials.json"
    credentials.write_text(
        json.dumps(
            [
                {
                    "id": "read-gateway",
                    "resource": READ_RESOURCE,
                    "required_scopes": ["tools:read"],
                    "resource_client": {"client_id": "read-gateway", "public_key_pem": read_public},
                    "assertion_ttl_seconds": 45,
                },
                {
                    "id": "write-gateway",
                    "resource": WRITE_RESOURCE,
                    "required_scopes": ["tools:write"],
                    "resource_client": {
                        "client_id": "write-gateway",
                        "public_key_pem": write_public,
                    },
                },
            ]
        )
    )
    binary = os.environ.get("MCP_AUTH_SERVER_BINARY")
    process = subprocess.Popen(
        [binary] if binary else ["go", "run", "./cmd/auth-server"],
        cwd=Path(__file__).parents[2] / "auth-server",
        env={
            **os.environ,
            "MCP_AUTH_ISSUER": url,
            "MCP_AUTH_RESOURCES": f"{READ_RESOURCE},{WRITE_RESOURCE}",
            "MCP_AUTH_RESOURCE_SCOPES": json.dumps(
                {READ_RESOURCE: ["tools:read"], WRITE_RESOURCE: ["tools:read", "tools:write"]}
            ),
            "MCP_AUTH_LISTEN_ADDR": f"127.0.0.1:{port}",
            "MCP_AUTH_LOCAL_DEVELOPMENT": "true",
            "MCP_AUTH_LOCAL_SUBJECT": "e2e-user",
            "MCP_AUTH_REQUIRE_HTTPS": "false",
            "MCP_AUTH_REGISTRATION_ENABLED": "true",
            "MCP_AUTH_EXTERNAL_CREDENTIALS_FILE": str(credentials),
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_ready(process, url + "/readyz")
        yield Stack(
            url,
            Gateway(PrivateKeyJWTClientAuth("read-gateway", read_private, "k1"), READ_RESOURCE),
            Gateway(PrivateKeyJWTClientAuth("write-gateway", write_private, "k2"), WRITE_RESOURCE),
        )
    finally:
        process.terminate()
        process.wait(timeout=10)


def login(stack: Stack, resource: str, scopes: set[str] | None) -> dict[str, str]:
    """Run authorize + token; scopes=None omits the scope parameter entirely."""
    with httpx.Client(follow_redirects=False) as client:
        registration = client.post(
            stack.url + "/register",
            json={
                "client_name": "e2e",
                "redirect_uris": [CALLBACK],
                "token_endpoint_auth_method": "none",
            },
        )
        client_id = registration.json()["client_id"]
        state = OAuthState.generate()
        request = authorization_url(
            stack.url + "/authorize", client_id, CALLBACK, resource, scopes or set(), state
        )
        location = client.get(request + "&approve=true").headers["Location"]
        code = parse_qs(urlsplit(location).query)["code"][0]
        response = client.post(
            stack.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "redirect_uri": CALLBACK,
                "code_verifier": state.code_verifier,
                "resource": resource,
            },
        )
        assert response.status_code == 200, response.text
        return {**response.json(), "client_id": client_id}


def exchange(
    stack: Stack,
    gateway: Gateway,
    subject_token: str,
    auth: PrivateKeyJWTClientAuth | None = None,
    **overrides: str,
) -> httpx.Response:
    form = {
        "grant_type": EXCHANGE,
        "subject_token": subject_token,
        "subject_token_type": ACCESS_TOKEN_TYPE,
        "requested_token_type": ASSERTION_TYPE,
        "audience": gateway.resource,
        **(auth or gateway.auth).form_fields(stack.token_endpoint),
    }
    form.update(overrides)
    return httpx.post(stack.token_endpoint, data=form)


def unverified(token: str) -> dict[str, object]:
    return dict(jwt.decode(token, options={"verify_signature": False}))


def test_assertion_is_issued_and_verifiable_with_jwks(stack: Stack) -> None:
    session = login(stack, READ_RESOURCE, {"tools:read"})
    subject = unverified(session["access_token"])
    assert subject["sid"]

    response = exchange(stack, stack.read, session["access_token"])
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token_type"] == "N_A"
    assert body["issued_token_type"] == ASSERTION_TYPE
    assert body["expires_in"] == 45

    assertion = body["access_token"]
    assert jwt.get_unverified_header(assertion)["typ"] == "credential-access+jwt"
    signing_key = jwt.PyJWKClient(stack.url + "/.well-known/jwks.json").get_signing_key_from_jwt(
        assertion
    )
    claims = jwt.decode(
        assertion,
        signing_key.key,
        algorithms=["RS256"],
        audience="read-gateway",
        issuer=stack.url,
    )
    assert claims["sub"] == "e2e-user"
    assert claims["resource"] == READ_RESOURCE
    assert claims["scope"] == "tools:read"
    assert claims["sid"] == subject["sid"]
    assert claims["jti"]
    assert claims["exp"] - claims["iat"] == 45


def test_login_without_scope_parameter_still_yields_assertion(stack: Stack) -> None:
    session = login(stack, READ_RESOURCE, None)
    assert session["scope"] == "tools:read"
    response = exchange(stack, stack.read, session["access_token"])
    assert response.status_code == 200, response.text
    assert unverified(response.json()["access_token"])["scope"] == "tools:read"


def test_wrong_request_shape_is_rejected(stack: Stack) -> None:
    session = login(stack, READ_RESOURCE, {"tools:read"})
    token = session["access_token"]
    assertion = exchange(stack, stack.read, token).json()["access_token"]

    # An assertion is not an access token and cannot be exchanged again.
    assert exchange(stack, stack.read, assertion).status_code == 400
    assert exchange(stack, stack.read, token, requested_token_type="x:other").status_code == 400
    assert exchange(stack, stack.read, token, subject_token_type="x:other").status_code == 400
    assert exchange(stack, stack.read, token, audience=WRITE_RESOURCE).status_code == 400
    assert exchange(stack, stack.read, "not.a.jwt").status_code == 400
    assert exchange(stack, stack.read, token[:-4] + "AAAA").status_code == 400


def test_client_authentication_is_required_and_single_use(stack: Stack) -> None:
    token = login(stack, READ_RESOURCE, {"tools:read"})["access_token"]

    form = {
        "grant_type": EXCHANGE,
        "subject_token": token,
        "requested_token_type": ASSERTION_TYPE,
        "audience": READ_RESOURCE,
        **stack.read.auth.form_fields(stack.token_endpoint),
    }
    assert httpx.post(stack.token_endpoint, data=form).status_code == 200
    assert httpx.post(stack.token_endpoint, data=form).status_code == 401  # jti replay

    unauthenticated = {k: v for k, v in form.items() if not k.startswith("client_")}
    unauthenticated["client_id"] = "read-gateway"
    assert httpx.post(stack.token_endpoint, data=unauthenticated).status_code in {400, 401}

    stranger_private, _ = _key_pair()
    forged = PrivateKeyJWTClientAuth("read-gateway", stranger_private, "k1")
    assert exchange(stack, stack.read, token, auth=forged).status_code == 401


def test_a_gateway_cannot_use_tokens_for_another_resource(stack: Stack) -> None:
    write_session = login(stack, WRITE_RESOURCE, {"tools:read", "tools:write"})
    read_session = login(stack, READ_RESOURCE, {"tools:read"})
    assert exchange(stack, stack.write, write_session["access_token"]).status_code == 200
    assert exchange(stack, stack.read, write_session["access_token"]).status_code == 400
    assert exchange(stack, stack.write, read_session["access_token"]).status_code == 400


def test_missing_required_scope_is_rejected(stack: Stack) -> None:
    read_only = login(stack, WRITE_RESOURCE, {"tools:read"})
    assert read_only["scope"] == "tools:read"
    response = exchange(stack, stack.write, read_only["access_token"])
    assert response.status_code == 403
    assert response.json()["error"] == "insufficient_scope"


def test_refresh_keeps_the_session_alive(stack: Stack) -> None:
    session = login(stack, READ_RESOURCE, {"tools:read"})
    refreshed = httpx.post(
        stack.token_endpoint,
        data={
            "grant_type": "refresh_token",
            "client_id": session["client_id"],
            "refresh_token": session["refresh_token"],
        },
    ).json()
    assert (
        unverified(refreshed["access_token"])["sid"] == unverified(session["access_token"])["sid"]
    )
    assert exchange(stack, stack.read, refreshed["access_token"]).status_code == 200


def test_refresh_token_replay_revokes_the_session(stack: Stack) -> None:
    session = login(stack, READ_RESOURCE, {"tools:read"})
    form = {
        "grant_type": "refresh_token",
        "client_id": session["client_id"],
        "refresh_token": session["refresh_token"],
    }
    refreshed = httpx.post(stack.token_endpoint, data=form)
    assert refreshed.status_code == 200
    assert exchange(stack, stack.read, refreshed.json()["access_token"]).status_code == 200

    assert httpx.post(stack.token_endpoint, data=form).status_code == 400  # replay
    for token in (session["access_token"], refreshed.json()["access_token"]):
        assert exchange(stack, stack.read, token).status_code == 400


def test_revoking_the_login_stops_assertions_for_unexpired_tokens(stack: Stack) -> None:
    session = login(stack, READ_RESOURCE, {"tools:read"})
    assert exchange(stack, stack.read, session["access_token"]).status_code == 200
    revoked = httpx.post(stack.url + "/revoke", data={"token": session["refresh_token"]})
    assert revoked.status_code == 200
    assert exchange(stack, stack.read, session["access_token"]).status_code == 400


def test_unrelated_client_cannot_request_an_assertion(stack: Stack) -> None:
    session = login(stack, READ_RESOURCE, {"tools:read"})
    response = httpx.post(
        stack.token_endpoint,
        data={
            "grant_type": EXCHANGE,
            "subject_token": session["access_token"],
            "requested_token_type": ASSERTION_TYPE,
            "audience": READ_RESOURCE,
            "client_id": session["client_id"],
        },
    )
    assert response.status_code in {400, 401}
