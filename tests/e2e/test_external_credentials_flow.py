"""Black-box credential-access assertion flow against a locally built auth server."""

import json
import os
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp_auth_client import OAuthState, PrivateKeyJWTClientAuth, authorization_url
from test_mcp_oauth_flow import _free_port, _wait_for_ready

ASSERTION_TYPE = "urn:mcp-auth:token-type:credential-access-assertion"
EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
CALLBACK = "http://127.0.0.1:39001/callback"


@pytest.mark.e2e
def test_credential_access_assertion_lifecycle(tmp_path: Path) -> None:
    auth_port = _free_port()
    auth_url = f"http://127.0.0.1:{auth_port}"
    resource = "http://127.0.0.1:9/mcp"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    credentials = tmp_path / "external-credentials.json"
    credentials.write_text(
        json.dumps(
            [
                {
                    "id": "vault-gateway",
                    "resource": resource,
                    "required_scopes": ["tools:read"],
                    "resource_client": {
                        "client_id": "vault-gateway",
                        "public_key_pem": public_pem.decode(),
                    },
                    "assertion_ttl_seconds": 45,
                }
            ]
        )
    )
    binary = os.environ.get("MCP_AUTH_SERVER_BINARY")
    process = subprocess.Popen(
        [binary] if binary else ["go", "run", "./cmd/auth-server"],
        cwd=Path(__file__).parents[2] / "auth-server",
        env={
            **os.environ,
            "MCP_AUTH_ISSUER": auth_url,
            "MCP_AUTH_RESOURCES": resource,
            "MCP_AUTH_LISTEN_ADDR": f"127.0.0.1:{auth_port}",
            "MCP_AUTH_ALLOWED_SCOPES": "tools:read",
            "MCP_AUTH_LOCAL_DEVELOPMENT": "true",
            "MCP_AUTH_LOCAL_SUBJECT": "e2e-user",
            "MCP_AUTH_REQUIRE_HTTPS": "false",
            "MCP_AUTH_REGISTRATION_ENABLED": "true",
            "MCP_AUTH_EXTERNAL_CREDENTIALS_FILE": str(credentials),
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    gateway = PrivateKeyJWTClientAuth("vault-gateway", private_pem, "gateway-key")
    token_endpoint = auth_url + "/token"

    def exchange(client: httpx.Client, subject_token: str, **overrides: str) -> httpx.Response:
        form = {
            "grant_type": EXCHANGE,
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": ASSERTION_TYPE,
            "audience": resource,
            **gateway.form_fields(token_endpoint),
        }
        form.update(overrides)
        return client.post(token_endpoint, data=form)

    def login(client: httpx.Client) -> dict[str, str]:
        registration = client.post(
            auth_url + "/register",
            json={
                "client_name": "e2e",
                "redirect_uris": [CALLBACK],
                "token_endpoint_auth_method": "none",
            },
        )
        client_id = registration.json()["client_id"]
        state = OAuthState.generate()
        url = authorization_url(
            auth_url + "/authorize", client_id, CALLBACK, resource, {"tools:read"}, state
        )
        location = client.get(url + "&approve=true").headers["Location"]
        code = parse_qs(urlsplit(location).query)["code"][0]
        response = client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "redirect_uri": CALLBACK,
                "code_verifier": state.code_verifier,
                "resource": resource,
            },
        )
        assert response.status_code == 200
        return {**response.json(), "client_id": client_id}

    try:
        _wait_for_ready(process, auth_url + "/readyz")
        with httpx.Client(follow_redirects=False) as client:
            session = login(client)
            access_token = session["access_token"]
            assert jwt.decode(access_token, options={"verify_signature": False})["sid"]

            response = exchange(client, access_token)
            assert response.status_code == 200, response.text
            body = response.json()
            assert body["token_type"] == "N_A"
            assert body["issued_token_type"] == ASSERTION_TYPE
            assert body["expires_in"] == 45

            # The assertion verifies against the published JWKS and is bound to the gateway.
            assertion = body["access_token"]
            assert jwt.get_unverified_header(assertion)["typ"] == "credential-access+jwt"
            signing_key = jwt.PyJWKClient(
                auth_url + "/.well-known/jwks.json"
            ).get_signing_key_from_jwt(assertion)
            claims = jwt.decode(
                assertion,
                signing_key.key,
                algorithms=["RS256"],
                audience="vault-gateway",
                issuer=auth_url,
            )
            subject = jwt.decode(access_token, options={"verify_signature": False})
            assert claims["sub"] == "e2e-user"
            assert claims["resource"] == resource
            assert claims["scope"] == "tools:read"
            assert claims["sid"] == subject["sid"]
            assert claims["exp"] - claims["iat"] == 45

            # An assertion is not an access token, and a client cannot ask for the wrong shape.
            assert exchange(client, assertion).status_code == 400
            assert exchange(client, access_token, requested_token_type="x:other").status_code == 400
            assert (
                exchange(client, access_token, audience="http://127.0.0.1:9/other").status_code
                == 400
            )
            assert exchange(client, "not.a.jwt").status_code == 400

            # Replaying a client assertion is refused.
            replay_form = {
                "grant_type": EXCHANGE,
                "subject_token": access_token,
                "requested_token_type": ASSERTION_TYPE,
                "audience": resource,
                **gateway.form_fields(token_endpoint),
            }
            assert client.post(token_endpoint, data=replay_form).status_code == 200
            assert client.post(token_endpoint, data=replay_form).status_code == 401

            # An unauthenticated caller and an unrelated client are refused.
            no_auth = {
                "grant_type": EXCHANGE,
                "subject_token": access_token,
                "requested_token_type": ASSERTION_TYPE,
                "audience": resource,
                "client_id": session["client_id"],
            }
            assert client.post(token_endpoint, data=no_auth).status_code in {400, 401}

            # Revoking the login session stops assertions even for an unexpired access token.
            revoked = client.post(auth_url + "/revoke", data={"token": session["refresh_token"]})
            assert revoked.status_code == 200
            assert exchange(client, access_token).status_code == 400
    finally:
        process.terminate()
        process.wait(timeout=10)
