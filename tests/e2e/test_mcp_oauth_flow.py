"""Black-box MCP authorization flow against a locally built auth server."""

import asyncio
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from mcp_auth_client import (
    AsyncHTTPClient,
    JWTVerifier,
    OAuthState,
    authorization_url,
    discover_authorization_server,
    discover_protected_resource,
    parse_www_authenticate,
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_ready(process: subprocess.Popen[bytes], url: str) -> None:
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError("authorization server exited before becoming ready")
        try:
            response = httpx.get(url, timeout=0.2)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.05)
    raise AssertionError(f"process did not become ready at {url}")


def _resource_process(sdk: str, root: Path, environment: dict[str, str]) -> subprocess.Popen[bytes]:
    if sdk == "python":
        command = [sys.executable, "server.py"]
        cwd = root / "examples" / "demo-mcp"
    elif sdk == "go":
        binary = os.environ.get("MCP_AUTH_GO_SERVER_BINARY")
        command = [binary] if binary else ["go", "run", "."]
        cwd = root / "examples" / "go-mcp"
    else:
        command = [
            str(root / "examples" / "typescript-mcp" / "node_modules" / ".bin" / "tsx"),
            "src/server.ts",
        ]
        cwd = root / "examples" / "typescript-mcp"
    return subprocess.Popen(
        command,
        cwd=cwd,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


@pytest.mark.e2e
@pytest.mark.parametrize("sdk", ["python", "go", "typescript"])
def test_mcp_authorization_code_pkce_and_resource_flow(sdk: str) -> None:
    resource_port = _free_port()
    resource_url = f"http://127.0.0.1:{resource_port}"
    resource = resource_url + "/mcp"
    metadata_url = resource_url + "/.well-known/oauth-protected-resource/mcp"
    auth_port = _free_port()
    auth_url = f"http://127.0.0.1:{auth_port}"
    root = Path(__file__).parents[2]
    resource_environment = {
        **os.environ,
        "MCP_AUTH_ISSUER": auth_url,
        "MCP_AUTH_JWKS_URI": auth_url + "/.well-known/jwks.json",
        "MCP_AUTH_JWKS_SSRF_SAFE": "false",
        "MCP_RESOURCE": resource,
        "MCP_PORT": str(resource_port),
        "MCP_PATH": "/mcp",
        "PUBLIC_BASE_URL": resource_url,
        "MCP_SERVER_URL": resource_url,
        "MCP_ALLOWED_HOSTS": f"127.0.0.1,127.0.0.1:{resource_port},localhost",
    }
    resource_process = _resource_process(sdk, root, resource_environment)
    binary = os.environ.get("MCP_AUTH_SERVER_BINARY")
    command = [binary] if binary else ["go", "run", "./cmd/auth-server"]
    environment = {
        **os.environ,
        "MCP_AUTH_ISSUER": auth_url,
        "MCP_AUTH_RESOURCES": resource,
        "MCP_AUTH_LISTEN_ADDR": f"127.0.0.1:{auth_port}",
        "MCP_AUTH_ALLOWED_SCOPES": "tools:read",
        "MCP_AUTH_LOCAL_DEVELOPMENT": "true",
        "MCP_AUTH_LOCAL_SUBJECT": "e2e-user",
        "MCP_AUTH_REQUIRE_HTTPS": "false",
        "MCP_AUTH_REGISTRATION_ENABLED": "true",
    }
    process = subprocess.Popen(
        command,
        cwd=root / "auth-server",
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        _wait_for_ready(resource_process, metadata_url)
        _wait_for_ready(process, auth_url + "/readyz")
        with httpx.Client(follow_redirects=False) as client:
            initialize = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "sdk-e2e", "version": "0.3.0"},
                },
            }
            request_headers = {
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            }
            challenge_response = client.post(resource, headers=request_headers, json=initialize)
            assert challenge_response.status_code == 401
            challenge = parse_www_authenticate(challenge_response.headers["WWW-Authenticate"])
            assert challenge.scheme == "Bearer"
            assert challenge.resource_metadata == metadata_url

            async def discover() -> tuple[object, object]:
                async with AsyncHTTPClient() as async_http:
                    protected = await discover_protected_resource(async_http.client, metadata_url)
                    auth = await discover_authorization_server(
                        async_http.client, protected.authorization_servers[0]
                    )
                    return protected, auth

            protected, auth = asyncio.run(discover())
            assert protected.resource == resource
            client_registration = client.post(
                auth.authorization_endpoint.rsplit("/", 1)[0] + "/register",
                json={
                    "client_name": "local-e2e-client",
                    "redirect_uris": ["http://127.0.0.1:39001/callback"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert client_registration.status_code == 201
            client_id = client_registration.json()["client_id"]

            oauth_state = OAuthState.generate()
            request_url = authorization_url(
                auth.authorization_endpoint,
                client_id,
                "http://127.0.0.1:39001/callback",
                resource,
                {"tools:read"},
                oauth_state,
            )
            callback = client.get(request_url + "&approve=true")
            assert callback.status_code == 302
            callback_query = parse_qs(urlsplit(callback.headers["Location"]).query)
            oauth_state.validate_callback(callback_query["state"][0])
            code = callback_query["code"][0]

            token_response = client.post(
                auth.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "code": code,
                    "redirect_uri": "http://127.0.0.1:39001/callback",
                    "code_verifier": oauth_state.code_verifier,
                    "resource": resource,
                },
            )
            assert token_response.status_code == 200
            access_token = token_response.json()["access_token"]

            jwks = client.get(auth.jwks_uri).json()
            verifier = JWTVerifier.from_jwks(
                jwks,
                issuer=auth.issuer,
                audience=resource,
                required_scopes={"tools:read"},
            )
            claims = asyncio.run(verifier.verify(access_token))
            assert claims.subject == "e2e-user"
            assert "tools:read" in claims.scopes

            invalid_response = client.post(
                resource,
                headers={**request_headers, "Authorization": "Bearer invalid"},
                json=initialize,
            )
            assert invalid_response.status_code == 401

            no_scope_state = OAuthState.generate()
            no_scope_url = authorization_url(
                auth.authorization_endpoint,
                client_id,
                "http://127.0.0.1:39001/callback",
                resource,
                set(),
                no_scope_state,
            )
            no_scope_callback = client.get(no_scope_url + "&approve=true")
            no_scope_code = parse_qs(urlsplit(no_scope_callback.headers["Location"]).query)["code"][
                0
            ]
            no_scope_response = client.post(
                auth.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "code": no_scope_code,
                    "redirect_uri": "http://127.0.0.1:39001/callback",
                    "code_verifier": no_scope_state.code_verifier,
                    "resource": resource,
                },
            )
            assert no_scope_response.status_code == 200
            insufficient_response = client.post(
                resource,
                headers={
                    **request_headers,
                    "Authorization": f"Bearer {no_scope_response.json()['access_token']}",
                },
                json=initialize,
            )
            # FastMCP currently maps verifier failures to 401 while the Go and
            # TypeScript adapters distinguish insufficient scope with 403.
            # Both statuses prove that the SDK refused the under-scoped token.
            assert insufficient_response.status_code in {401, 403}

            mcp_response = client.post(
                resource,
                headers={**request_headers, "Authorization": f"Bearer {access_token}"},
                json=initialize,
            )
            assert mcp_response.status_code == 200
            assert "result" in mcp_response.text
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        resource_process.terminate()
        try:
            resource_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            resource_process.kill()
            resource_process.wait(timeout=5)
