"""Hermetic runtime-connector flow ending in a downstream tools/call."""

import asyncio
import json
import os
import socket
import subprocess
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp_auth_client import (
    JWTVerifier,
    OAuthState,
    build_exchange_client,
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _jwk(public_key: rsa.RSAPublicKey, key_id: str) -> dict[str, str]:
    value = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    value.update({"kid": key_id, "use": "sig", "alg": "RS256"})
    return value


class _OIDCHandler(BaseHTTPRequestHandler):
    issuer = ""
    signing_key: rsa.RSAPrivateKey
    jwks: dict[str, object]
    codes: dict[str, dict[str, str]] = {}

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/jwks":
            self._json(200, self.jwks)
            return
        if parsed.path == "/authorize":
            query = parse_qs(parsed.query)
            code = f"upstream-{len(self.codes) + 1}"
            self.codes[code] = {
                "client_id": query["client_id"][0],
                "redirect_uri": query["redirect_uri"][0],
                "nonce": query["nonce"][0],
            }
            location = (
                self.codes[code]["redirect_uri"]
                + "?"
                + urlencode({"code": code, "state": query["state"][0]})
            )
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        if urlsplit(self.path).path != "/token":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode())
        if form.get("grant_type", [""])[0] == "urn:ietf:params:oauth:grant-type:token-exchange":
            subject = form.get("subject_token", [""])[0]
            audience = form.get("audience", [""])[0]
            if not subject or not audience:
                self._json(400, {"error": "invalid_target"})
                return
            token = jwt.encode(
                {
                    "iss": self.issuer,
                    "sub": "mock-user",
                    "aud": audience,
                    "scope": form.get("scope", [""])[0],
                    "iat": int(time.time()),
                    "exp": int(time.time()) + 300,
                },
                self.signing_key,
                algorithm="RS256",
                headers={"kid": "mock-oidc-key"},
            )
            self._json(200, {"access_token": token, "token_type": "Bearer", "expires_in": 300})
            return
        code = form.get("code", [""])[0]
        record = self.codes.pop(code, None)
        if record is None or form.get("client_id", [""])[0] != record["client_id"]:
            self._json(400, {"error": "invalid_grant"})
            return
        token = jwt.encode(
            {
                "iss": self.issuer,
                "sub": "mock-user",
                "aud": record["client_id"],
                "nonce": record["nonce"],
                "iat": int(time.time()),
                "exp": int(time.time()) + 300,
            },
            self.signing_key,
            algorithm="RS256",
            headers={"kid": "mock-oidc-key"},
        )
        self._json(200, {"id_token": token, "access_token": "upstream-access"})

    def _json(self, status: int, value: object) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


class _DownstreamHandler(BaseHTTPRequestHandler):
    signing_key: rsa.RSAPublicKey
    issuer = ""

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/data":
            self.send_error(404)
            return
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            self._json(401, {"error": "missing_token"})
            return
        try:
            claims = jwt.decode(
                header.removeprefix("Bearer "),
                self.signing_key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience="https://api.example.com",
            )
        except jwt.PyJWTError:
            self._json(401, {"error": "invalid_token"})
            return
        self._json(200, {"subject": claims["sub"], "read_only": True})

    def _json(self, status: int, value: object) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


class _ResourceHandler(BaseHTTPRequestHandler):
    resource_url = ""
    issuer = ""
    auth_jwks: dict[str, object]
    token_endpoint = ""
    downstream_url = ""
    # Fixed for the lifetime of the test so its public half can be registered
    # with the auth server ahead of time, mirroring how a real resource server
    # is pre-provisioned rather than allowed to self-register a signing key.
    exchange_private_key_pem: bytes

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/.well-known/oauth-protected-resource":
            self._json(
                200,
                {
                    "resource": self.resource_url + "/mcp",
                    "authorization_servers": [self.issuer],
                    "scopes_supported": ["tools:read"],
                },
            )
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/mcp":
            self.send_error(404)
            return
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            self.send_response(401)
            self.send_header(
                "WWW-Authenticate",
                'Bearer resource_metadata="'
                f'{self.resource_url}/.well-known/oauth-protected-resource"',
            )
            self.end_headers()
            return
        verifier = JWTVerifier.from_jwks(
            self.auth_jwks,
            issuer=self.issuer,
            audience=self.resource_url + "/mcp",
            required_scopes={"tools:read"},
        )
        try:
            mcp_claims = asyncio.run(verifier.verify(authorization.removeprefix("Bearer ")))

            async def exchange() -> str:
                exchange_client = build_exchange_client(
                    self.token_endpoint,
                    "https://api.example.com",
                    "resource-server",
                    self.exchange_private_key_pem,
                    "resource-key",
                    allow_insecure=True,
                )
                try:
                    return (
                        await exchange_client.exchange(authorization.removeprefix("Bearer "))
                    ).access_token
                finally:
                    await exchange_client.aclose()

            downstream_token = asyncio.run(exchange())
            downstream = httpx.post(
                self.downstream_url,
                headers={"Authorization": f"Bearer {downstream_token}"},
                timeout=5,
            )
            downstream.raise_for_status()
            result = downstream.json()
            self._json(
                200,
                {"jsonrpc": "2.0", "result": {"subject": mcp_claims.subject, "downstream": result}},
            )
        except Exception:
            self._json(401, {"error": "invalid_token"})

    def _json(self, status: int, value: object) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


def _serve(handler: type[BaseHTTPRequestHandler]) -> tuple[ThreadingHTTPServer, Thread, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_port}"


@pytest.mark.e2e
def test_runtime_oidc_connector_and_downstream_tools_call() -> None:
    oidc_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _OIDCHandler.signing_key = oidc_key
    oidc_server, oidc_thread, oidc_url = _serve(_OIDCHandler)
    _OIDCHandler.issuer = oidc_url
    _OIDCHandler.jwks = {"keys": [_jwk(oidc_key.public_key(), "mock-oidc-key")]}

    downstream_server, downstream_thread, downstream_url = _serve(_DownstreamHandler)
    _DownstreamHandler.signing_key = oidc_key.public_key()
    _DownstreamHandler.issuer = oidc_url

    resource_exchange_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    resource_exchange_private_pem = resource_exchange_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    resource_exchange_public_pem = resource_exchange_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    auth_url = f"http://127.0.0.1:{_free_port()}"
    resource_server, resource_thread, resource_url = _serve(_ResourceHandler)
    _ResourceHandler.resource_url = resource_url
    _ResourceHandler.issuer = auth_url
    _ResourceHandler.token_endpoint = auth_url + "/token"
    _ResourceHandler.downstream_url = downstream_url + "/data"
    _ResourceHandler.exchange_private_key_pem = resource_exchange_private_pem

    root = Path(__file__).parents[2]
    binary = os.environ.get("MCP_AUTH_SERVER_BINARY")
    command = [binary] if binary else ["go", "run", "./cmd/auth-server"]
    callback_uri = auth_url + "/identity/callback"
    connector = {
        "mock": {
            "issuer": oidc_url,
            "authorization_endpoint": oidc_url + "/authorize",
            "token_endpoint": oidc_url + "/token",
            "jwks_uri": oidc_url + "/jwks",
            "client_id": "mock-auth-client",
            "client_secret_env": "",
            "scopes": ["openid"],
            "exchange_client_id": "mock-exchange-client",
            "token_endpoint_auth_method": "none",
            "allowed_upstream_callback_uris": [callback_uri],
            "downstream_token_strategy": "rfc8693",
        }
    }
    with tempfile.TemporaryDirectory() as temporary_directory:
        connector_file = Path(temporary_directory) / "connectors.json"
        connector_file.write_text(json.dumps(connector))
        resource_clients_file = Path(temporary_directory) / "resource-clients.json"
        resource_clients_file.write_text(
            json.dumps(
                [
                    {
                        "client_id": "resource-server",
                        "name": "test resource server",
                        "resource": resource_url + "/mcp",
                        "public_key_pem": resource_exchange_public_pem.decode(),
                    }
                ]
            )
        )
        environment = {
            **os.environ,
            "MCP_AUTH_ISSUER": auth_url,
            "MCP_AUTH_RESOURCES": resource_url + "/mcp",
            "MCP_AUTH_LISTEN_ADDR": f"127.0.0.1:{urlsplit(auth_url).port}",
            "MCP_AUTH_ALLOWED_SCOPES": "tools:read",
            "MCP_AUTH_LOCAL_DEVELOPMENT": "true",
            "MCP_AUTH_REQUIRE_HTTPS": "false",
            "MCP_AUTH_REGISTRATION_ENABLED": "true",
            "MCP_AUTH_CONNECTORS_FILE": str(connector_file),
            "MCP_AUTH_CONNECTOR": "mock",
            "MCP_AUTH_RESOURCE_CLIENTS_FILE": str(resource_clients_file),
        }
        process = subprocess.Popen(command, cwd=root / "auth-server", env=environment)
        try:
            for _ in range(100):
                try:
                    if httpx.get(auth_url + "/readyz", timeout=0.2).status_code == 200:
                        break
                except httpx.HTTPError:
                    time.sleep(0.05)
            else:
                raise AssertionError("OIDC authorization server did not become ready")

            with httpx.Client(follow_redirects=False) as client:
                protected = client.get(
                    resource_url + "/.well-known/oauth-protected-resource"
                ).json()
                authorization = client.get(
                    auth_url + "/.well-known/oauth-authorization-server"
                ).json()
                assert protected["authorization_servers"] == [auth_url]
                assert authorization["issuer"] == auth_url
                registration = client.post(
                    authorization["registration_endpoint"],
                    json={
                        "client_name": "oidc-e2e",
                        "redirect_uris": ["http://localhost:39001/callback"],
                        "token_endpoint_auth_method": "none",
                    },
                )
                registration.raise_for_status()
                client_id = registration.json()["client_id"]
                oauth_state = OAuthState.generate()
                query = {
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": "http://localhost:39001/callback",
                    "scope": "tools:read",
                    "resource": resource_url + "/mcp",
                    "state": oauth_state.state,
                    "nonce": oauth_state.nonce,
                    "code_challenge": oauth_state.code_challenge,
                    "code_challenge_method": "S256",
                }
                consent = client.get(auth_url + "/authorize?" + urlencode(query))
                consent_id = consent.text.split('name="consent_id" value="', 1)[1].split('"', 1)[0]
                upstream = client.post(
                    auth_url + "/authorize/consent",
                    data={"consent_id": consent_id, "decision": "approve"},
                )
                upstream = client.get(upstream.headers["Location"])
                callback = client.get(upstream.headers["Location"])
                callback_query = parse_qs(urlsplit(callback.headers["Location"]).query)
                assert callback_query["state"][0] == oauth_state.state
                code = callback_query["code"][0]
                token = client.post(
                    authorization["token_endpoint"],
                    data={
                        "grant_type": "authorization_code",
                        "client_id": client_id,
                        "code": code,
                        "redirect_uri": "http://localhost:39001/callback",
                        "code_verifier": oauth_state.code_verifier,
                        "resource": resource_url + "/mcp",
                    },
                )
                token.raise_for_status()
                access_token = token.json()["access_token"]
                auth_jwks = client.get(authorization["jwks_uri"]).json()
                _ResourceHandler.auth_jwks = auth_jwks
                response = client.post(
                    resource_url + "/mcp",
                    headers={"Authorization": f"Bearer {access_token}"},
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "read_only_data"},
                    },
                )
                response.raise_for_status()
                assert response.json()["result"] == {
                    "subject": "mock-user",
                    "downstream": {"subject": "mock-user", "read_only": True},
                }
        finally:
            process.terminate()
            process.wait(timeout=5)

    for server, thread in (
        (resource_server, resource_thread),
        (oidc_server, oidc_thread),
        (downstream_server, downstream_thread),
    ):
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
