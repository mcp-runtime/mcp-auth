"""Hermetic two-process Codex OAuth cancellation reproduction (#501).

No model turns, real MCP servers, user credentials, or existing Codex processes
are used. Run directly with --codex /path/to/codex. Output contains only counts,
version, feature selection, and bounded failure stages. The local OAuth fixture
retains strict refresh-family replay revocation.
"""

import argparse
import base64
import hashlib
import json
import os
import queue
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class OAuthFixture:
    def __init__(self):
        self.lock = threading.Lock()
        self.codes = {}
        self.refresh = {}
        self.access = {}
        self.rotations = 0
        self.replays = 0
        self.revoked = False
        self.deletes = 0
        self.base = ""
        self.ttl = 70

    def issue(self):
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.access[access] = time.monotonic() + self.ttl
        self.refresh[refresh] = False
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "Bearer",
            "expires_in": self.ttl,
            "scope": "tools:read offline_access",
        }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Never print request paths: authorization codes are credentials.

    @property
    def fixture(self):
        return self.server.fixture

    def reply(self, status, body=None, headers=None):
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        raw = self.headers.get("Authorization", "").removeprefix("Bearer ")
        with self.fixture.lock:
            valid = self.fixture.access.get(raw, 0) > time.monotonic()
        if not valid:
            self.reply(
                401,
                {"error": "invalid_token"},
                {
                    "WWW-Authenticate": (
                        f'Bearer resource_metadata="{self.fixture.base}'
                        '/.well-known/oauth-protected-resource/mcp", error="invalid_token"'
                    )
                },
            )
        return valid

    def do_GET(self):  # noqa: N802
        path = urllib.parse.urlsplit(self.path)
        f = self.fixture
        if path.path.startswith("/.well-known/oauth-protected-resource"):
            self.reply(
                200,
                {
                    "resource": f.base + "/mcp",
                    "authorization_servers": [f.base],
                    "scopes_supported": ["tools:read", "offline_access"],
                },
            )
        elif path.path in {
            "/.well-known/oauth-authorization-server",
            "/.well-known/openid-configuration",
        }:
            self.reply(
                200,
                {
                    "issuer": f.base,
                    "authorization_endpoint": f.base + "/authorize",
                    "token_endpoint": f.base + "/token",
                    "registration_endpoint": f.base + "/register",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "token_endpoint_auth_methods_supported": ["none"],
                    "code_challenge_methods_supported": ["S256"],
                    "authorization_response_iss_parameter_supported": True,
                    "scopes_supported": ["tools:read", "offline_access"],
                },
            )
        elif path.path == "/authorize":
            query = urllib.parse.parse_qs(path.query)
            redirect = urllib.parse.urlsplit(query.get("redirect_uri", [""])[0])
            if (
                redirect.hostname not in {"127.0.0.1", "localhost"}
                or redirect.scheme != "http"
                or query.get("code_challenge_method") != ["S256"]
            ):
                self.reply(400, {"error": "invalid_request"})
                return
            code = secrets.token_urlsafe(32)
            with f.lock:
                f.codes[code] = query
            location = (
                urllib.parse.urlunsplit(redirect)
                + "?"
                + urllib.parse.urlencode(
                    {"code": code, "state": query.get("state", [""])[0], "iss": f.base}
                )
            )
            self.reply(302, headers={"Location": location})
        elif path.path == "/mcp" and self.authorized():
            self.reply(405, headers={"Allow": "POST, DELETE"})
        elif path.path != "/mcp":
            self.reply(404)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        if length > 65536:
            self.reply(413)
            return
        data = self.rfile.read(length)
        path = urllib.parse.urlsplit(self.path).path
        f = self.fixture
        if path == "/register":
            body = json.loads(data)
            body.update({"client_id": "fixture-client", "token_endpoint_auth_method": "none"})
            self.reply(201, body)
        elif path == "/token":
            form = urllib.parse.parse_qs(data.decode())
            with f.lock:
                if form.get("grant_type") == ["authorization_code"]:
                    auth = f.codes.pop(form.get("code", [""])[0], None)
                    challenge = (
                        base64.urlsafe_b64encode(
                            hashlib.sha256(form.get("code_verifier", [""])[0].encode()).digest()
                        )
                        .decode()
                        .rstrip("=")
                    )
                    if (
                        auth is None
                        or auth.get("code_challenge") != [challenge]
                        or auth.get("redirect_uri") != form.get("redirect_uri")
                        or form.get("client_id") != ["fixture-client"]
                    ):
                        self.reply(400, {"error": "invalid_grant"})
                        return
                elif form.get("grant_type") == ["refresh_token"]:
                    raw = form.get("refresh_token", [""])[0]
                    if (
                        raw not in f.refresh
                        or f.revoked
                        or form.get("client_id") != ["fixture-client"]
                    ):
                        self.reply(400, {"error": "invalid_grant"})
                        return
                    if f.refresh[raw]:
                        f.replays += 1
                        f.revoked = True
                        self.reply(400, {"error": "invalid_grant"})
                        return
                    f.refresh[raw] = True
                    f.rotations += 1
                else:
                    self.reply(400, {"error": "unsupported_grant_type"})
                    return
                self.reply(200, f.issue())
        elif path == "/mcp" and self.authorized():
            rpc = json.loads(data)
            method = rpc.get("method")
            if "id" not in rpc:
                self.reply(202)
                return
            result = {}
            headers = {}
            if method == "initialize":
                result = {
                    "protocolVersion": rpc["params"]["protocolVersion"],
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "refresh-fixture", "version": "1"},
                }
                headers["Mcp-Session-Id"] = secrets.token_hex(16)
            elif method == "tools/list":
                result = {
                    "tools": [
                        {
                            "name": "fixture_recent",
                            "description": "Read a fixed local fixture",
                            "inputSchema": {"type": "object", "properties": {}},
                            "annotations": {"readOnlyHint": True},
                        }
                    ]
                }
            elif method == "tools/call":
                if rpc["params"]["name"] != "fixture_recent":
                    self.reply(400)
                    return
                result = {"content": [{"type": "text", "text": "fixture-ok"}]}
            self.reply(200, {"jsonrpc": "2.0", "id": rpc["id"], "result": result}, headers)
        elif path != "/mcp":
            self.reply(404)

    def do_DELETE(self):  # noqa: N802
        with self.fixture.lock:
            self.fixture.deletes += 1
        if self.authorized():
            self.reply(200)


class Client:
    def __init__(self, binary, home, coordinated):
        env = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT"}
        }
        env.update(
            {
                "CODEX_HOME": str(home),
                "HOME": str(home),
                "OPENAI_API_KEY": "local-fixture-placeholder",
            }
        )
        self.process = subprocess.Popen(
            [
                binary,
                "app-server",
                "--listen",
                "stdio://",
                "-c",
                f"features.mcp_oauth_refresh_coordination={str(coordinated).lower()}",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            env=env,
            cwd=home,
        )
        self.messages = queue.Queue()
        self.sequence = 0
        threading.Thread(target=self.read, daemon=True).start()
        try:
            self.call(
                "initialize",
                {
                    "clientInfo": {"name": "oauth-cancellation-fixture", "version": "1"},
                    "capabilities": {"experimentalApi": True},
                },
            )
            self.send({"method": "initialized"})
            features = self.call("experimentalFeature/list", {"limit": 1000})["data"]
            feature = next(
                (f for f in features if f["name"] == "mcp_oauth_refresh_coordination"), None
            )
            if feature is None or feature["enabled"] != coordinated:
                self.close()
                raise RuntimeError("coordination_setting_unavailable")
        except (RuntimeError, queue.Empty, OSError, ValueError, KeyError):
            self.close()
            raise

    def read(self):
        for line in self.process.stdout:
            try:
                self.messages.put(json.loads(line))
            except json.JSONDecodeError:
                pass
        self.messages.put(None)

    def send(self, value):
        self.process.stdin.write(json.dumps(value) + "\n")
        self.process.stdin.flush()

    def call(self, method, params, timeout=40):
        self.sequence += 1
        request_id = self.sequence
        self.send({"id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            response = self.messages.get(timeout=max(0.01, deadline - time.monotonic()))
            if response is None:
                raise RuntimeError("app_server_exited")
            if response.get("id") != request_id:
                continue
            if "error" in response:
                raise RuntimeError("rpc_rejected")  # Raw errors can contain OAuth secrets.
            return response["result"]
        raise RuntimeError("rpc_timeout")

    def start_thread(self, home):
        return self.call(
            "thread/start",
            {
                "cwd": str(home),
                "ephemeral": True,
                "approvalPolicy": "never",
                "sandbox": "read-only",
            },
        )["thread"]["id"]

    def invoke(self, thread):
        result = self.call(
            "mcpServer/tool/call",
            {
                "threadId": thread,
                "server": "refresh_fixture",
                "tool": "fixture_recent",
                "arguments": {},
            },
        )
        if "fixture-ok" not in json.dumps(result):
            raise RuntimeError("fixture_read_failed")

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()


def run(binary, coordinated, cycles, access_ttl):
    fixture = OAuthFixture()
    fixture.ttl = access_ttl
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.fixture = fixture
    fixture.base = f"http://127.0.0.1:{server.server_port}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    clients = []
    report = {"coordinated": coordinated, "cycles_completed": 0, "ok": False, "stage": "initialize"}
    directory = tempfile.TemporaryDirectory(prefix="codex-refresh-fixture-")
    try:
        home = Path(directory.name)
        home.joinpath("config.toml").write_text(
            'mcp_oauth_credentials_store = "file"\n[mcp_servers.refresh_fixture]\n'
            f'url = "{fixture.base}/mcp"\nstartup_timeout_sec = 15\n'
            "[features]\n"
            f"mcp_oauth_refresh_coordination = {str(coordinated).lower()}\n"
        )
        a = Client(binary, home, coordinated)
        clients.append(a)
        report["stage"] = "login"
        login = a.call("mcpServer/oauth/login", {"name": "refresh_fixture", "timeoutSecs": 30})
        # Authorization URL and callback remain private to this test process.
        with urllib.request.urlopen(login["authorizationUrl"], timeout=10) as response:
            response.read(65536)
        time.sleep(0.5)
        a.call("config/mcpServer/reload", None)
        ta = a.start_thread(home)
        a.invoke(ta)
        for cycle in range(cycles):
            report["stage"] = "peer_connect"
            b = Client(binary, home, coordinated)
            clients.append(b)
            tb = b.start_thread(home)
            b.invoke(tb)
            time.sleep(fixture.ttl + 1)
            report["stage"] = "rotation"
            a.invoke(ta)
            report["stage"] = "peer_cancellation"
            b.call("thread/unsubscribe", {"threadId": tb})
            b.close()
            clients.remove(b)
            report["peer_processes_closed"] = cycle + 1
            report["stage"] = "read_after_cancellation"
            a.invoke(ta)
            report["cycles_completed"] = cycle + 1
        report["stage"] = "complete"
    except (RuntimeError, queue.Empty, OSError, ValueError, KeyError):
        pass
    finally:
        for client in clients:
            client.close()
        server.shutdown()
        server.server_close()
        directory.cleanup()
        report["ok"] = (
            report["stage"] == "complete"
            and fixture.rotations >= cycles
            and fixture.replays == 0
            and not fixture.revoked
            and report.get("peer_processes_closed", 0) == cycles
        )
        report.update(
            {
                "rotations": fixture.rotations,
                "replays": fixture.replays,
                "family_revoked": fixture.revoked,
                "transport_deletes": fixture.deletes,
            }
        )
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", required=True)
    parser.add_argument("--access-ttl", type=int, default=70, choices=range(2, 901))
    parser.add_argument("--cycles", type=int, default=3, choices=range(1, 11))
    parser.add_argument(
        "--legacy",
        action="store_true",
        help="Control run with coordination disabled; may reproduce revocation",
    )
    args = parser.parse_args()
    version = subprocess.check_output([args.codex, "--version"], text=True).strip()
    report = run(args.codex, not args.legacy, args.cycles, args.access_ttl)
    report["access_ttl_seconds"] = args.access_ttl
    report["version"] = version
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
