# Local development

Requirements: Go 1.26+ for the authorization server, Python 3.12+, and Node.js 22+. The Go client module declares `go 1.18` so older toolchains can import it; CI still tests that module on Go 1.26 and 1.27. Python 3.11 is not supported: 3.12 is the oldest interpreter this repository type-checks, even though CPython still supports 3.11. CI tests Python 3.12, 3.13, and 3.14, and Node 22, 24, and 26 for the TypeScript SDK. End-to-end jobs stay on one version of each language (Go 1.26, Python 3.12, Node 24).

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev,fastmcp]'
npm ci --prefix auth-client/typescript
npm ci --prefix examples/typescript-mcp
go test ./auth-server/... ./auth-client/go/...
pytest
```

Run the authorization server in local mode. It generates an ephemeral RSA key when no key file is configured; do not use that mode for production.

```bash
MCP_AUTH_LOCAL_DEVELOPMENT=true \
MCP_AUTH_REQUIRE_HTTPS=false \
MCP_AUTH_REGISTRATION_ENABLED=true \
go run ./auth-server/cmd/auth-server
```

The default issuer is `http://localhost:8080`, the resource audience is `http://localhost:8081/mcp`, and metadata is available at `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, and `/.well-known/jwks.json`.

## Development commands

```bash
ruff check .
ruff format --check .
mypy auth-client/python/src
pytest -q
npm test --prefix auth-client/typescript
npm run typecheck --prefix examples/typescript-mcp
go test ./auth-server/... ./auth-client/go/...
go vet ./auth-server/... ./auth-client/go/...
uv run pip-audit --skip-editable
python -m build
docker compose -f deploy/docker-compose.e2e.yml up --build --abort-on-container-exit --exit-code-from e2e-client
docker compose -f deploy/docker-compose.e2e.yml down --volumes --remove-orphans
```

CI runs the local authorization flow against real Python, Go, and TypeScript
resource servers. It also runs Compose MCP OAuth compatibility with Keycloak
and the in-tree Python demo resource server, Go vulnerability analysis, Python
and npm dependency auditing, a Trivy HIGH/CRITICAL scan of the authorization
server image, CodeQL, and the public-repository secret/artifact audit.

A published GitHub Release with a `vX.Y.Z` tag runs
`.github/workflows/docker-release.yml`. It builds and pushes the authorization
server image for Linux amd64 and arm64 to
`princekrroshan01/mcp-auth-server:<version>` and `:<tag>` (and `latest` for stable
releases). It also uploads server archives for Linux, macOS, and Windows on amd64
and arm64, a Python wheel and source distribution, a TypeScript SDK tarball,
and `SHA256SUMS`. SDK packages retain the versions declared in their manifests.
To verify downloaded packages, run `sha256sum --check SHA256SUMS` in the directory
containing all release assets. GitHub also provides source archives automatically.

`.github/workflows/dockerhub-readme.yml` syncs the Docker Hub overview on releases,
README/image changes on `main`, or manual dispatch. Relative links become public
URLs pinned to the triggering commit. Both workflows use repository secrets
`DOCKER_USERNAME` and `DOCKER_PASSWORD`; the latter is a Docker Hub access token
with read/write/delete scope, as required by the README update action.

The README embeds `docs/images/auth-flow.png` so its diagram also renders on
Docker Hub. Edit `docs/images/auth-flow.mmd`, then regenerate and commit the PNG:

```bash
npm exec --yes --package=@mermaid-js/mermaid-cli@11.12.0 -- \
  mmdc -i docs/images/auth-flow.mmd -o docs/images/auth-flow.png -w 1800 -s 2 -b white
```

SDK verifier parity cases live in `sdk-conformance/cases.json`, next to `jwks.json` and `key.json`. Each language test signs the case claims with the shared private JWK and asserts the `expect` verdict. To add a case, append an object with an `id`, a `description`, and `expect` of `accept` or `reject`. Override `header`, `claims`, `exp_offset_seconds`, `nbf_offset_seconds`, `clock_skew_seconds`, or `required_scopes` only for the fields that differ from `defaults`. Use `kind: "oversized_jwks"` for the 1 MiB body cap. Do not commit a PEM file or a pre-signed JWT; the public-repository audit rejects both. Run `uv run pytest -q`, `cd auth-client/go && GOWORK=off go test ./...`, and `npm test --prefix auth-client/typescript`.

The compatibility checks cover the shared authorization flow used by the
2025-06-18 and 2026-07-28 MCP authorization specifications. The server emits
the newer authorization-response `iss` parameter by default; setting
`MCP_AUTH_AUTHORIZATION_RESPONSE_ISS=false` preserves the earlier response
shape for deployments that need it.
