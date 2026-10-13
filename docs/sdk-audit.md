# Official MCP SDK audit for resource-server auth

Status: audit only (issue #18). **Nothing was removed, slimmed, or migrated.**
No replacement has yet passed equivalent tests against
`sdk-conformance/cases.json`, and the issue forbids removing verification or
challenge behavior before that happens.

## Methodology

- Read `auth-client/{python,typescript,go}`, `docs/auth-client.md`,
  `sdk-conformance/`, and `examples/{demo-mcp,go-mcp,typescript-mcp}`.
- Downloaded each official package/module into an isolated scratch directory
  and read its source statically. No package code was executed or installed.
- Cross-checked version metadata against PyPI, the npm registry, and
  proxy.golang.org on 2026-10-13.
- Anything not found in the downloaded source is marked **unverified** or
  **missing (not found in source)**. No runnable per-SDK adapter examples and
  no end-to-end run against a deployed MCP Auth server were produced in this
  pass; both are follow-ups (see the end).

## Versions verified

| Language | Official SDK | Version | Runtime / notable deps |
|---|---|---|---|
| Python | [`mcp`](https://pypi.org/project/mcp/) ([repo](https://github.com/modelcontextprotocol/python-sdk)) | 2.3.0 (wheel read) | Python >=3.10; starlette, pydantic, `pyjwt[crypto]`, httpx2 |
| TypeScript | [`@modelcontextprotocol/sdk`](https://www.npmjs.com/package/@modelcontextprotocol/sdk) ([repo](https://github.com/modelcontextprotocol/typescript-sdk)) | 1.32.1 (tarball read) | Node >=18; express 5, hono, `jose`, zod |
| Go | [`github.com/modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk) | v1.8.0 (2026-09-04) | go 1.25.0; `golang-jwt/jwt/v5`, `x/oauth2` |

Custom SDKs for reference: Python `mcp-auth-client` 0.3.0 (>=3.12, httpx +
PyJWT), TypeScript `@mcp-auth/client` (Node >=22, no deps), Go `mcpauth`
(`go 1.18`, stdlib only). Python 2.x is a major line; the v1 to v2 break
should be re-checked before pinning (migration guide not reviewed here).
`@modelcontextprotocol/sdk` 1.x is the version that was latest at audit time;
whether a 2.x line is planned for TypeScript is unverified.

## What the custom SDKs provide

- RS256-only JWKS verification with bounded refresh, unknown-`kid` refetch
  limit, 1 MiB JWKS cap, 10 s fetch timeout, SSRF URL policy (Py/TS).
- Claim checks: `iss`, `aud` (string or array), `exp`, `nbf`, `sub`, `typ`
  (absent, `JWT`, `at+jwt`), configurable clock skew (default 60 s).
- Scope policy: all `required_scopes` must be present; per-tool checks are the
  handler's job using verified scopes.
- RFC 9728 document generated from the verifier
  (`protected_resource_metadata`, `ProtectedResourceMetadataHandler`).
- Challenges: 401 `invalid_token` and 403 `insufficient_scope` with `scope` and
  `resource_metadata` parameters (`unauthorized_headers_for_error`,
  `bearerChallenge`, Go `RequireToken`).
- Transport glue: FastMCP adapter (Py), `authenticateRequest` (TS),
  `RequireToken` plus `TokenClaimsFromContext` (Go).
- Discovery, RFC 8693 `TokenExchangeClient` with `private_key_jwt`, cache keyed
  by hash of subject token, audience, and scopes.

## Compatibility matrix

Legend: **S** supported, **A** needs a thin adapter, **M** missing.
Paths are inside the named package version.

### 1. Verification (RS256/JWKS, rotation/caching, iss, aud, exp, sub, scopes)

| | Verdict | Evidence |
|---|---|---|
| Python | **M** for JWKS/iss/sub; **A** for aud/exp/scopes | The SDK defines only a `TokenVerifier` protocol (`mcp/server/auth/provider.py`, `verify_token(token) -> AccessToken \| None`) and leaves signature, issuer, and audience checks to the verifier. No JWKS code exists in `mcp/server/auth`. `BearerAuthBackend` (`middleware/bearer_auth.py`) enforces `exp` and, with `validate_token_resource`, compares `AccessToken.resource` to the server URL. Scopes are enforced by `RequireAuthMiddleware`. Must supply JWKS verifier (PyJWT `PyJWKClient` is a possible base; caching/rotation behavior unverified). |
| TypeScript | **M** for JWKS/iss/sub; **A** for aud/exp/scopes | `OAuthTokenVerifier` returns `AuthInfo` (`dist/esm/server/auth/types.d.ts`); `requireBearerAuth` (`server/auth/middleware/bearerAuth.js`) enforces scopes, `expiresAt` (no skew), and optional `expectedResource`. `jose` is a dependency but only used in client assertions (`client/auth-extensions.js`), not for server verification. `AuthInfo` has no `subject` field; `extra` can carry it. |
| Go | **M** for JWKS/iss/aud/sub; **A** for exp/scopes | `auth.TokenVerifier` callback (`auth/auth.go`); `RequireBearerToken` enforces scopes, expiration, and `ClockSkew`. `oauthex.MatchesResource` ([`oauthex/audience.go`](https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/oauthex/audience.go)) is a helper for `aud` comparison. `golang-jwt` is a dependency, but no server-side JWKS verifier was found. |

Conclusion for item 1: none of the three ships an RS256/JWKS verifier. All
three expose a verifier hook, so the custom verifier would be kept as the hook
implementation.

### 2. RFC 9728 metadata and challenges

| | Verdict | Evidence |
|---|---|---|
| Python | **S** metadata; **A** challenges | `create_protected_resource_routes` serves the doc at the path-suffixed well-known URL (`server/auth/routes.py`). `RequireAuthMiddleware` returns 401 `invalid_token` and 403 `insufficient_scope` with `resource_metadata`. It does not add a `scope` parameter to the challenge (not found in source). |
| TypeScript | **S** metadata; **S/A** challenges | `mcpAuthMetadataRouter` and `getOAuthProtectedResourceMetadataUrl` (`server/auth/router.js`). `requireBearerAuth` emits `error`, `error_description`, `scope` (always the required set), and `resource_metadata`; 401 vs 403 split is correct. Metadata is Express-only and mounts only the path-suffixed URL; the bare URL needs a manual route. |
| Go | **S** metadata; **A** challenges | `ProtectedResourceMetadataHandler(*oauthex.ProtectedResourceMetadata)` with CORS (`auth/auth.go`). Unlike the custom SDK it does not derive the doc from the verifier. `RequireBearerToken` sets `Bearer resource_metadata=..., scope=...` on 401/403 but **does not emit `error="invalid_token"` or `error="insufficient_scope"`** (verified in `auth/auth.go`), so clients cannot tell retryable-with-scope from rejected. A wrapper is needed to match `docs/auth-client.md`. |

### 3. Transport integration and identity in handlers

| | Verdict | Evidence |
|---|---|---|
| Python | **S** | `FastMCP`/`MCPServer` and low-level server accept `token_verifier` plus `AuthSettings` and wire `BearerAuthBackend`/`RequireAuthMiddleware` (`server/mcpserver/server.py`, `server/lowlevel/server.py`). Handlers read identity via `get_access_token()` (`server/auth/middleware/auth_context.py`). `AccessToken` has `client_id`, `scopes`, `expires_at`, `resource`; subject/issuer are optional (`principal_components`). |
| TypeScript | **S** | `req.auth` set by `requireBearerAuth` is forwarded by `StreamableHTTPServerTransport` and delivered to handlers as `extra.authInfo` (`server/streamableHttp.js`, `shared/protocol.js`). |
| Go | **S** | `TokenInfo` goes into the request context; `mcp.StreamableHTTPHandler` forwards it to handlers as `req.Extra.TokenInfo` (`mcp/streamable.go`, `mcp/shared.go`) and uses `UserID` to bind sessions. `TokenInfo` has no first-class subject beyond `UserID`/`Extra`. |

### 4. Token exchange for downstream APIs

| | Verdict | Evidence |
|---|---|---|
| Python | **M** | No RFC 8693 client found in `mcp/` (the client has identity-assertion and client-credentials extensions; server has a jwt-bearer/ID-JAG grant hook). |
| TypeScript | **M** | No token-exchange code found in `dist/esm`. `client/auth-extensions.js` has private-key-JWT client auth only. |
| Go | **A (partial)** | `oauthex.ExchangeToken` ([`oauthex/token_exchange.go`](https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/oauthex/token_exchange.go)) is RFC 8693 but documented and shaped for SEP-990 (ID token to ID-JAG, MCP client side). Whether it can express an RS-side `audience`/`resource` exchange with `private_key_jwt` auth, and its caching, is **unverified**. |

### 5. Errors, dependencies, maintenance

| | Notes |
|---|---|
| Python | Failures are `None` from the verifier, so reasons are lost and no 401 detail is distinguished (bad signature vs expired). Pulls starlette/uvicorn/pydantic/httpx2 transitive deps; `Development Status :: 5 - Production/Stable`. Active repo, major version 2.x. |
| TypeScript | Typed `OAuthError` classes map to 400/401/403/500 cleanly. Heavy transitive tree (express, hono, zod, ajv). Node >=18 (wider than ours). Active, 1.32.x. |
| Go | Sentinel errors `ErrInvalidToken`, `ErrOAuth`; other errors become 500. Requires go 1.25 (custom SDK: 1.18). Active, v1.8.0 released 2026-09-04. |

Maintenance status is based on release cadence and repository content only;
issue/PR activity was not reviewed (unverified).

## Comparison with `sdk-conformance/cases.json`

All 12 cases are verifier verdicts. Official SDKs give no verdict on any of
them without a custom verifier, so a "replacement" must be official middleware
plus a verifier that still has to pass these.

| Case | Official SDK coverage |
|---|---|
| `typ-at-jwt`, `typ-jwt`, `typ-id-token`, `typ-not-a-string` | Not covered (no JWT parsing). Custom code. |
| `exp-within-skew`, `exp-beyond-skew` | Go has `ClockSkew`; Python and TS have none (strict `exp`). |
| `nbf-within-skew` | Not covered by any official middleware. |
| `unknown-kid`, `oversized-jwks` | Not covered (no JWKS). Refetch-rate-limit unit tests have no equivalent. |
| `one-of-two-required-scopes` | Covered: all three require every scope (Py/TS/Go verified). |
| `aud-string`, `aud-array` | Partly: Python/TS compare a single `resource`; Go has `MatchesResource` over a list. Verifier must normalise `aud`. |

Also not covered by cases.json: 401 vs 403 challenge shape, `scope`
parameter, metadata mounting, and the end-to-end run against the deployed MCP
Auth server (Compose E2E in `docs/auth-client.md`). The official SDKs are
therefore not substitutes yet; equivalent challenge/metadata test cases would
need to be added to the harness first.

## Recommendation per SDK

| SDK | Recommendation | Rationale |
|---|---|---|
| Python `mcp-auth-client` | **Keep, then slim later** | Official `mcp` offers transport wiring, scope gate, metadata routes, and handler identity, but no verifier. Target shape: `JWTVerifier` implements `TokenVerifier` for official `mcp`; drop `fastmcp.py`/`integration.py` glue and metadata/challenge code only after parity. Note `mcp` 2.x vs the FastMCP 3.x/4.x the SDK targets today. |
| TypeScript `@mcp-auth/client` | **Keep, then slim later** | Same pattern: `JWTVerifier` returning `AuthInfo` for `requireBearerAuth`; official router covers metadata. Keep the zero-dependency core for non-Express users. |
| Go `mcpauth` | **Keep** (slim last) | Official Go middleware lacks `error=` codes and a verifier, and the metadata handler does not derive from the verifier. Also the go 1.18 floor versus go 1.25 is a compatibility cost for adopters. Largest remaining value in keeping `RequireToken`. |

Nothing is removed. No SDK is a "remove" candidate today.

## Helpers that must stay (MCP Auth-specific or not in official SDKs)

- RS256/JWKS verifier with rotation, caching, `typ`, `iss`, `aud`, `nbf`,
  `sub`, skew, size cap, SSRF policy (all languages).
- `insufficient_scope` / `invalid_token` challenge builders (needed in Go; the
  other two are close but lack equivalent test coverage).
- Metadata derived from the verifier (scope catalogue vs gate separation) and
  the bare plus path-suffixed mounting.
- RFC 8693 `TokenExchangeClient`, `PrivateKeyJWTClientAuth`, cache, and
  `build_exchange_client` (no official equivalent for resource-server use).
- Authorization-server discovery and provider-neutral metadata models.
- The conformance fixtures themselves.

## Migration path

1. Add challenge/metadata cases to the conformance harness and an
   official-SDK variant of each example (below), running the same cases.
2. Implement the custom verifier as the official verifier hook:
   Python `TokenVerifier.verify_token`, TypeScript `OAuthTokenVerifier`,
   Go `auth.TokenVerifier` (verifier maps `sub`, `iss`, scopes into
   `AccessToken`/`AuthInfo`/`TokenInfo.Extra`).
3. Swap transport and challenge code for official middleware per example once
   the parity cases pass; keep custom versions in the SDK until then.
4. Document supported official SDK versions (this table) and re-run the
   audit on each major release.

## Follow-up steps (not done here)

1. Python: build `examples/demo-mcp` variant on `mcp` 2.x `token_verifier` +
   `AuthSettings` using `JWTVerifier` as the verifier; run the Compose E2E.
2. TypeScript: replace the hand-rolled HTTP in `examples/typescript-mcp` with
   `requireBearerAuth` + `mcpAuthMetadataRouter` + `StreamableHTTPServerTransport`,
   reading `extra.authInfo`.
3. Go: `examples/go-mcp` on `auth.RequireBearerToken` + `mcp.StreamableHTTPHandler`,
   wrapped to add `error=` codes; add a test asserting the challenge strings.
4. Verify the unverified items: Go `ExchangeToken` for RS-side exchange, PyJWT
   JWKS caching behavior, Python 2.x migration impact, official-SDK issue/PR
   health.
5. Only after items 1 to 3 pass equivalent conformance and E2E checks, propose
   slimming PRs, one language at a time.
