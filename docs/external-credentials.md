# External credential connectors

An **external credential connector** lets a separately deployed resource server
obtain a short-lived, signed *credential-access assertion* for the authenticated
user and one MCP resource. The resource server then fetches the user's upstream
credentials from its own secret manager and injects them into requests to a fixed
upstream service.

`auth-server` stays provider-neutral. It never sees, stores or relays the upstream
credential, holds no secret-manager SDK or token, and does not know which secret
provider the resource server uses.

## Why this exists

Without it, every user pastes upstream credentials (usernames, API tokens, service
headers) into their MCP client configuration. With it, the client configuration holds
only the MCP URL. The client completes the normal OAuth flow with `auth-server`; the
resource server asks `auth-server` whether it may act for this user's live session on
this resource, and only then looks credentials up.

## Roles

| Component | Responsibility |
| --- | --- |
| `auth-server` | Login, consent, tokens, session validity and revocation, resource and scope policy, authenticating the resource client. Mints the assertion. |
| External resource server | Verifies the MCP token, requests an assertion on **every request**, resolves credentials from its secret manager, injects headers, proxies to the fixed upstream. |
| MCP client | Standard OAuth. Never receives upstream credentials. |

## Wire contract

One endpoint, the existing `POST /token` with the RFC 8693 token-exchange grant. There
is **no private endpoint** on the resource server and no callback from `auth-server` to
it. The exchange returns an *assertion*, not a credential bundle.

### Request

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<MCP access token presented by the client>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
requested_token_type=urn:mcp-auth:token-type:credential-access-assertion
audience=<canonical resource URL>
client_id=<resource client id>
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<RFC 7523 private_key_jwt, aud = <issuer>/token>
```

### Who authenticates what

| Check | Performed by | How |
| --- | --- | --- |
| Which resource server is asking | `auth-server` | `private_key_jwt` signed by the key registered for that resource client; `jti` is single-use, so a replayed client assertion is rejected. The client is bound to exactly one resource. |
| Who the human user is | `auth-server` | Verified identity from the login provider, carried in the `sub` of the access token it issued. A secret-manager service account never establishes user identity. |
| That the token is genuine | `auth-server` | Signature, `iss`, `typ=at+jwt`, expiry, `aud` equal to the client's resource. |
| That the user may use this resource | `auth-server` | Every `required_scopes` entry is in the token's scope. |
| That the login session is still active | `auth-server` | The token's `sid` (refresh-token family) must have an unused, unrevoked, unexpired refresh token. Revoked or ended sessions are refused. Tokens without `sid` are refused. |
| That the plugin may use this connector | `auth-server` | `audience` and `resource` must equal the connector's resource, and the authenticated client must be the connector's registered client. |

### Response (200)

```json
{
  "access_token": "<assertion JWT>",
  "issued_token_type": "urn:mcp-auth:token-type:credential-access-assertion",
  "token_type": "N_A",
  "expires_in": 60,
  "scope": "gitlab:use"
}
```

`Cache-Control: no-store`. `token_type` is `N_A` because the value is not an access
token and must never be sent as a Bearer credential.

The assertion is a JWT signed with the same key set published at the JWKS URI:

| Header / claim | Value |
| --- | --- |
| `typ` | `credential-access+jwt` (never `at+jwt`, so it cannot be used as an access token) |
| `iss` | The issuer. Together with `sub` this is the stable identity key; mappings must include the issuer to prevent subject collisions. |
| `sub` | Verified user subject |
| `aud`, `azp` | The resource client id |
| `resource` | Canonical resource URL |
| `connector` | Connector id |
| `sid` | Session id the approval was based on |
| `scope` | Scopes granted to the subject token |
| `token_use` | `credential_access` (the exchange refuses an assertion presented as a subject token) |
| `jti`, `iat`, `nbf`, `exp` | Single-use id; lifetime `assertion_ttl_seconds` (default 60, max 300) |

It contains **no credential material**.

### What the resource server does with it

1. Verify signature, `typ`, `iss`, `aud` (its own client id), expiry.
2. Check `sub`/`sid` equal those of the access token it just verified and `resource`
   equals its own canonical URL.
3. Treat `jti` as single-use.
4. Resolve credentials for `(iss, sub, service)` from its own mapping and secret manager.

### Errors

| Status | OAuth error | Meaning |
| --- | --- | --- |
| 401 | `invalid_client` | Resource client authentication failed or client reused a `client_assertion`. |
| 400 | `invalid_grant` | Subject token invalid, expired, foreign, untyped, has no `sid`, or the session is inactive. |
| 400 | `invalid_target` | `audience` or `resource` is not the connector's resource. |
| 400 | `invalid_request` | Unsupported `requested_token_type` or `subject_token_type`. |
| 403 | `insufficient_scope` | Subject token lacks a required scope. |
| 500 | `server_error` | Session lookup or signing failed. |

## Revocation

`auth-server` re-checks the session on **every** exchange, and the resource server
exchanges on every request. A revoked session is therefore refused on the next request
with no vault access. The resource server must not cache assertions or exchange
results. It may cache credentials, but only after a successful exchange, so a cache
hit cannot bypass revocation.

## Configuration

Set `MCP_AUTH_EXTERNAL_CREDENTIALS_FILE` to a JSON array. Unknown keys are rejected and
invalid files fail startup:

```json
[
  {
    "id": "gitlab-secrets",
    "resource": "https://mcp.example.com/gitlab/mcp",
    "required_scopes": ["gitlab:use"],
    "resource_client": {
      "client_id": "gitlab-secrets-plugin",
      "public_key_file": "/etc/mcp-auth/gitlab-secrets-plugin.pub.pem",
      "algorithm": "RS256"
    },
    "assertion_ttl_seconds": 60
  }
]
```

| Field | Rules |
| --- | --- |
| `id` | `[A-Za-z0-9._-]{1,64}`, unique |
| `resource` | Absolute URL that is in `MCP_AUTH_RESOURCES`; one connector per resource |
| `required_scopes` | Each must be allowed for the resource in `MCP_AUTH_RESOURCE_SCOPES` |
| `resource_client` | `client_id` unique; exactly one of `public_key_pem` or `public_key_file`; optional `algorithm` (`RS256` default, `PS256`, `ES256`) matching the key. Only the **public** key is configured. |
| `assertion_ttl_seconds` | 1 to 300, default 60 |

Login-provider selection stays at the server level (`MCP_AUTH_CONNECTOR`). A
connector entry carries no vendor settings, no login-provider reference, and no
secret-manager configuration.

Startup fails if the key provider cannot sign assertions or issue session-bound access
tokens. The default key provider supports both.

## Compatibility

* Access tokens issued by this version carry an additional `sid` claim. Existing
  resource servers ignore unknown claims. Tokens issued before the upgrade have no
  `sid` and cannot be exchanged for an assertion until the user signs in again.
* Existing connectors, the `upstream_session` and `rfc8693` strategies, and their exchange
  responses are unchanged. Exchange dispatches to the external path only for a resource
  client bound to an external-credential resource.
* `Store` gains `RefreshFamilyActive`; the in-memory and SQLite stores implement it.
* `KeyProvider` is unchanged. Two optional interfaces, `SessionSigner` and `ClaimsSigner`,
  are implemented by the local key provider.
