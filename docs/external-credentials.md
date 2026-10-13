# External credential connector

A separately deployed resource server (for example a secret-manager-backed MCP
gateway) can ask `auth-server` for a short-lived, signed **credential-access
assertion** for the authenticated user and one MCP resource, using the RFC 8693
token-exchange grant. `auth-server` stays the only authority for identity,
session validity, resource/scope policy and resource-client authentication. It
never handles a secret-provider SDK, vault reference or upstream credential:
secret retrieval and header injection belong to the external plugin.

## Configuration

Set `MCP_AUTH_EXTERNAL_CREDENTIALS_FILE` to a JSON array. Unknown fields are
rejected, and the file is validated at startup.

```json
[
  {
    "id": "vault-gateway",
    "resource": "https://mcp.example.org/cully/mcp",
    "required_scopes": ["tools:read"],
    "resource_client": {
      "client_id": "vault-gateway",
      "public_key_file": "/etc/mcp-auth/vault-gateway.pub",
      "algorithm": "RS256"
    },
    "assertion_ttl_seconds": 60
  }
]
```

- `resource` must be listed in `MCP_AUTH_RESOURCES`.
- `required_scopes` is non-empty and every scope must be allowed for that resource.
- `resource_client` takes `client_id`, one of `public_key_pem` / `public_key_file`, and
  `algorithm` (`RS256` default, `PS256`, `ES256`). Client ids must be unique across this
  file and `MCP_AUTH_RESOURCE_CLIENTS_FILE`.
- `assertion_ttl_seconds` defaults to 60 and may not exceed 300.

The signing key provider must support session ids and assertion signing (the
built-in one does).

## Wire contract

`POST /token`, authenticated with `private_key_jwt` as the resource client:

| Parameter | Value |
| --- | --- |
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | the user's access token for `resource` |
| `subject_token_type` | optional; `urn:ietf:params:oauth:token-type:access_token` |
| `requested_token_type` | `urn:mcp-auth:token-type:credential-access-assertion` |
| `audience` | the configured `resource` |
| `client_id`, `client_assertion_type`, `client_assertion` | RFC 7523 client authentication (each assertion `jti` is single-use) |

Before an assertion is minted the server verifies the subject token's
signature, `iss`, `typ: at+jwt`, `aud == resource`, expiry and `required_scopes`,
requires a `sid` claim, and checks that the login session behind it is still
active (not revoked, not expired). Revoking the refresh token or family ends the
session even if the access token has not expired.

Success response:

```json
{
  "access_token": "<jwt>",
  "issued_token_type": "urn:mcp-auth:token-type:credential-access-assertion",
  "token_type": "N_A",
  "expires_in": 60,
  "scope": "tools:read"
}
```

The assertion is signed with the server's key (published in JWKS), header
`typ: credential-access+jwt`, with claims:

| Claim | Meaning |
| --- | --- |
| `iss` | the authorization server issuer |
| `sub` | the user |
| `aud` | the resource client's `client_id` |
| `sid` | login-session (refresh family) id |
| `resource` | the MCP resource |
| `scope` | scopes of the subject token |
| `jti`, `iat`, `nbf`, `exp` | uniqueness and a short lifetime |

The plugin must verify signature, `iss`, `typ`, `aud` (its own client id) and
`exp`, and may use `jti` for replay protection.

Errors: `invalid_client` (unauthenticated or unbound client), `invalid_request`
(wrong `requested_token_type` / `subject_token_type`), `invalid_target` (wrong
`audience`), `invalid_grant` (bad, foreign, wrong-audience, expired,
insufficient-scope or session-less subject token, or inactive session),
`unauthorized_client` (a client without an external-credential binding asked for
an assertion). Every outcome is audited as `credential_assertion`.

## Notes

- Access tokens issued before upgrading carry no `sid` and are rejected here
  until the user refreshes or signs in again.
- The existing OAuth token-exchange connectors and their responses are unchanged.
  They now also require the subject token's `iss` to be this server and its
  `typ` to be `at+jwt`.
