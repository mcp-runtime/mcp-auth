# Architecture

`mcp-auth` keeps protocol authorization, resource-server enforcement, and
provider-specific behavior behind explicit boundaries. The authorization server and
SDKs can be deployed independently; neither requires MCP tool handlers to know which
identity provider authenticated the user.

## Components

`auth-server` is an independently deployable Go OAuth authorization server. It owns authorization codes, consent, access-token signing, refresh-token rotation, client registration, and authorization-server metadata.

`auth-client/python`, `auth-client/go`, and `auth-client/typescript` are
resource-server SDKs. They validate access tokens issued by any compatible
authorization server and provide discovery, challenge, and token-exchange
helpers. They do not require the bundled authorization server.

Provider integrations implement `IdentityProvider` or `TokenExchanger` interfaces. Provider-specific claims, SDKs, and policy remain outside the core server and SDKs.

## Standards and roles

mcp-auth supports the MCP OAuth 2.1 profile, including RFC 8414 Authorization
Server Metadata, RFC 9728 Protected Resource Metadata, mandatory PKCE S256,
resource indicators and audience-bound tokens, refresh-token rotation, RFC
9207 authorization-response `iss`, and Client ID Metadata Documents (CIMD).
CIMD is the preferred client-registration mechanism when advertised by the
authorization server; Dynamic Client Registration (DCR) remains available as a
backwards-compatibility fallback for servers that do not advertise CIMD. The
client chooses one mechanism according to server metadata; it does not perform
DCR after a successful CIMD registration because CIMD has no registration
endpoint. This is a defined profile, not a claim to implement every OAuth
extension or every
responsibility in the MCP specification. Clients, resource servers, and
authorization servers have distinct normative responsibilities.

| Role | Responsibilities |
| --- | --- |
| Authorization server (`auth-server`) | Publishes authorization-server metadata; handles client registration, authorization, consent, codes and tokens; requires PKCE S256; binds tokens to the requested resource; rotates refresh tokens; brokers user authentication through the selected upstream provider. |
| Resource-server SDK | Publishes or helps publish Protected Resource Metadata and challenges; validates issuer, signature, audience/resource, expiry, subject, and required scopes; provides token-exchange helpers. The resource server defines its own access policy. |
| Upstream identity provider | Authenticates users and owns MFA, directory and access policy, user lifecycle, and upstream credentials. mcp-auth is not an identity provider. |

```mermaid
flowchart TB
    subgraph clients["MCP clients"]
        desktop["Desktop or CLI client"]
    end

    subgraph resource["MCP resource server"]
        tools["MCP tools"]
        sdk["mcp-auth client SDK<br/>challenge, discovery, JWT verification"]
        policy["Resource policy<br/>audience and scopes"]
        sdk --> policy --> tools
    end

    subgraph auth["mcp-auth process"]
        handlers["OAuth endpoints"]
        provider["IdentityProvider"]
        exchanger["TokenExchanger"]
        store["Store"]
        keys["KeyProvider"]
        handlers --> provider
        handlers --> exchanger
        handlers --> store
        handlers --> keys
    end

    idp["OIDC or OAuth 2.0 provider"]
    api["Downstream API"]

    desktop <-->|"MCP + OAuth"| sdk
    desktop <-->|"OAuth 2.1 Authorization Code + PKCE S256"| handlers
    provider <-->|"Login and identity"| idp
    exchanger <-->|"Downstream credential"| idp
    tools -->|"Provider token only"| api
```

## MCP request flow

```mermaid
sequenceDiagram
    autonumber
    actor Client as MCP client
    participant RS as MCP resource server
    participant AS as mcp-auth
    participant IdP as Upstream IdP

    Client->>RS: MCP request without token
    RS-->>Client: 401 + WWW-Authenticate resource_metadata
    Client->>RS: GET protected-resource metadata
    RS-->>Client: authorization_servers + resource
    Client->>AS: GET authorization-server metadata
    AS-->>Client: authorize, token, register, JWKS endpoints
    opt Dynamic client registration enabled
        Client->>AS: POST /register
        AS-->>Client: client_id
    end
    Client->>AS: GET /authorize + resource + PKCE challenge
    AS->>IdP: Redirect user to upstream authorization
    IdP-->>AS: Authorization callback
    AS-->>Client: Authorization code + optional RFC 9207 iss
    Client->>AS: POST /token + code verifier
    AS-->>Client: Short-lived MCP JWT + rotating refresh token
    Client->>RS: MCP request + Bearer MCP JWT
    RS->>AS: Fetch or refresh JWKS
    AS-->>RS: Public signing keys
    RS-->>Client: Authorized MCP response
```

The resource server validates the token's signature, issuer, audience/resource,
expiry, subject, and required scopes before dispatching an MCP tool. Authorization
is optional in MCP itself; each resource server decides whether its data or actions
require it.

Compatibility follows the shared authorization flow in the [2025-06-18 MCP authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) and the [2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization). Newer issuer-response validation is additive, so deployments can support clients from either version. The 2026-07-28 client-registration change is also implemented: an HTTPS URL `client_id` is fetched as an OAuth Client ID Metadata Document, and dynamic client registration remains for clients that do not use one. See [Client ID Metadata Documents](auth-server.md#client-id-metadata-documents).

## Token boundaries

There are three different credentials:

| Credential | Issued for | Allowed use |
| --- | --- | --- |
| MCP client token | The MCP resource server | Inbound resource-server authorization |
| Resource-server service credential | A downstream authorization server/API | Server-to-server authentication |
| Downstream API token | The downstream API audience | Requests to that downstream API only |

The resource server must never forward the MCP client token to an API with a different audience. Use RFC 8693 token exchange or another provider adapter to mint a separate downstream token. Under the default `upstream_session` strategy the exchange response includes `issued_token_type`, and `audience`, `scope`, and `requested_token_type` are advisory: the credential is the one captured at login, not a newly minted audience-scoped token.

```mermaid
flowchart LR
    mcpToken["MCP access token<br/>aud = MCP resource"]
    serviceCredential["Resource-server credential<br/>private_key_jwt"]
    downstreamToken["Downstream token<br/>aud = downstream API"]

    client["MCP client"] -->|"Bearer"| mcpToken
    mcpToken -->|"validated by"| resource["MCP resource server"]
    resource -->|"authenticates exchange with"| serviceCredential
    serviceCredential --> exchange["mcp-auth / token exchange"]
    mcpToken -.->|"subject_token; never sent to API"| exchange
    exchange --> downstreamToken
    downstreamToken -->|"Bearer"| api["Downstream API"]

    mcpToken ~~~ warning["The MCP token and downstream token<br/>are not interchangeable"]
```

`private_key_jwt` proves which resource server is requesting exchange. It does not
identify the end user; the validated MCP token remains the subject credential.

## External credential resource servers

A resource server that injects per-user upstream credentials from its own secret manager
(for example a gateway in front of an MCP backend) uses the same exchange endpoint but
receives a signed, short-lived credential-access assertion instead of an upstream token.
`auth-server` checks the resource client, the subject token and the live session on every
exchange and never handles the credential. See
[External credential connectors](external-credentials.md).

## Extensibility

- `Store` allows durable persistence without changing handlers. OAuth state belongs in a shared managed store for multi-instance deployments.
- `KeyProvider` allows KMS/HSM or secret-manager-backed signing and JWKS publication; local PEM/ephemeral keys are for development only.
- `IdentityProvider` allows local development, OIDC, SAML-backed login, or another user system.
- `TokenExchanger` allows RFC 8693 or provider-specific downstream exchange.
- SDK discovery objects accept third-party authorization-server metadata.
- FastMCP is optional in the Python package; non-FastMCP servers can use the verifier and challenge helpers directly.

## Deployment topology

One `auth-server` process has one issuer, one selected connector, and one canonical
resource audience. Deploy multiple processes when protecting multiple resources.
That keeps client registrations, consent state, signing keys, and upstream sessions
from accidentally crossing resource boundaries.

```mermaid
flowchart TB
    proxy["HTTPS reverse proxy"]

    subgraph one["Resource A boundary"]
        authA["auth-server A<br/>issuer A + connector A"]
        storeA[("Store A")]
        keysA["Key provider A"]
        resourceA["MCP resource A"]
        authA --> storeA
        authA --> keysA
        resourceA -.->|"JWKS + token exchange"| authA
    end

    subgraph two["Resource B boundary"]
        authB["auth-server B<br/>issuer B + connector B"]
        storeB[("Store B")]
        keysB["Key provider B"]
        resourceB["MCP resource B"]
        authB --> storeB
        authB --> keysB
        resourceB -.->|"JWKS + token exchange"| authB
    end

    proxy --> authA
    proxy --> resourceA
    proxy --> authB
    proxy --> resourceB
```

For exact runtime settings and operational constraints, see
[Authorization server](auth-server.md). For SDK integration, see
[Auth client SDKs](auth-client.md).
