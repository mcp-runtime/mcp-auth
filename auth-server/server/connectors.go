package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// ConnectorConfig describes one provider-neutral upstream OAuth connector.
// Secrets are referenced by environment variable name and are never stored in
// this structure as literal configuration values.
type ConnectorConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	// TokenEndpointInternal is an optional private endpoint used for
	// server-side code exchange. It avoids public-ingress hairpinning while
	// TokenEndpoint remains the standards-discovered/public endpoint.
	TokenEndpointInternal   string `json:"token_endpoint_internal"`
	TokenEndpointServerName string `json:"token_endpoint_server_name"`
	JWKSURI                 string `json:"jwks_uri"`
	JWKSURIInternal         string `json:"jwks_uri_internal"`
	// UserinfoEndpoint is optional. When set (directly or via discovery),
	// it's used to supplement ID token claims for the identity_claims
	// fallback list when none of them are present in the ID token itself.
	UserinfoEndpoint        string   `json:"userinfo_endpoint"`
	ClientID                string   `json:"client_id"`
	ClientIDEnv             string   `json:"client_id_env"`
	ClientSecretEnv         string   `json:"client_secret_env"`
	Scopes                  []string `json:"scopes"`
	MCPScopes               []string `json:"mcp_scopes"`
	ExchangeClientID        string   `json:"exchange_client_id"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	// AllowedUpstreamCallbackURIs restricts which of this server's own
	// identity-callback URLs (MCP_AUTH_ISSUER + /identity/callback) may be
	// registered with this connector's upstream provider. This guards the
	// server's own registration with the upstream, not an MCP client's
	// redirect_uri. Optional: empty means any derived callback is accepted.
	AllowedUpstreamCallbackURIs []string `json:"allowed_upstream_callback_uris"`
	// AllowedClientRedirectURIs restricts which redirect_uris an MCP client
	// (Cursor, Claude Desktop, ...) may register via dynamic client
	// registration, in addition to the scheme/host checks validRedirect
	// already applies. Optional: empty means any redirect_uri that passes
	// validRedirect is accepted. An http loopback entry ignores the port.
	// http://127.0.0.1:*, http://localhost:*, and http://[::1]:* match any
	// path on that host, which is what an ephemeral desktop listener needs.
	AllowedClientRedirectURIs []string `json:"allowed_client_redirect_uris"`
	// DownstreamTokenStrategy selects how a resource server's downstream
	// credential is obtained: "upstream_session" (default) reuses and
	// refreshes the token this connector's own upstream provider already
	// issued at login, and works with any OAuth2/OIDC provider regardless of
	// RFC 8693 support. "rfc8693" performs RFC 8693 token-exchange against
	// this connector's upstream provider instead, for providers that support
	// it and need a token minted for a specific audience the login session
	// itself wasn't scoped for.
	DownstreamTokenStrategy string `json:"downstream_token_strategy"`
	// AllowedAlgorithms lists the JWS algorithms this connector's ID tokens
	// may be signed with: any of "RS256", "PS256", "ES256". Defaults to
	// ["RS256"] when unset, matching every connector configured before this
	// field existed.
	AllowedAlgorithms []string `json:"allowed_algorithms"`
	// IdentityClaims is the ordered list of ID token claims to use as the
	// local Identity.Subject, trying each in turn. Defaults to ["sub"] when
	// unset. If none of them are present in the ID token and UserinfoEndpoint
	// is known, the userinfo endpoint is called (with the upstream access
	// token) to supplement the claims before resolving again — some
	// providers only expose email/group claims there, not in the ID token.
	IdentityClaims []string `json:"identity_claims"`
	// IDTokenNoncePolicy defaults to "required". Set "disabled" only for an
	// upstream provider whose documented ID-token claims omit nonce.
	IDTokenNoncePolicy string `json:"id_token_nonce_policy"`
	// Consent customizes the browser consent page. When omitted, the server
	// renders its built-in page. website_url and support_url must be absolute
	// https URLs when set.
	Consent *ConsentConfig `json:"consent,omitempty"`
}

const (
	DownstreamTokenStrategyUpstreamSession = "upstream_session"
	DownstreamTokenStrategyRFC8693         = "rfc8693"
)

func (c ConnectorConfig) validate(name string, allowInsecure bool) error {
	for field, value := range map[string]string{
		"issuer":                 c.Issuer,
		"authorization_endpoint": c.AuthorizationEndpoint,
		"token_endpoint":         c.TokenEndpoint,
		"jwks_uri":               c.JWKSURI,
	} {
		if value == "" {
			return fmt.Errorf("connector %q is missing %s", name, field)
		}
		parsed, err := url.Parse(value)
		validScheme := parsed.Scheme == "https" || (allowInsecure && parsed.Scheme == "http")
		if err != nil || !validScheme || parsed.Host == "" {
			return fmt.Errorf("connector %q has non-HTTPS %s", name, field)
		}
	}
	if c.TokenEndpointInternal != "" {
		parsed, err := url.Parse(c.TokenEndpointInternal)
		validScheme := parsed.Scheme == "https" || (allowInsecure && parsed.Scheme == "http")
		if err != nil || !validScheme || parsed.Host == "" {
			return fmt.Errorf("connector %q has non-HTTPS token_endpoint_internal", name)
		}
		if c.TokenEndpointServerName == "" {
			return fmt.Errorf("connector %q requires token_endpoint_server_name with token_endpoint_internal", name)
		}
	}
	if c.JWKSURIInternal != "" {
		parsed, err := url.Parse(c.JWKSURIInternal)
		validScheme := parsed.Scheme == "https" || (allowInsecure && parsed.Scheme == "http")
		if err != nil || !validScheme || parsed.Host == "" {
			return fmt.Errorf("connector %q has non-HTTPS jwks_uri_internal", name)
		}
		if c.TokenEndpointServerName == "" {
			return fmt.Errorf("connector %q requires token_endpoint_server_name with jwks_uri_internal", name)
		}
	}
	if c.UserinfoEndpoint != "" {
		parsed, err := url.Parse(c.UserinfoEndpoint)
		validScheme := parsed.Scheme == "https" || (allowInsecure && parsed.Scheme == "http")
		if err != nil || !validScheme || parsed.Host == "" {
			return fmt.Errorf("connector %q has an invalid userinfo_endpoint", name)
		}
	}
	if c.ClientID == "" && c.ClientIDEnv == "" {
		return fmt.Errorf("connector %q is missing client_id or client_id_env", name)
	}
	if c.ClientID != "" && c.ClientIDEnv != "" {
		return fmt.Errorf("connector %q must set only one of client_id or client_id_env", name)
	}
	if c.TokenEndpointAuthMethod == "" {
		return fmt.Errorf("connector %q is missing token_endpoint_auth_method", name)
	}
	if c.TokenEndpointAuthMethod != "none" && c.TokenEndpointAuthMethod != "client_secret_basic" && c.TokenEndpointAuthMethod != "client_secret_post" {
		return fmt.Errorf("connector %q has unsupported token_endpoint_auth_method", name)
	}
	if c.TokenEndpointAuthMethod != "none" && c.ClientSecretEnv == "" {
		return fmt.Errorf("connector %q requires client_secret_env", name)
	}
	if c.ExchangeClientID == "" {
		return fmt.Errorf("connector %q is missing exchange_client_id", name)
	}
	if c.DownstreamTokenStrategy != "" && c.DownstreamTokenStrategy != DownstreamTokenStrategyUpstreamSession && c.DownstreamTokenStrategy != DownstreamTokenStrategyRFC8693 {
		return fmt.Errorf("connector %q has unsupported downstream_token_strategy", name)
	}
	if c.IDTokenNoncePolicy != "" && c.IDTokenNoncePolicy != "required" && c.IDTokenNoncePolicy != "disabled" {
		return fmt.Errorf("connector %q has unsupported id_token_nonce_policy", name)
	}
	for _, algorithm := range c.AllowedAlgorithms {
		if !validAlgorithm(algorithm) {
			return fmt.Errorf("connector %q has an unsupported allowed_algorithms entry %q", name, algorithm)
		}
	}
	for _, claim := range c.IdentityClaims {
		if claim == "" {
			return fmt.Errorf("connector %q has an empty identity_claims entry", name)
		}
	}
	for _, redirectURI := range c.AllowedUpstreamCallbackURIs {
		if err := validUpstreamCallbackURI(redirectURI); err != nil {
			return fmt.Errorf("connector %q has an invalid allowed upstream callback URI: %w", name, err)
		}
	}
	for _, redirectURI := range c.AllowedClientRedirectURIs {
		if err := validAbsoluteURI(redirectURI); err != nil {
			return fmt.Errorf("connector %q has an invalid allowed client redirect URI: %w", name, err)
		}
	}
	if err := c.Consent.validate(name); err != nil {
		return err
	}
	return nil
}

func (c ConnectorConfig) tokenEndpoint() string {
	if c.TokenEndpointInternal != "" {
		return c.TokenEndpointInternal
	}
	return c.TokenEndpoint
}

func (c ConnectorConfig) jwksURI() string {
	if c.JWKSURIInternal != "" {
		return c.JWKSURIInternal
	}
	return c.JWKSURI
}

func (c ConnectorConfig) httpClient() *http.Client {
	if c.TokenEndpointInternal == "" || c.TokenEndpointServerName == "" {
		return http.DefaultClient
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return http.DefaultClient
	}
	transport := base.Clone()
	transport.TLSClientConfig = &tls.Config{ServerName: c.TokenEndpointServerName, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport, Timeout: http.DefaultClient.Timeout}
}

// resolvedAllowedAlgorithms returns the configured algorithm allowlist,
// defaulting to RS256 only when unset.
func (c ConnectorConfig) resolvedAllowedAlgorithms() []string {
	if len(c.AllowedAlgorithms) == 0 {
		return []string{"RS256"}
	}
	return c.AllowedAlgorithms
}

// requiresIDToken reports whether this connector's own authorization request
// makes an ID token mandatory.
//
// Requesting the "openid" scope is what makes a flow OIDC rather than plain
// OAuth 2.0, and OIDC Core requires the provider to return an id_token in
// that case — so a missing one is a real error (a provider fault, or someone
// dropping "openid" from the scopes), not a cue to quietly accept less
// verification. A connector that never asks for "openid" is a plain OAuth 2.0
// connector, GitHub-style: there is no ID token to miss, and identity comes
// from userinfo_endpoint instead. Begin() defaults to "openid" when no scopes
// are configured, so an empty list means OIDC here too.
func (c ConnectorConfig) requiresIDToken() bool {
	if len(c.Scopes) == 0 {
		return true
	}
	return contains(c.Scopes, "openid")
}

// requiresIDTokenNonce keeps nonce validation mandatory unless a connector
// explicitly opts out for an upstream that cannot return a nonce claim.
func (c ConnectorConfig) requiresIDTokenNonce() bool {
	return c.IDTokenNoncePolicy == "" || c.IDTokenNoncePolicy == "required"
}

// resolvedIdentityClaims returns the configured identity-claim fallback
// list, defaulting to ["sub"] when unset.
func (c ConnectorConfig) resolvedIdentityClaims() []string {
	if len(c.IdentityClaims) == 0 {
		return []string{"sub"}
	}
	return c.IdentityClaims
}

// ResolvedDownstreamTokenStrategy returns the configured strategy, defaulting
// to upstream_session when unset.
func (c ConnectorConfig) ResolvedDownstreamTokenStrategy() string {
	if c.DownstreamTokenStrategy == "" {
		return DownstreamTokenStrategyUpstreamSession
	}
	return c.DownstreamTokenStrategy
}

// resolveClientID returns the connector's OAuth client_id, reading it from
// the environment when client_id_env is set instead of a literal value.
func (c ConnectorConfig) resolveClientID() (string, error) {
	if c.ClientIDEnv == "" {
		return c.ClientID, nil
	}
	value := strings.TrimSpace(os.Getenv(c.ClientIDEnv))
	if value == "" {
		return "", fmt.Errorf("client id environment variable %q is empty", c.ClientIDEnv)
	}
	return value, nil
}

// LoadConnectors reads a JSON object keyed by connector name. A literal
// client_secret field is rejected to prevent accidental secret commits.
func LoadConnectors(path string) (map[string]ConnectorConfig, error) {
	return LoadConnectorsWithOptions(path, false)
}

// LoadConnectorsWithOptions permits HTTP endpoints only for an explicitly
// enabled local-development process. Production connector files always use
// HTTPS so upstream credentials and authorization codes are protected in transit.
func LoadConnectorsWithOptions(path string, allowInsecure bool) (map[string]ConnectorConfig, error) {
	if path == "" {
		return map[string]ConnectorConfig{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read connectors file: %w", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse connectors file: %w", err)
	}
	connectors := make(map[string]ConnectorConfig, len(raw))
	for name, value := range raw {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(value, &object); err != nil {
			return nil, fmt.Errorf("connector %q is not an object", name)
		}
		if _, ok := object["client_secret"]; ok {
			return nil, errors.New("connectors file must use client_secret_env, never client_secret")
		}
		var connector ConnectorConfig
		decoder := json.NewDecoder(bytes.NewReader(value))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&connector); err != nil {
			return nil, fmt.Errorf("parse connector %q: %w", name, err)
		}
		// Discovery only runs when at least one required endpoint is missing,
		// never just because userinfo_endpoint (always optional) is unset —
		// a connector that already specifies everything it needs must never
		// make a network call it didn't have to make before this existed.
		if connector.Issuer != "" && (connector.AuthorizationEndpoint == "" || connector.TokenEndpoint == "" || connector.JWKSURI == "") {
			discoveryClient := &http.Client{Timeout: discoveryTimeout}
			discovered, err := discoverOIDCConfiguration(context.Background(), discoveryClient, connector.Issuer)
			if err != nil {
				return nil, fmt.Errorf("connector %q: discover OIDC configuration: %w", name, err)
			}
			if connector.AuthorizationEndpoint == "" {
				connector.AuthorizationEndpoint = discovered.AuthorizationEndpoint
			}
			if connector.TokenEndpoint == "" {
				connector.TokenEndpoint = discovered.TokenEndpoint
			}
			if connector.JWKSURI == "" {
				connector.JWKSURI = discovered.JWKSURI
			}
			if connector.UserinfoEndpoint == "" {
				connector.UserinfoEndpoint = discovered.UserinfoEndpoint
			}
		}
		if err := connector.validate(name, allowInsecure); err != nil {
			return nil, err
		}
		connectors[name] = connector
	}
	return connectors, nil
}
