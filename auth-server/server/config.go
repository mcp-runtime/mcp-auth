package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Issuer               string
	Resources            []string
	ListenAddr           string
	AccessTokenTTL       time.Duration
	RefreshTokenTTL      time.Duration
	AuthorizationCodeTTL time.Duration
	AllowedScopes        []string
	// ResourceScopes replaces AllowedScopes for the named MCP resource. The
	// platform supplies this map from each server's own OAuth configuration.
	ResourceScopes map[string][]string
	// ResourceScopesJSON is parsed during Validate so malformed deployment
	// configuration fails startup instead of silently widening access.
	ResourceScopesJSON  string
	TrustedOrigins      []string
	PrivateKeyFile      string
	RegistrationEnabled bool
	// IdentityCallback overrides the redirect URI this server registers with
	// the upstream provider. Empty derives it from the issuer.
	IdentityCallback string
	// ClientIDMetadataEnabled turns on OAuth Client ID Metadata Documents.
	// Enabled by default to support MCP clients that use CIMD. Set
	// MCP_AUTH_CLIENT_ID_METADATA_ENABLED=false to opt out. Fetches are limited
	// to public HTTPS destinations and bounded by timeout and response size.
	ClientIDMetadataEnabled bool
	// ClientIDMetadataHosts optionally restricts which hosts a client_id
	// metadata document may be fetched from. Empty means any public host.
	ClientIDMetadataHosts       []string
	LocalDevelopment            bool
	LocalSubject                string
	LocalClientID               string
	AuthorizationResponseIssuer bool
	LocalTokenExchange          bool
	RequireHTTPS                bool
	// TrustProxyTLS lets the deployment declare that a trusted reverse
	// proxy terminates TLS in front of this process and overwrites the
	// forwarded headers. Only then is X-Forwarded-Proto evidence of
	// anything: it is client-supplied, so trusting it unconditionally
	// turns RequireHTTPS into a header any caller can set.
	TrustProxyTLS           bool
	AllowInsecureConnectors bool
	ConnectorsFile          string
	ConnectorName           string
	StoreBackend            string
	DatabaseURL             string
	ResourceClientsFile     string
	// AllowedClientRedirectURIs restricts dynamic client registration
	// (POST /register) when non-empty, in addition to validRedirect.
	// http loopback entries match scheme, hostname, and path and ignore the
	// port. http://127.0.0.1:*, http://localhost:*, and http://[::1]:* match
	// any path on that host. https and private-use entries match exactly.
	// It is populated from the selected connector's
	// allowed_client_redirect_uris, not set directly from an environment variable.
	AllowedClientRedirectURIs []string
	// LogLevel gates the one-line-per-request access log (method, path,
	// status, duration, client_id where known). "silent" disables it;
	// anything else (the default, "info") enables it. There was previously
	// no way to answer "did the request even arrive" without opening the
	// store directly, which is a real obstacle for a server whose job is
	// being integrated against by third-party clients.
	LogLevel string
	// Consent is copied from the selected connector. Nil uses the built-in
	// consent page. It is not read from an environment variable.
	Consent *ConsentConfig
}

// Validate applies deployment safety checks that are intentionally separate
// from NewServer so tests and embedders can supply their own transport setup.
// It also normalizes Issuer (stripping any trailing slash) in place: every
// endpoint URL this server builds or advertises is derived from Issuer via
// the methods below, and a trailing slash surviving into that derivation is
// what previously produced double slashes on some endpoints and a
// mismatched token_endpoint between what was advertised and what
// authenticateClientAssertion actually checked against.
func (c *Config) Validate() error {
	c.Issuer = strings.TrimRight(c.Issuer, "/")
	resources := c.configuredResources()
	if c.Issuer == "" || len(resources) == 0 {
		return errors.New("issuer and resources are required")
	}
	issuer, err := url.Parse(c.Issuer)
	if err != nil || issuer.Hostname() == "" || issuer.Scheme == "" {
		return errors.New("issuer must be an absolute URL")
	}
	for _, value := range resources {
		resource, err := url.Parse(value)
		if err != nil || resource.Hostname() == "" || resource.Scheme == "" {
			return errors.New("resources must be absolute URLs")
		}
	}
	if c.RequireHTTPS && issuer.Scheme != "https" {
		return errors.New("issuer and resource must use HTTPS when MCP_AUTH_REQUIRE_HTTPS is enabled")
	}
	if c.RequireHTTPS {
		for _, value := range resources {
			if parsed, _ := url.Parse(value); parsed.Scheme != "https" {
				return errors.New("issuer and resource must use HTTPS when MCP_AUTH_REQUIRE_HTTPS is enabled")
			}
		}
	}
	if c.IdentityCallback != "" {
		callback, err := url.Parse(c.IdentityCallback)
		if err != nil || callback.Scheme == "" || callback.Host == "" || callback.Fragment != "" {
			return errors.New("MCP_AUTH_IDENTITY_CALLBACK_URL must be an absolute URL with no fragment")
		}
		if c.RequireHTTPS && callback.Scheme != "https" {
			return errors.New("MCP_AUTH_IDENTITY_CALLBACK_URL must use HTTPS when MCP_AUTH_REQUIRE_HTTPS is enabled")
		}
		if callback.Path == "" || callback.Path == "/" {
			return errors.New("MCP_AUTH_IDENTITY_CALLBACK_URL must name a path, so the callback can be routed to this server")
		}
	}
	if c.AllowInsecureConnectors && c.RequireHTTPS {
		return errors.New("insecure connector transport requires MCP_AUTH_REQUIRE_HTTPS=false")
	}
	if c.LocalDevelopment && !isLoopbackHost(issuer.Hostname()) {
		return fmt.Errorf("local development is only allowed with a loopback issuer, got %q", issuer.Hostname())
	}
	if !c.LocalDevelopment && c.PrivateKeyFile == "" {
		return errors.New("MCP_AUTH_PRIVATE_KEY_FILE is required outside local development")
	}
	storeBackend := strings.ToLower(c.StoreBackend)
	if !c.LocalDevelopment && storeBackend == "memory" {
		return errors.New("memory store is only allowed in local development")
	}
	if storeBackend != "memory" && storeBackend != "sqlite" {
		return fmt.Errorf("unsupported store backend %q", c.StoreBackend)
	}
	if storeBackend == "sqlite" && c.DatabaseURL == "" {
		return errors.New("MCP_AUTH_DATABASE_URL is required for the sqlite store")
	}
	if c.ConnectorName != "" && c.ConnectorsFile == "" {
		return errors.New("MCP_AUTH_CONNECTORS_FILE is required when MCP_AUTH_CONNECTOR is set")
	}
	if c.ConnectorsFile != "" && c.ConnectorName == "" {
		return errors.New("MCP_AUTH_CONNECTOR is required when MCP_AUTH_CONNECTORS_FILE is set")
	}
	if c.ResourceScopesJSON != "" {
		if err := json.Unmarshal([]byte(c.ResourceScopesJSON), &c.ResourceScopes); err != nil || c.ResourceScopes == nil {
			return errors.New("MCP_AUTH_RESOURCE_SCOPES must be a JSON object of resource URLs to scope arrays")
		}
	}
	for resource, scopes := range c.ResourceScopes {
		if !contains(resources, resource) {
			return fmt.Errorf("MCP_AUTH_RESOURCE_SCOPES contains unrecognized resource %q", resource)
		}
		if len(scopes) == 0 {
			return fmt.Errorf("MCP_AUTH_RESOURCE_SCOPES requires scopes for %q", resource)
		}
		seen := make(map[string]bool, len(scopes))
		for _, scope := range scopes {
			if strings.TrimSpace(scope) != scope || scope == "" || strings.ContainsAny(scope, " \t\r\n\"\\") || seen[scope] {
				return fmt.Errorf("MCP_AUTH_RESOURCE_SCOPES contains an invalid or duplicate scope for %q", resource)
			}
			seen[scope] = true
		}
	}
	return nil
}

func (c Config) configuredResources() []string {
	return append([]string(nil), c.Resources...)
}

func (c Config) scopesForResource(resource string) []string {
	if scopes, ok := c.ResourceScopes[resource]; ok {
		return scopes
	}
	return c.AllowedScopes
}

func (c Config) supportedScopes() []string {
	seen := make(map[string]bool)
	for _, scope := range c.AllowedScopes {
		seen[scope] = true
	}
	for _, scopes := range c.ResourceScopes {
		for _, scope := range scopes {
			seen[scope] = true
		}
	}
	result := make([]string, 0, len(seen))
	for scope := range seen {
		result = append(result, scope)
	}
	sort.Strings(result)
	return result
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// issuerBase is Issuer with any trailing slash stripped, so every endpoint
// method below produces a single-slash-joined URL regardless of whether
// Validate has already normalized Issuer (it always has on the real startup
// path; this is a second line of defense for callers, such as tests, that
// build a Config without calling Validate). Every URL this server builds
// from Issuer must go through one of these methods — never Issuer + "..."
// or an ad hoc TrimRight at the point of use — so the advertised value and
// the value actually checked against can never independently drift, which
// is exactly how they drifted before (server.go's metadata handler
// concatenated Issuer raw while its client-assertion check trimmed it).
// IssuerPath is the issuer's path component without surrounding slashes, or ""
// when the issuer is mounted at the host root. RFC 8414 section 3.1 derives the
// metadata URL from it: an issuer of https://host/tenant serves its metadata at
// https://host/.well-known/oauth-authorization-server/tenant, not at
// https://host/tenant/.well-known/oauth-authorization-server.
func (c Config) IssuerPath() string {
	parsed, err := url.Parse(c.Issuer)
	if err != nil {
		return ""
	}
	return strings.Trim(parsed.Path, "/")
}

func (c Config) issuerBase() string {
	return strings.TrimRight(c.Issuer, "/")
}

func (c Config) AuthorizationEndpoint() string { return c.issuerBase() + "/authorize" }
func (c Config) TokenEndpoint() string         { return c.issuerBase() + "/token" }
func (c Config) RegistrationEndpoint() string  { return c.issuerBase() + "/register" }
func (c Config) RevocationEndpoint() string    { return c.issuerBase() + "/revoke" }
func (c Config) JWKSURI() string               { return c.issuerBase() + "/.well-known/jwks.json" }

// IdentityCallbackURL is the redirect URI this server hands the upstream
// provider, and therefore the one an operator has to register with it.
//
// It defaults to <issuer>/identity/callback. The override exists because that
// URI is frequently not ours to choose: an OAuth app may already exist with a
// fixed redirect URI, the provider may be administered by another team, or
// change control may make adding one slow. Pointing this at a URI the provider
// already accepts lets a deployment adopt mcp-auth without touching the
// provider at all. IdentityCallbackPath then serves the callback at whatever
// path the override names, so the redirect still lands on this server.
func (c Config) IdentityCallbackURL() string {
	if c.IdentityCallback != "" {
		return strings.TrimRight(c.IdentityCallback, "/")
	}
	return c.issuerBase() + "/identity/callback"
}

// IdentityCallbackPath is the path the callback handler is mounted at, taken
// from IdentityCallbackURL so an override is reachable rather than merely
// advertised.
func (c Config) IdentityCallbackPath() string {
	parsed, err := url.Parse(c.IdentityCallbackURL())
	if err != nil || parsed.Path == "" || parsed.Path == "/" {
		return "/identity/callback"
	}
	return parsed.Path
}

// ConsentEndpoint is where the consent form posts. It has to come from the
// issuer like the rest: a root-relative form action resolves against the
// browser's origin, which drops the issuer's path prefix on a path-mounted
// deployment and posts to a 404.
func (c Config) ConsentEndpoint() string { return c.issuerBase() + "/authorize/consent" }

func ConfigFromEnv() Config {
	return Config{
		Issuer:                      env("MCP_AUTH_ISSUER", "http://localhost:8080"),
		Resources:                   csvEnv("MCP_AUTH_RESOURCES", []string{"http://localhost:8081/mcp"}),
		ListenAddr:                  env("MCP_AUTH_LISTEN_ADDR", ":8080"),
		AccessTokenTTL:              durationEnv("MCP_AUTH_ACCESS_TOKEN_TTL", 10*time.Minute),
		RefreshTokenTTL:             durationEnv("MCP_AUTH_REFRESH_TOKEN_TTL", 24*time.Hour),
		AuthorizationCodeTTL:        durationEnv("MCP_AUTH_AUTHORIZATION_CODE_TTL", 2*time.Minute),
		AllowedScopes:               csvEnv("MCP_AUTH_ALLOWED_SCOPES", []string{"tools:read"}),
		ResourceScopesJSON:          strings.TrimSpace(os.Getenv("MCP_AUTH_RESOURCE_SCOPES")),
		TrustedOrigins:              csvEnv("MCP_AUTH_TRUSTED_ORIGINS", nil),
		PrivateKeyFile:              os.Getenv("MCP_AUTH_PRIVATE_KEY_FILE"),
		RegistrationEnabled:         boolEnv("MCP_AUTH_REGISTRATION_ENABLED", false),
		IdentityCallback:            strings.TrimSpace(os.Getenv("MCP_AUTH_IDENTITY_CALLBACK_URL")),
		ClientIDMetadataEnabled:     boolEnv("MCP_AUTH_CLIENT_ID_METADATA_ENABLED", true),
		ClientIDMetadataHosts:       csvEnv("MCP_AUTH_CLIENT_ID_METADATA_HOSTS", nil),
		LocalDevelopment:            boolEnv("MCP_AUTH_LOCAL_DEVELOPMENT", false),
		LocalSubject:                env("MCP_AUTH_LOCAL_SUBJECT", "local-user"),
		LocalClientID:               os.Getenv("MCP_AUTH_LOCAL_CLIENT_ID"),
		AuthorizationResponseIssuer: boolEnv("MCP_AUTH_AUTHORIZATION_RESPONSE_ISS", true),
		LocalTokenExchange:          boolEnv("MCP_AUTH_LOCAL_TOKEN_EXCHANGE", false),
		RequireHTTPS:                boolEnv("MCP_AUTH_REQUIRE_HTTPS", true),
		TrustProxyTLS:               boolEnv("MCP_AUTH_TRUST_PROXY_TLS", false),
		AllowInsecureConnectors:     boolEnv("MCP_AUTH_ALLOW_INSECURE_CONNECTORS", false),
		ConnectorsFile:              os.Getenv("MCP_AUTH_CONNECTORS_FILE"),
		ConnectorName:               os.Getenv("MCP_AUTH_CONNECTOR"),
		StoreBackend:                env("MCP_AUTH_STORE", "memory"),
		DatabaseURL:                 os.Getenv("MCP_AUTH_DATABASE_URL"),
		ResourceClientsFile:         os.Getenv("MCP_AUTH_RESOURCE_CLIENTS_FILE"),
		LogLevel:                    env("MCP_AUTH_LOG_LEVEL", "info"),
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func durationEnv(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func boolEnv(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func csvEnv(name string, fallback []string) []string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
