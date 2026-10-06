package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Agent-Hellboy/mcp-auth/auth-server/server"
)

func main() {
	config := server.ConfigFromEnv()
	if err := config.Validate(); err != nil {
		slog.Error("invalid server configuration", "error", err)
		os.Exit(1)
	}
	store, closeStore, err := buildStore(config)
	if err != nil {
		slog.Error("store initialization failed", "error", err)
		os.Exit(1)
	}
	defer closeStore()

	config, identityProvider, tokenExchanger, err := buildProviders(config, store)
	if err != nil {
		slog.Error("provider initialization failed", "error", err)
		os.Exit(1)
	}
	authServer, err := server.NewServer(config, store, identityProvider, tokenExchanger, os.Stderr)
	if err != nil {
		slog.Error("server initialization failed", "error", err)
		os.Exit(1)
	}
	if err := loadResourceClients(authServer.Store, config.ResourceClientsFile); err != nil {
		slog.Error("resource client registration failed", "error", err)
		os.Exit(1)
	}
	if config.LocalDevelopment && config.LocalClientID != "" {
		if err := authServer.Store.SaveClient(server.Client{
			ID:                config.LocalClientID,
			Name:              "local resource server",
			RedirectURIs:      []string{"http://127.0.0.1:39001/callback"},
			TokenEndpointAuth: "none",
		}); err != nil {
			slog.Error("local client registration failed", "error", err)
			os.Exit(1)
		}
	}
	if config.LocalDevelopment && config.LocalTokenExchange {
		authServer.TokenExchanger = server.LocalTokenExchanger{
			Issuer:      config.Issuer,
			KeyProvider: authServer.KeyProvider,
			TTL:         config.AccessTokenTTL,
		}
	}
	if config.LocalDevelopment && config.PrivateKeyFile == "" {
		slog.Warn("INSECURE LOCAL DEVELOPMENT: using an ephemeral signing key; all tokens become invalid after restart")
	}
	localIdentity := config.LocalDevelopment && config.ConnectorName == ""
	localExchange := config.LocalDevelopment && config.LocalTokenExchange
	if localIdentity || localExchange {
		slog.Warn("INSECURE LOCAL DEVELOPMENT is active", "fixed_subject_identity", localIdentity, "subject", config.LocalSubject, "local_token_exchange", localExchange)
		go repeatLocalDevelopmentWarning(localIdentity, localExchange)
	}
	slog.Info("mcp auth server listening", "addr", config.ListenAddr, "issuer", config.Issuer)
	if err := http.ListenAndServe(config.ListenAddr, authServer.Handler()); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

// loadResourceClients registers pre-provisioned private_key_jwt clients (for
// example, a resource server performing RFC 8693 token exchange) so the
// token endpoint can authenticate them. Registration is re-applied on every
// startup, so the file is the source of truth and edits take effect on restart.
func loadResourceClients(store server.Store, path string) error {
	if path == "" {
		return nil
	}
	clients, err := server.LoadResourceClients(path)
	if err != nil {
		return err
	}
	for _, client := range clients {
		if err := store.SaveClient(server.Client{
			ID:                client.ClientID,
			Name:              client.Name,
			TokenEndpointAuth: "private_key_jwt",
			PublicKeyPEM:      client.PublicKeyPEM,
			Algorithm:         client.Algorithm,
		}); err != nil {
			return fmt.Errorf("register resource client %q: %w", client.ClientID, err)
		}
	}
	return nil
}

// repeatLocalDevelopmentWarning keeps the local-development identity path
// visible for the life of the process. A single line at startup is easy to
// miss once other logs scroll past it.
func repeatLocalDevelopmentWarning(localIdentity, tokenExchange bool) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		slog.Warn("INSECURE LOCAL DEVELOPMENT is still active", "fixed_subject_identity", localIdentity, "local_token_exchange", tokenExchange)
	}
}

func buildStore(config server.Config) (server.Store, func(), error) {
	switch strings.ToLower(config.StoreBackend) {
	case "memory":
		return server.NewMemoryStore(), func() {}, nil
	case "sqlite":
		store, err := server.NewSQLiteStore(config.DatabaseURL)
		if err != nil {
			return nil, nil, err
		}
		return store, func() { _ = store.Close() }, nil
	default:
		return nil, nil, errors.New("unsupported store backend")
	}
}

func connectorNames(connectors map[string]server.ConnectorConfig) []string {
	names := make([]string, 0, len(connectors))
	for name := range connectors {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func connectorNamesExcept(connectors map[string]server.ConnectorConfig, selected string) []string {
	names := make([]string, 0, len(connectors))
	for name := range connectors {
		if name != selected {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func buildProviders(config server.Config, store server.Store) (server.Config, server.IdentityProvider, server.TokenExchanger, error) {
	if config.ConnectorName == "" {
		if !config.LocalDevelopment {
			return config, nil, nil, errors.New("a named connector is required outside local development")
		}
		return config, server.LocalIdentityProvider{Subject: config.LocalSubject}, nil, nil
	}
	allowInsecure := config.LocalDevelopment || config.AllowInsecureConnectors
	connectors, err := server.LoadConnectorsWithOptions(config.ConnectorsFile, allowInsecure)
	if err != nil {
		return config, nil, nil, err
	}
	connector, ok := connectors[config.ConnectorName]
	if !ok {
		return config, nil, nil, fmt.Errorf(
			"connector %q was not found in %s (file defines: %s)",
			config.ConnectorName, config.ConnectorsFile, strings.Join(connectorNames(connectors), ", "),
		)
	}
	// One process serves exactly one connector, so every other entry in the
	// file is inert. Say so by name at startup rather than ignoring it
	// silently, which is how someone ends up believing a second connector is
	// live. This warns rather than refuses because a single connectors file
	// shared across deployments — a staging entry and a production one, each
	// selected by its own MCP_AUTH_CONNECTOR — is a supported layout.
	if ignored := connectorNamesExcept(connectors, config.ConnectorName); len(ignored) > 0 {
		slog.Warn(
			"connectors defined but not served by this process; only MCP_AUTH_CONNECTOR is live",
			"selected", config.ConnectorName,
			"ignored", strings.Join(ignored, ","),
		)
	}
	// Legacy connector scope settings remain a fallback for deployments that
	// have not moved scope policy into the MCP resource configuration.
	if len(connector.MCPScopes) > 0 {
		config.AllowedScopes = append([]string(nil), connector.MCPScopes...)
	}
	config.AllowedClientRedirectURIs = append([]string(nil), connector.AllowedClientRedirectURIs...)
	config.Consent = copyConsent(connector.Consent)
	callbackURL := config.IdentityCallbackURL()
	identity, err := server.NewOIDCIdentityProvider(connector, callbackURL, allowInsecure)
	if err != nil {
		return config, nil, nil, err
	}
	exchanger, err := buildTokenExchanger(connector, allowInsecure, store)
	if err != nil {
		return config, nil, nil, err
	}
	return config, identity, exchanger, nil
}

// copyConsent gives the server config its own consent block so later edits
// to the loaded connector do not change the page, matching the slice copies
// above.
func copyConsent(in *server.ConsentConfig) *server.ConsentConfig {
	if in == nil {
		return nil
	}
	out := *in
	out.IntroParagraphs = append([]string(nil), in.IntroParagraphs...)
	out.Permissions = append([]string(nil), in.Permissions...)
	if in.ScopeLabels != nil {
		out.ScopeLabels = make(map[string]string, len(in.ScopeLabels))
		for key, value := range in.ScopeLabels {
			out.ScopeLabels[key] = value
		}
	}
	return &out
}

// buildTokenExchanger selects the downstream-token strategy the connector is
// configured for. upstream_session (the default) reuses the token set
// captured at login; rfc8693 performs RFC 8693 token-exchange against the
// same upstream provider, for providers that support it.
func buildTokenExchanger(connector server.ConnectorConfig, allowInsecure bool, store server.Store) (server.TokenExchanger, error) {
	if connector.ResolvedDownstreamTokenStrategy() == server.DownstreamTokenStrategyRFC8693 {
		return server.NewOIDCTokenExchanger(connector, allowInsecure)
	}
	return server.NewUpstreamSessionExchanger(store, connector)
}
