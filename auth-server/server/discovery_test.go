package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConnectorsFillsMissingEndpointsViaDiscovery(t *testing.T) {
	var discoveryRequests int
	var accept string
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		discoveryRequests++
		accept = r.Header.Get("Accept")
		// jwks_uri is on a different host than the issuer on purpose: some
		// providers publish keys that way, and discovery must still accept it.
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": "http://discovered.example.com/authorize",
			"token_endpoint":         "http://discovered.example.com/token",
			"jwks_uri":               "http://discovered.example.com/jwks",
			"userinfo_endpoint":      "http://discovered.example.com/userinfo",
		})
	}))
	defer server.Close()
	issuer = server.URL

	path := filepath.Join(t.TempDir(), "connectors.json")
	body := fmt.Sprintf(`{"provider":{"issuer":%q,"client_id":"client","exchange_client_id":"exchange","token_endpoint_auth_method":"none"}}`, server.URL)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	connectors, err := LoadConnectorsWithOptions(path, true)
	if err != nil {
		t.Fatalf("load connectors: %v", err)
	}
	connector := connectors["provider"]
	if connector.AuthorizationEndpoint != "http://discovered.example.com/authorize" ||
		connector.TokenEndpoint != "http://discovered.example.com/token" ||
		connector.JWKSURI != "http://discovered.example.com/jwks" ||
		connector.UserinfoEndpoint != "http://discovered.example.com/userinfo" {
		t.Fatalf("endpoints were not filled in from discovery: %+v", connector)
	}
	if discoveryRequests != 1 {
		t.Fatalf("expected exactly one discovery request, got %d", discoveryRequests)
	}
	if accept != "application/json" {
		t.Fatalf("discovery request Accept = %q, want application/json", accept)
	}
}

func TestLoadConnectorsSkipsDiscoveryWhenFullySpecified(t *testing.T) {
	// issuer points at a host that would fail if dialed, so if discovery
	// were incorrectly triggered for a fully-specified connector, this load
	// would fail instead of succeeding.
	const unreachableIssuer = "http://127.0.0.1:1"
	path := filepath.Join(t.TempDir(), "connectors.json")
	body := fmt.Sprintf(`{"provider":{
		"issuer":%q,
		"authorization_endpoint":"http://idp.example.com/authorize",
		"token_endpoint":"http://idp.example.com/token",
		"jwks_uri":"http://idp.example.com/jwks",
		"client_id":"client","exchange_client_id":"exchange",
		"token_endpoint_auth_method":"none"
	}}`, unreachableIssuer)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	connectors, err := LoadConnectorsWithOptions(path, true)
	if err != nil {
		t.Fatalf("expected a fully-specified connector to load without attempting discovery: %v", err)
	}
	if connectors["provider"].AuthorizationEndpoint != "http://idp.example.com/authorize" {
		t.Fatalf("unexpected connector: %+v", connectors["provider"])
	}
}

func TestDiscoverOIDCConfigurationChecksIssuer(t *testing.T) {
	var issuer string
	var accept string
	accepted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		// A trailing slash still matches. jwks_uri is on another host, which
		// is legitimate for some providers and must not be rejected.
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer + "/",
			"authorization_endpoint": "https://idp.example.com/authorize",
			"token_endpoint":         "https://idp.example.com/token",
			"jwks_uri":               "https://keys.example.com/jwks",
		})
	}))
	defer accepted.Close()
	issuer = accepted.URL
	discovered, err := discoverOIDCConfiguration(context.Background(), accepted.Client(), issuer)
	if err != nil {
		t.Fatalf("matching issuer: %v", err)
	}
	if discovered.JWKSURI != "https://keys.example.com/jwks" {
		t.Fatalf("jwks_uri on another host was dropped: %+v", discovered)
	}
	if accept != "application/json" {
		t.Fatalf("Accept = %q, want application/json", accept)
	}

	rejected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 "https://evil.example.com",
			"authorization_endpoint": "https://idp.example.com/authorize",
			"token_endpoint":         "https://idp.example.com/token",
			"jwks_uri":               "https://idp.example.com/jwks",
		})
	}))
	defer rejected.Close()
	if _, err := discoverOIDCConfiguration(context.Background(), rejected.Client(), rejected.URL); err == nil {
		t.Fatal("expected an issuer mismatch to be rejected")
	}
}

func TestLoadConnectorsReportsDiscoveryFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connectors.json")
	body := `{"provider":{"issuer":"http://127.0.0.1:1","client_id":"client","exchange_client_id":"exchange","token_endpoint_auth_method":"none"}}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConnectorsWithOptions(path, true); err == nil {
		t.Fatal("expected an unreachable issuer with missing endpoints to fail discovery")
	}
}
