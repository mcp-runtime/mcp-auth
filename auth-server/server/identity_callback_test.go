package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIdentityCallbackURLDefaultsToIssuer(t *testing.T) {
	config := Config{Issuer: "https://auth.example.com/auth"}
	if got := config.IdentityCallbackURL(); got != "https://auth.example.com/auth/identity/callback" {
		t.Fatalf("IdentityCallbackURL() = %q", got)
	}
	if got := config.IdentityCallbackPath(); got != "/auth/identity/callback" {
		t.Fatalf("IdentityCallbackPath() = %q", got)
	}
}

// An operator who cannot add a redirect URI to an existing OAuth app points
// this at one the provider already accepts.
func TestIdentityCallbackURLOverride(t *testing.T) {
	config := Config{
		Issuer:           "https://auth.example.com/auth",
		IdentityCallback: "https://auth.example.com/legacy/oauth/callback",
	}
	if got := config.IdentityCallbackURL(); got != "https://auth.example.com/legacy/oauth/callback" {
		t.Fatalf("IdentityCallbackURL() = %q", got)
	}
	if got := config.IdentityCallbackPath(); got != "/legacy/oauth/callback" {
		t.Fatalf("IdentityCallbackPath() = %q", got)
	}
}

func TestIdentityCallbackURLValidation(t *testing.T) {
	base := func() Config {
		return Config{
			Issuer: "https://auth.example.com", Resources: []string{"https://mcp.example.com/mcp"},
			RequireHTTPS: true, PrivateKeyFile: "key.pem", StoreBackend: "sqlite",
			DatabaseURL: "/tmp/x.db", AllowedScopes: []string{"tools:read"},
		}
	}
	rejected := map[string]string{
		"not absolute":         "/oauth/callback",
		"no path":              "https://auth.example.com",
		"bare slash":           "https://auth.example.com/",
		"carries a fragment":   "https://auth.example.com/cb#frag",
		"plaintext over https": "http://auth.example.com/cb",
	}
	for name, value := range rejected {
		config := base()
		config.IdentityCallback = value
		if err := config.Validate(); err == nil {
			t.Errorf("Validate() accepted %s (%q)", name, value)
		}
	}
	config := base()
	config.IdentityCallback = "https://auth.example.com/legacy/oauth/callback"
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() rejected a usable override: %v", err)
	}
}

// The override has to be routed, not merely advertised: the provider redirects
// the browser there, so the handler must answer on that path. An unrouted path
// yields the mux's own 404; the handler itself answers 400 for a state it
// cannot consume, so matching non-404 statuses is what proves the route exists.
func TestIdentityCallbackServedAtOverridePath(t *testing.T) {
	instance := testServer(t)
	instance.Config.IdentityCallback = "https://auth.example.com/legacy/oauth/callback"
	// LocalIdentityProvider is not interactive, and identityCallback answers 404
	// for that before it ever looks at the path.
	instance.IdentityProvider = &OIDCIdentityProvider{
		Connector: ConnectorConfig{Issuer: "https://idp.example.com"},
		Client:    http.DefaultClient,
		ClientID:  "upstream-client",
	}
	handler := instance.Handler()

	for _, path := range []string{"/legacy/oauth/callback", "/identity/callback"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path+"?state=unknown", nil))
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400 from the callback handler (404 means the path is not routed)", path, recorder.Code)
		}
	}

	// A path the override does not name stays unrouted.
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/not/a/callback", nil))
	if recorder.Code != http.StatusNotFound {
		t.Errorf("GET /not/a/callback = %d, want 404", recorder.Code)
	}
}
